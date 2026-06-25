#include "gsa.h"
#include <sstream>
#include <iostream>
#include <ctime>
#include <cstring>
#include <stdexcept>
#include <algorithm>
#include <cctype>
#include <openssl/rand.h>
#ifdef _WIN32
#  include <windows.h>
#else
#  include <unistd.h>
#endif

// ─────────────────────────────────────────────────────────────────────────────
// GsaClient — small free-function helpers
// ─────────────────────────────────────────────────────────────────────────────

std::string gsa_gen_uuid()
{
    uint8_t b[16];
    RAND_bytes(b, sizeof(b));
    b[6] = (b[6] & 0x0F) | 0x40; // version 4
    b[8] = (b[8] & 0x3F) | 0x80; // variant
    char buf[37];
    snprintf(buf, sizeof(buf),
        "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        b[0],b[1],b[2],b[3], b[4],b[5], b[6],b[7],
        b[8],b[9], b[10],b[11],b[12],b[13],b[14],b[15]);
    return buf;
}

std::string gsa_country(const std::string& locale)
{
    // "en_US" → "US", "en-US" → "US"
    for (char sep : {'_', '-'}) {
        size_t p = locale.find(sep);
        if (p != std::string::npos && p+1 < locale.size())
            return locale.substr(p+1);
    }
    return "US";
}

// ─────────────────────────────────────────────────────────────────────────────
// GsaClient — main entry point
// ─────────────────────────────────────────────────────────────────────────────

Account GsaClient::login(const std::string&  email,
                         const std::string&  password,
                         const AnisetteData& anisette,
                         const std::string&  authCode)
{
    // ── SRP group: RFC 5054 Appendix A / pysrp NG_2048 prime, g = 2 ───
    const Bytes& N_bytes  = srp::N_2048();
    const int    N_LEN    = (int)N_bytes.size();  // 256
    const Bytes  g_bytes  = srp::g();
    const Bytes  g_padded = srp::g_padded(N_LEN);

    // Client private key a, public key A = g^a mod N
    const Bytes a_bytes = srp::random_private_value();
    const Bytes A_bytes = srp::compute_A(a_bytes, N_bytes, g_bytes, N_LEN);

    // ── Step 1: init ──────────────────────────────────────────────────

    // Pin clientTime so headers and cpd body use the identical timestamp
    AnisetteData ani = anisette;
    if (ani.clientTime.empty()) ani.clientTime = iso8601_now();
    const PlistDict cpd = make_cpd(ani);

    // New protocol: body wrapped in { Header: {Version}, Request: {...} }
    PlistDict req_body;
    req_body["A2k"] = PlistValue::makeData(A_bytes);
    req_body["cpd"] = PlistValue::makeDict(cpd);
    req_body["ps"]  = PlistValue::makeArray({
        PlistValue::makeString("s2k"),
        PlistValue::makeString("s2k_fo")
    });
    req_body["u"] = PlistValue::makeString(email);
    req_body["o"] = PlistValue::makeString("init");

    PlistDict hdr_dict; hdr_dict["Version"] = PlistValue::makeString("1.0.1");
    PlistDict wrapper1;
    wrapper1["Header"]  = PlistValue::makeDict(hdr_dict);
    wrapper1["Request"] = PlistValue::makeDict(req_body);

    const auto        hdrs  = build_headers(ani);
    const std::string body1 = encode_plist_xml(wrapper1);
    if (m_debug) dbg_request("init", hdrs, body1);
    const HttpResponse r1 = m_http.post(GSA_ENDPOINT, body1, hdrs);
    if (m_debug) dbg_response("init", r1);
    if (r1.statusCode != 200)
        throw IpaError("GSA init: HTTP " + std::to_string(r1.statusCode));

    const PlistDict d1_outer = decode_plist(r1.body);
    check_status(d1_outer, "init");
    // New protocol: response is { Header:{}, Response:{B,s,c,sp,i,...} }
    const PlistDict d1 = d1_outer.count("Response")
                         ? dict_dict(d1_outer, "Response")
                         : d1_outer; // fallback: old flat format

    const Bytes salt  = dict_data(d1, "s");
    const Bytes B_raw = dict_data(d1, "B");
    const std::string sc1 = dict_str(d1, "c");
    int iters = (int)dict_int(d1, "i");
    if (iters <= 0) iters = 20000;

    if (m_debug)
        fprintf(stderr,
            "[GSA] parsed: N_LEN=%d  B=%zu  s=%zu  iters=%d  c_len=%zu\n",
            N_LEN, B_raw.size(), salt.size(), iters, sc1.size());

    if (B_raw.empty() || salt.empty() || sc1.empty())
        throw IpaError("GSA init: incomplete server response"
                       " (B=" + std::to_string(B_raw.size()) + ")");

    // ── SRP math ──────────────────────────────────────────────────────

    BIGNUM* B_bn = bn_from_bytes(B_raw);
    const Bytes B_padded = bn_to_padded(B_bn, N_LEN);
    bn_free(B_bn);

    try
    {
        if (m_debug) fprintf(stderr, "[SRP] step1: k\n");
        const Bytes k = srp::compute_k(N_bytes, g_padded);

        if (m_debug) fprintf(stderr, "[SRP] step2: u\n");
        const Bytes u = srp::compute_u(A_bytes, B_padded);

        // Apple s2k: x = PBKDF2-SHA256( SHA256(password), salt, iters, 32 )
        // The email is NOT included in x; it appears only as H(I) in M1.
        std::string email_lc = email;
        std::transform(email_lc.begin(), email_lc.end(), email_lc.begin(),
                       [](unsigned char c){ return std::tolower(c); });
        if (m_debug) {
            const Bytes dbg_hp = sha2::digest(password);
            const Bytes dbg_he = sha2::digest(email_lc);
            fprintf(stderr, "[SRP] step3: x (pbkdf2 iters=%d)\n", iters);
            fprintf(stderr, "[SRP] sha256(password)[0..3]: %02x %02x %02x %02x\n",
                (unsigned)dbg_hp[0],(unsigned)dbg_hp[1],(unsigned)dbg_hp[2],(unsigned)dbg_hp[3]);
            fprintf(stderr, "[SRP] sha256(email_lc)[0..3]: %02x %02x %02x %02x\n",
                (unsigned)dbg_he[0],(unsigned)dbg_he[1],(unsigned)dbg_he[2],(unsigned)dbg_he[3]);
            fprintf(stderr, "[SRP] password_len=%zu  email=%s\n",
                password.size(), email_lc.c_str());
        }
        const Bytes x_bytes = srp::compute_x_apple(password, salt, iters);

        if (m_debug) {
            fprintf(stderr, "[SRP] step4: BN ops, x[0..3]:");
            for (int _i=0;_i<4;_i++) fprintf(stderr," %02x",(unsigned char)x_bytes[_i]);
            fprintf(stderr,"\n");
        }
        if (m_debug) fprintf(stderr, "[SRP] step5: S, K\n");
        const Bytes S_bytes = srp::compute_premaster_secret(
            B_padded, k, g_bytes, x_bytes, N_bytes, a_bytes, u, N_LEN);
        const Bytes K = srp::compute_session_key(S_bytes);

        if (m_debug) fprintf(stderr, "[SRP] step6: M1\n");
        const Bytes M1 = srp::compute_M1(N_bytes, g_padded, email_lc, salt,
                                         A_bytes, B_padded, K);
        if (m_debug) {
            auto hxN = [](const Bytes& b, size_t n) {
                std::string s; char c[3];
                for(size_t i=0;i<n&&i<b.size();i++){snprintf(c,3,"%02x",(unsigned)b[i]);s+=c;}
                return s;
            };
            fprintf(stderr,"[M1] salt    [0..3]: %s\n", hxN(salt,4).c_str());
            fprintf(stderr,"[M1] A       [0..7]: %s\n", hxN(A_bytes,8).c_str());
            fprintf(stderr,"[M1] B       [0..7]: %s\n", hxN(B_padded,8).c_str());
            fprintf(stderr,"[M1] K             : %s\n", hxN(K,32).c_str());
            fprintf(stderr,"[M1] M1            : %s\n", hxN(M1,32).c_str());
        }

        // ── Step 2: complete ──────────────────────────────────────────
        PlistDict cpl_req;
        cpl_req["M1"]  = PlistValue::makeData(M1);
        cpl_req["c"]   = PlistValue::makeString(sc1);
        cpl_req["cpd"] = PlistValue::makeDict(cpd);
        cpl_req["o"]   = PlistValue::makeString("complete");
        cpl_req["u"]   = PlistValue::makeString(email);

        PlistDict wrapper2;
        wrapper2["Header"]  = PlistValue::makeDict(hdr_dict);
        wrapper2["Request"] = PlistValue::makeDict(cpl_req);

        if (m_debug) fprintf(stderr, "[SRP] step7: sending complete\n");
        const std::string body2 = encode_plist_xml(wrapper2);
        if (m_debug) dbg_request("complete", hdrs, body2);
        const HttpResponse r2 = m_http.post(GSA_ENDPOINT, body2, hdrs);
        if (m_debug) dbg_response("complete", r2);
        if (r2.statusCode != 200)
            throw IpaError("GSA complete: HTTP " + std::to_string(r2.statusCode));

        const PlistDict d2_outer = decode_plist(r2.body);
        check_status(d2_outer, "complete");
        PlistDict d2 = d2_outer.count("Response")
                       ? dict_dict(d2_outer, "Response")
                       : d2_outer;

        const std::string result = dict_str(d2, "Result");
        const std::string sc2    = dict_str(d2, "sc");

        if (result == "TwoFactorAuthentication" ||
            result == "TwoStepVerification")
        {
            if (authCode.empty()) throw AuthCodeRequired();
            { /* outer Result=TwoFactor path: not used for 409-spd accounts */ }
            check_status(d2, "2fa");
        }
        else if (!result.empty() && result != "Allow") {
            if (result == "RepairRequired")
                throw IpaError("Apple ID needs repair: appleid.apple.com");
            throw IpaError("GSA: unexpected Result = " + result);
        }

        // ── Decrypt spd ───────────────────────────────────────────────
        if (m_debug) fprintf(stderr, "[SRP] step8: spd decrypt\n");
        const Bytes spd_enc = dict_data(d2, "spd");
        if (m_debug)
            fprintf(stderr, "[GSA] spd_enc: %zu bytes\n", spd_enc.size());
        if (spd_enc.empty())
            throw IpaError("GSA: spd missing — possible SRP key mismatch");

        // key = HMAC-SHA256(K, "extra data key")  [32 bytes → AES-256]
        // iv  = HMAC-SHA256(K, "extra data iv")[:16]
        const Bytes dk  = sha2::hmac(K, std::string("extra data key:"));
        Bytes div = sha2::hmac(K, std::string("extra data iv:"));
        div.resize(16);

        Bytes spd_plain;
        try {
            spd_plain = aes::cbc_decrypt(dk, div, spd_enc);
        } catch (const std::exception&) {
            throw IpaError("GSA: AES-CBC decrypt failed — wrong session key?");
        }
        PlistDict spd         = decode_plist(   // handles bplist00; may be replaced by 2FA path
            std::string(spd_plain.begin(), spd_plain.end()));

        if (m_debug) {
            fprintf(stderr, "[GSA] spd_plain: %zu bytes\n", spd_plain.size());
            fprintf(stderr, "%s\n", encode_plist_xml(spd).c_str());
        }

        if (m_debug) {
            fprintf(stderr, "[GSA] spd keys:");
            for (auto& [kk, vv] : spd) fprintf(stderr, " '%s'", kk.c_str());
            fprintf(stderr, "\n");
        }

        // ── Check for 2FA (status-code 409 inside spd) ───────────────
        {
            int64_t spd_sc = dict_int(spd, "status-code");
            if (spd_sc == 409) {
                // Second pass after successful 2FA validate — should not happen,
                // but if it does, fail cleanly instead of looping forever.
                if (authCode == "__2fa_done__")
                    throw IpaError("GSA 2FA: still getting 409 after validation");

                const std::string sm      = dict_str(spd, "sm");
                const std::string fa_dsid = dict_str(spd, "adsid");
                const std::string fa_tok  = dict_str(spd, "GsIdmsToken");

                // Apple sends push automatically when SRP returns 409.
                // No need for explicit GET /auth/verify/trusteddevice.
                if (!sm.empty()) fprintf(stderr, "[2FA] %s\n", sm.c_str());

                std::string code = authCode;
                if (code.empty()) {
                    fprintf(stderr, "Enter 2FA code: ");
                    fflush(stderr);
                    std::getline(std::cin, code);
                    while (!code.empty() &&
                           (code.back() == '\r' || code.back() == '\n'))
                        code.pop_back();
                }
                if (code.empty()) throw AuthCodeRequired();

                if (!do_2fa_validate(fa_dsid, fa_tok, code, anisette))
                    throw IpaError("GSA 2FA: invalid code");

                if (m_debug) fprintf(stderr, "[GSA] 2FA confirmed — re-running SRP\n");
                return login(email, password, anisette, "__2fa_done__");
            }
        }

        // ── Build Account from spd ─────────────────────────────────────
        Account acc;

        // DsPrsId may be an integer (20232787564) or string — coerce both
        acc.directoryServicesID = dict_str(spd, "DsPrsId");
        if (acc.directoryServicesID.empty())
            acc.directoryServicesID = dict_str(spd, "adsid");

        // Token: try all known field names
        std::string tok = dict_str(spd, "GsIdmsToken");
        if (tok.empty()) tok = dict_str(spd, "idms_token");
        if (tok.empty()) tok = dict_str(spd, "acntToken");

        if (acc.directoryServicesID.empty() || tok.empty())
            throw IpaError("GSA: adsid/token absent from decrypted spd");

        acc.gsIdmsToken.set(tok);   // GsIdmsToken — for X-Apple-Identity-Token
        acc.passwordToken.set(tok); // will be replaced by iTunes Store token in do_itunes_auth
        acc.email    = email;
        acc.password.set(password);

        // Name: "fn"/"ln" are top-level spd keys (not inside acctInfo)
        acc.firstName = dict_str(spd, "fn");
        acc.lastName  = dict_str(spd, "ln");
        // Fallback: check acctInfo sub-dict (old format)
        if (acc.firstName.empty() && acc.lastName.empty()) {
            auto ai = spd.find("acctInfo");
            if (ai != spd.end() && ai->second.isDict()) {
                acc.firstName = dict_str(ai->second.dictVal, "firstName");
                acc.lastName  = dict_str(ai->second.dictVal, "lastName");
            }
        }
        acc.name = (acc.firstName.empty() && acc.lastName.empty())
                   ? email
                   : (acc.firstName + " " + acc.lastName);

        acc.adsid = dict_str(spd, "adsid");

        // t dict — PET (5 min) and HB (1 year) tokens
        {
            auto t_it = spd.find("t");
            if (t_it != spd.end() && t_it->second.isDict()) {
                const PlistDict& td = t_it->second.dictVal;
                auto extract_token = [&](const std::string& key) -> std::string {
                    auto it = td.find(key);
                    if (it == td.end() || !it->second.isDict()) return {};
                    return dict_str(it->second.dictVal, "token");
                };
                acc.petToken = extract_token("com.apple.gs.idms.pet");
                acc.hbToken  = extract_token("com.apple.gs.idms.hb");
            }
        }
        if (m_debug) {
            fprintf(stderr, "[GSA] adsid=%s\n", acc.adsid.c_str());
            fprintf(stderr, "[GSA] pet=%s\n",
                    acc.petToken.empty() ? "(empty)" : acc.petToken.substr(0,20).c_str());
            fprintf(stderr, "[GSA] hb=%s\n",
                    acc.hbToken.empty()  ? "(empty)" : acc.hbToken.substr(0,20).c_str());
        }

        // Storefront
        for (auto& hk : {"x-apple-store-front", "x-apple-storefront"}) {
            auto it = r2.headers.find(hk);
            if (it != r2.headers.end() && !it->second.empty()) {
                acc.storeFront = it->second;
                break;
            }
        }
        if (acc.storeFront.empty())
            acc.storeFront = fetch_storefront(acc);

        // Pod
        {
            auto it = r2.headers.find("x-apple-icloud-country");
            if (it != r2.headers.end()) acc.pod = it->second;
        }

        return acc;
    } // end SRP try block
    catch (const AuthCodeRequired&) {
        throw;  // re-throw AuthCodeRequired as-is
    }
    catch (const std::exception& srp_ex) {
        // Catch vector/string/alloc exceptions from SRP math to get useful message
        throw IpaError(std::string("GSA SRP exception: ") + srp_ex.what());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GsaClient — private helpers
// ─────────────────────────────────────────────────────────────────────────────

std::map<std::string, std::string> GsaClient::build_2fa_headers(
    const AnisetteData& anisette,
    const std::string& dsid,
    const std::string& idms_token)
{
    const std::string raw = dsid + ":" + idms_token;
    const std::string identity_token = base64_encode(
        reinterpret_cast<const uint8_t*>(raw.data()), raw.size());

    std::map<std::string, std::string> hdrs;
    hdrs["Accept"]                   = "text/x-xml-plist";
    hdrs["Content-Type"]             = "text/x-xml-plist";
    hdrs["User-Agent"]               = "Xcode";
    hdrs["Accept-Language"]          = "en-us";
    hdrs["X-Apple-App-Info"]         = "com.apple.gs.xcode.auth";
    hdrs["X-Xcode-Version"]          = "11.2 (11B41)";
    hdrs["X-Apple-Identity-Token"]   = identity_token;
    hdrs["X-Apple-I-MD"]             = anisette.otp;
    hdrs["X-Apple-I-MD-M"]           = anisette.machineID;
    hdrs["X-Apple-I-MD-LU"]          = anisette.localUserUUID;
    if (!anisette.routingInfo.empty())
        hdrs["X-Apple-I-MD-RINFO"]   = anisette.routingInfo;
    hdrs["X-Apple-I-Client-Time"]    = anisette.clientTime;
    hdrs["X-Apple-Locale"]           = anisette.locale;
    hdrs["X-Apple-I-TimeZone"]       = anisette.timezone;
    if (!anisette.clientInfo.empty())
        hdrs["X-MMe-Client-Info"]    = anisette.clientInfo;
    if (!anisette.deviceID.empty())
        hdrs["X-Mme-Device-Id"]      = anisette.deviceID;
    return hdrs;
}

bool GsaClient::do_2fa_validate(const std::string& dsid, const std::string& idms_token,
                                const std::string& code,
                                const AnisetteData& anisette)
{
    auto hdrs = build_2fa_headers(anisette, dsid, idms_token);
    hdrs["security-code"] = code;

    const HttpResponse r = m_http.get(
        "https://gsa.apple.com/grandslam/GsService2/validate", hdrs);
    if (m_debug) {
        fprintf(stderr, "[GSA] 2fa validate status=%d\n", r.statusCode);
        if (!r.body.empty())
            fprintf(stderr, "[GSA] 2fa validate body:\n%s\n", r.body.c_str());
    }
    if (r.statusCode != 200) return false;
    // Apple returns HTTP 200 even on error — check ec in body
    if (!r.body.empty()) {
        try {
            const PlistDict rd = decode_plist(r.body);
            int64_t ec = dict_int(rd, "ec");
            if (ec != 0) {
                if (m_debug)
                    fprintf(stderr, "[GSA] 2fa validate ec=%lld em=%s\n",
                            (long long)ec, dict_str(rd, "em").c_str());
                return false;
            }
        } catch (...) {}
    }
    return true;
}

PlistDict GsaClient::make_cpd(const AnisetteData& a)
{
    PlistDict cpd;
    // ── Service contract flags ─────────────────────────────────────────
    cpd["bootstrap"] = PlistValue::makeBool(true);
    cpd["icscrec"]   = PlistValue::makeBool(true);
    cpd["pbe"]       = PlistValue::makeBool(false);
    cpd["prkgen"]    = PlistValue::makeBool(true);
    cpd["svct"]      = PlistValue::makeString("iCloud");
    // ── New fields (protocol update ~2026) ────────────────────────────
    cpd["X-Apple-I-Device-Configuration-Mode"] = PlistValue::makeString("Default");
    cpd["X-Apple-I-ReAuth"]      = PlistValue::makeBool(false);
    cpd["X-Apple-I-Request-UUID"]= PlistValue::makeString(gsa_gen_uuid());
    cpd["loc"]  = PlistValue::makeString(a.locale);
    cpd["cou"]  = PlistValue::makeString(gsa_country(a.locale));
    cpd["dc"]   = PlistValue::makeString("PC");
    cpd["dec"]  = PlistValue::makeBool(true);
    cpd["capp"] = PlistValue::makeString("com.apple.gs.xcode.auth");
    cpd["ptkn"] = PlistValue::makeString("");
    cpd["prtn"] = PlistValue::makeString("R1");
    cpd["at"]   = PlistValue::makeString("");
    // ── Anisette fields ───────────────────────────────────────────────
    cpd["X-Apple-I-MD"]          = PlistValue::makeString(a.otp);
    cpd["X-Apple-I-MD-M"]        = PlistValue::makeString(a.machineID);
    cpd["X-Apple-I-MD-LU"]       = PlistValue::makeString(a.localUserUUID);
    cpd["X-Apple-I-MD-RINFO"]    = PlistValue::makeInt(
        a.routingInfo.empty() ? 0LL : std::stoll(a.routingInfo));
    cpd["X-Apple-I-SRL-NO"]      = PlistValue::makeString(a.serialNo);
    cpd["X-Apple-I-Client-Time"] = PlistValue::makeString(a.clientTime);
    cpd["X-Apple-Locale"]        = PlistValue::makeString(a.locale);
    cpd["X-Apple-I-TimeZone"]    = PlistValue::makeString(a.timezone);
    if (!a.clientInfo.empty())
        cpd["X-MMe-Client-Info"] = PlistValue::makeString(a.clientInfo);
    if (!a.deviceID.empty())
        cpd["X-Mme-Device-Id"]   = PlistValue::makeString(a.deviceID);
    return cpd;
}

std::map<std::string, std::string>
GsaClient::build_headers(const AnisetteData& a) const
{
    const std::string ct = a.clientTime.empty() ? iso8601_now() : a.clientTime;
    // New GSA protocol: most anisette fields moved into cpd body.
    // Only X-Apple-I-MD-M, X-Mme-Client-Info, X-Mme-Device-Id stay in headers.
    std::map<std::string, std::string> h = {
        {"Content-Type",  "text/x-xml-plist"},
        {"Accept",        "*/*"},
        {"User-Agent",    ITUNES_UA},
        {"Accept-Language","en-US,en;q=0.9"},
        // Machine ID stays in headers (required by new protocol)
        {"X-Apple-I-MD-M", a.machineID},
    };
    if (!a.clientInfo.empty()) h["X-MMe-Client-Info"] = a.clientInfo;
    if (!a.deviceID.empty())   h["X-Mme-Device-Id"]   = a.deviceID;
    return h;
}

void GsaClient::check_status(const PlistDict& d, const char* step)
{
    // New protocol wraps in { Header:{}, Response:{ Status:{ec,em,...} } }
    // Old protocol had Status at top level
    const PlistDict* lookup = &d;
    PlistDict resp_copy;
    if (d.count("Response") && d.at("Response").isDict()) {
        resp_copy = d.at("Response").dictVal;
        lookup = &resp_copy;
    }
    auto it = lookup->find("Status");
    if (it == lookup->end() || !it->second.isDict()) return;
    const PlistDict& st = it->second.dictVal;
    const int64_t ec = dict_int(st, "ec");
    if (ec == 0) return;
    const std::string em = dict_str(st, "em");
    if (ec == -22421) throw IpaError("Bad Apple ID or password");
    if (ec == -22020) throw AuthCodeRequired();
    throw IpaError(std::string("GSA ") + step
                   + " error " + std::to_string(ec) + ": " + em);
}

std::string GsaClient::fetch_storefront(const Account& acc)
{
    const std::map<std::string, std::string> hdrs = {
        {"iCloud-DSID", acc.directoryServicesID},
        {"X-Dsid",      acc.directoryServicesID},
        {"X-Token",     acc.passwordToken.get()},
    };
    try {
        const HttpResponse r = m_http.get(
            "https://itunes.apple.com/search"
            "?term=app&limit=1&media=software&entity=software", hdrs);
        for (auto& hk : {"x-apple-store-front", "x-apple-storefront"}) {
            auto it = r.headers.find(hk);
            if (it != r.headers.end() && !it->second.empty())
                return it->second;
        }
    } catch (const std::exception& e) {
        // itunes.apple.com uses a different CA than gsa.apple.com;
        // if SSL fails (e.g. CA bundle incomplete) fall through to default.
        fprintf(stderr, "[WARN] fetch_storefront SSL error: %s — using fallback\n",
                e.what());
    }
    return "143441-1,32"; // US fallback
}

std::string GsaClient::iso8601_now()
{
    time_t now = std::time(nullptr);
    struct tm t{};
#ifdef _WIN32
    gmtime_s(&t, &now);
#else
    gmtime_r(&now, &t);
#endif
    char buf[64];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ",
             t.tm_year+1900, t.tm_mon+1, t.tm_mday,
             t.tm_hour, t.tm_min, t.tm_sec);
    return buf;
}

void GsaClient::dbg_request(const char* step,
                            const std::map<std::string, std::string>& hdrs,
                            const std::string& body)
{
    fprintf(stderr, "\n[GSA >>] %s  REQUEST HEADERS:\n", step);
    for (auto& [k, v] : hdrs)
        fprintf(stderr, "  %-36s %s\n", (k + ":").c_str(), v.c_str());
    fprintf(stderr, "[GSA >>] body (%zu bytes):\n%.400s\n",
            body.size(), body.c_str());
}

void GsaClient::dbg_response(const char* step, const HttpResponse& r)
{
    fprintf(stderr, "\n[GSA <<] %s  status=%d  body_len=%zu\n",
            step, r.statusCode, r.body.size());

    // First 16 bytes as hex — distinguishes empty vs binary plist vs XML
    if (!r.body.empty()) {
        fprintf(stderr, "  first bytes:");
        size_t n = r.body.size() < 16 ? r.body.size() : 16;
        for (size_t i = 0; i < n; i++)
            fprintf(stderr, " %02x", (unsigned char)r.body[i]);
        fprintf(stderr, "\n");
    } else {
        fprintf(stderr, "  [EMPTY BODY]\n");
    }

    // Printable body (stops at first null inside binary plists)
    if (!r.body.empty())
        fprintf(stderr, "  body text:\n%.2000s\n", r.body.c_str());

    // Response headers (useful: Content-Type, x-apple-store-front, etc.)
    fprintf(stderr, "  response headers:\n");
    for (auto& [k, v] : r.headers)
        fprintf(stderr, "    %s: %s\n", k.c_str(), v.c_str());
}
