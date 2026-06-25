#include "anisette.h"
#include "ipatool.h"  // IpaError
#include <nlohmann/json.hpp>
#include <sstream>
#include <cstdio>
#ifdef _WIN32
#  include <windows.h>
#else
#  include <unistd.h>
#endif

std::string AnisetteData::trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t");
    if (b == std::string::npos) return {};
    size_t e = s.find_last_not_of(" \t");
    return s.substr(b, e - b + 1);
}

AnisetteData AnisetteData::from_server_output(const std::string& output)
{
    AnisetteData a;
    std::istringstream ss(output);
    std::string line;
    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back(); // strip CR
        size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string key = trim(line.substr(0, colon));
        std::string val = trim(line.substr(colon + 1));
        if      (key == "X-Apple-I-MD")         a.otp           = val;
        else if (key == "X-Apple-I-MD-M")        a.machineID     = val;
        else if (key == "X-Apple-I-MD-LU")       a.localUserUUID = val;
        else if (key == "X-Apple-I-MD-RINFO")    a.routingInfo   = val;
        else if (key == "X-Apple-I-SRL-NO")      a.serialNo      = val;
        else if (key == "X-Apple-I-Client-Time") a.clientTime    = val;
        else if (key == "X-Apple-Locale")        a.locale        = val;
        else if (key == "X-Apple-I-TimeZone")    a.timezone      = val;
        else if (key == "X-MMe-Client-Info")     a.clientInfo    = val;
        else if (key == "X-Mme-Device-Id")       a.deviceID      = val;
        // unknown keys silently ignored
    }
    return a;
}

AnisetteData AnisetteData::fetch_from_exe(const std::string& exe_path)
{
#ifdef _WIN32
    // Redirect stderr→stdout so we capture "not recognized" error from cmd.exe
    std::string cmd = "\"" + exe_path + "\" 2>&1";
    FILE* pipe = _popen(cmd.c_str(), "r");
#else
    FILE* pipe = popen((exe_path + " 2>&1").c_str(), "r");
#endif
    if (!pipe)
        throw IpaError("anisette: could not run '" + exe_path + "' — is anisette in PATH?");

    std::string output;
    char buf[256];
    while (fgets(buf, sizeof(buf), pipe))
        output += buf;

#ifdef _WIN32
    int rc = _pclose(pipe);
#else
    int rc = pclose(pipe);
#endif
    if (rc != 0) {
        const bool not_found = (rc == 9009)
            || output.find("not recognized") != std::string::npos
            || output.find("operable program") != std::string::npos
            || output.find("No such file") != std::string::npos;
        if (not_found)
            throw IpaError("anisette not found — make sure anisette is in PATH or same directory");
        // Include anisette's own output so user sees the actual error (e.g. missing DLL)
        std::string detail = output.empty() ? "" : ("\n" + output);
        // Trim trailing whitespace from detail
        while (!detail.empty() && (detail.back() == '\n' || detail.back() == '\r' || detail.back() == ' '))
            detail.pop_back();
        throw IpaError("anisette exited with code " + std::to_string(rc)
                       + " — check that anisette binary is working" + detail);
    }

    AnisetteData a = from_server_output(output);
    if (!a.is_complete())
        throw IpaError("anisette: output missing X-Apple-I-MD or X-Apple-I-MD-M");
    return a;
}

AnisetteData AnisetteData::from_json(const std::string& json_text)
{
    AnisetteData a;
    nlohmann::json j = nlohmann::json::parse(json_text, nullptr, false);
    if (j.is_discarded() || !j.is_object()) return a;

    auto get = [&](const char* key) -> std::string {
        auto it = j.find(key);
        return (it != j.end() && it->is_string()) ? it->get<std::string>() : "";
    };
    a.otp           = get("X-Apple-I-MD");
    a.machineID     = get("X-Apple-I-MD-M");
    a.localUserUUID = get("X-Apple-I-MD-LU");
    a.routingInfo   = get("X-Apple-I-MD-RINFO");
    a.serialNo      = get("X-Apple-I-SRL-NO");
    a.clientTime    = get("X-Apple-I-Client-Time");
    a.clientInfo    = get("X-MMe-Client-Info");
    a.deviceID      = get("X-Mme-Device-Id");
    std::string loc = get("X-Apple-Locale");
    std::string tz  = get("X-Apple-I-TimeZone");
    if (!loc.empty()) a.locale   = loc;
    if (!tz.empty())  a.timezone = tz;
    return a;
}

AnisetteData AnisetteData::fetch_from_public_servers(HttpClient& http, bool debug)
{
    static const char* SERVERS[] = {
        "https://ani.sidestore.io",
        "https://ani.f1sh.me",
        "https://ani.npeg.us",
        "https://ani.sidestore.app",
        "https://ani.846969.xyz",
        "https://anisette.wedotstud.io",
        "https://ani.neoarz.com",
        "https://ani3server.fly.dev",
        "https://ani.jaydenha.uk",
        "https://anisette.crystall1ne.dev",
    };
    std::string lastErr;
    for (int pass = 0; pass < 2; pass++) {
        for (const char* server : SERVERS) {
            try {
                HttpResponse res = http.get(server, {{"Accept", "application/json"}});
                if (debug)
                    fprintf(stderr, "[anisette] %s → HTTP %d\n", server, res.statusCode);
                if (res.statusCode != 200) {
                    lastErr = std::string(server) + ": HTTP " + std::to_string(res.statusCode);
                    continue;
                }
                AnisetteData a = from_json(res.body);
                if (a.is_complete()) return a;
                lastErr = std::string(server) + ": missing required fields";
            } catch (const std::exception& e) {
                lastErr = std::string(server) + ": " + e.what();
            }
        }
        if (pass == 0) {
#ifdef _WIN32
            Sleep(700);
#else
            usleep(700 * 1000);
#endif
        }
    }
    throw IpaError("anisette: all public servers failed — " + lastErr);
}
