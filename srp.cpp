#include "srp.h"
#include "bignum.h"
#include "sha2.h"
#include <openssl/rand.h>

namespace srp {

const Bytes& N_2048() {
    static const Bytes N = {
        0xac, 0x6b, 0xdb, 0x41, 0x32, 0x4a, 0x9a, 0x9b,
        0xf1, 0x66, 0xde, 0x5e, 0x13, 0x89, 0x58, 0x2f,
        0xaf, 0x72, 0xb6, 0x65, 0x19, 0x87, 0xee, 0x07,
        0xfc, 0x31, 0x92, 0x94, 0x3d, 0xb5, 0x60, 0x50,
        0xa3, 0x73, 0x29, 0xcb, 0xb4, 0xa0, 0x99, 0xed,
        0x81, 0x93, 0xe0, 0x75, 0x77, 0x67, 0xa1, 0x3d,
        0xd5, 0x23, 0x12, 0xab, 0x4b, 0x03, 0x31, 0x0d,
        0xcd, 0x7f, 0x48, 0xa9, 0xda, 0x04, 0xfd, 0x50,
        0xe8, 0x08, 0x39, 0x69, 0xed, 0xb7, 0x67, 0xb0,
        0xcf, 0x60, 0x95, 0x17, 0x9a, 0x16, 0x3a, 0xb3,
        0x66, 0x1a, 0x05, 0xfb, 0xd5, 0xfa, 0xaa, 0xe8,
        0x29, 0x18, 0xa9, 0x96, 0x2f, 0x0b, 0x93, 0xb8,
        0x55, 0xf9, 0x79, 0x93, 0xec, 0x97, 0x5e, 0xea,
        0xa8, 0x0d, 0x74, 0x0a, 0xdb, 0xf4, 0xff, 0x74,
        0x73, 0x59, 0xd0, 0x41, 0xd5, 0xc3, 0x3e, 0xa7,
        0x1d, 0x28, 0x1e, 0x44, 0x6b, 0x14, 0x77, 0x3b,
        0xca, 0x97, 0xb4, 0x3a, 0x23, 0xfb, 0x80, 0x16,
        0x76, 0xbd, 0x20, 0x7a, 0x43, 0x6c, 0x64, 0x81,
        0xf1, 0xd2, 0xb9, 0x07, 0x87, 0x17, 0x46, 0x1a,
        0x5b, 0x9d, 0x32, 0xe6, 0x88, 0xf8, 0x77, 0x48,
        0x54, 0x45, 0x23, 0xb5, 0x24, 0xb0, 0xd5, 0x7d,
        0x5e, 0xa7, 0x7a, 0x27, 0x75, 0xd2, 0xec, 0xfa,
        0x03, 0x2c, 0xfb, 0xdb, 0xf5, 0x2f, 0xb3, 0x78,
        0x61, 0x60, 0x27, 0x90, 0x04, 0xe5, 0x7a, 0xe6,
        0xaf, 0x87, 0x4e, 0x73, 0x03, 0xce, 0x53, 0x29,
        0x9c, 0xcc, 0x04, 0x1c, 0x7b, 0xc3, 0x08, 0xd8,
        0x2a, 0x56, 0x98, 0xf3, 0xa8, 0xd0, 0xc3, 0x82,
        0x71, 0xae, 0x35, 0xf8, 0xe9, 0xdb, 0xfb, 0xb6,
        0x94, 0xb5, 0xc8, 0x03, 0xd8, 0x9f, 0x7a, 0xe4,
        0x35, 0xde, 0x23, 0x6d, 0x52, 0x5f, 0x54, 0x75,
        0x9b, 0x65, 0xe3, 0x72, 0xfc, 0xd6, 0x8e, 0xf2,
        0x0f, 0xa7, 0x11, 0x1f, 0x9e, 0x4a, 0xff, 0x73
    };
    return N;
}

const Bytes& g() {
    static const Bytes g_val = {0x02};
    return g_val;
}

Bytes g_padded(int n_len) {
    Bytes out(n_len, 0);
    out[n_len - 1] = 0x02; // g = 2, left-padded with zeros
    return out;
}

Bytes random_private_value() {
    Bytes out(32);
    RAND_bytes(out.data(), 32);
    return out;
}

Bytes compute_A(const Bytes& a, const Bytes& N, const Bytes& g_bytes, int n_len) {
    BIGNUM* N_bn = bn_from_bytes(N);
    BIGNUM* g_bn = bn_from_bytes(g_bytes);
    BIGNUM* a_bn = bn_from_bytes(a);
    BN_CTX* ctx  = bn_ctx_new();

    BIGNUM* A_bn = bn_mod_exp(g_bn, a_bn, N_bn, ctx);
    Bytes A_padded = bn_to_padded(A_bn, n_len);

    bn_free(N_bn); bn_free(g_bn); bn_free(a_bn); bn_free(A_bn);
    bn_ctx_free(ctx);
    return A_padded;
}

Bytes compute_k(const Bytes& N_padded, const Bytes& g_padded_bytes) {
    Bytes ki;
    ki.reserve(N_padded.size() + g_padded_bytes.size());
    ki.insert(ki.end(), N_padded.begin(), N_padded.end());
    ki.insert(ki.end(), g_padded_bytes.begin(), g_padded_bytes.end());
    return sha2::digest(ki);
}

Bytes compute_u(const Bytes& A_padded, const Bytes& B_padded) {
    Bytes ui;
    ui.reserve(A_padded.size() + B_padded.size());
    ui.insert(ui.end(), A_padded.begin(), A_padded.end());
    ui.insert(ui.end(), B_padded.begin(), B_padded.end());
    return sha2::digest(ui);
}

Bytes compute_x_apple(const std::string& password, const Bytes& salt, int iterations) {
    // p = PBKDF2-HMAC-SHA256( SHA256(password), salt, iters, 32 )
    Bytes hashed_pw = sha2::digest(password);
    std::string hashed_pw_str(hashed_pw.begin(), hashed_pw.end());
    Bytes p_hash = sha2::pbkdf2(hashed_pw_str, salt.data(), (int)salt.size(), iterations, 32);

    // h2 = SHA256( ":" || p )
    Bytes colon_p;
    colon_p.push_back(':');
    colon_p.insert(colon_p.end(), p_hash.begin(), p_hash.end());
    Bytes h2 = sha2::digest(colon_p);

    // x = SHA256( salt || h2 )
    Bytes x_in(salt.begin(), salt.end());
    x_in.insert(x_in.end(), h2.begin(), h2.end());
    return sha2::digest(x_in);
}

Bytes compute_premaster_secret(const Bytes& B, const Bytes& k, const Bytes& g_bytes,
                               const Bytes& x, const Bytes& N, const Bytes& a,
                               const Bytes& u, int n_len) {
    BIGNUM* N_bn = bn_from_bytes(N);
    BIGNUM* g_bn = bn_from_bytes(g_bytes);
    BIGNUM* B_bn = bn_from_bytes(B);
    BIGNUM* k_bn = bn_from_bytes(k);
    BIGNUM* x_bn = bn_from_bytes(x);
    BIGNUM* a_bn = bn_from_bytes(a);
    BIGNUM* u_bn = bn_from_bytes(u);
    BN_CTX* ctx  = bn_ctx_new();

    BIGNUM* gx  = bn_mod_exp(g_bn, x_bn, N_bn, ctx);
    BIGNUM* kv  = bn_mod_mul(k_bn, gx, N_bn, ctx);
    BIGNUM* Bkv = bn_mod_sub(B_bn, kv, N_bn, ctx);
    BIGNUM* ux  = bn_mul(u_bn, x_bn, ctx);
    BIGNUM* exp = bn_add(a_bn, ux);
    BIGNUM* S   = bn_mod_exp(Bkv, exp, N_bn, ctx);

    Bytes S_padded = bn_to_padded(S, n_len);

    bn_free(N_bn); bn_free(g_bn); bn_free(B_bn); bn_free(k_bn);
    bn_free(x_bn); bn_free(a_bn); bn_free(u_bn);
    bn_free(gx); bn_free(kv); bn_free(Bkv); bn_free(ux); bn_free(exp); bn_free(S);
    bn_ctx_free(ctx);

    return S_padded;
}

Bytes compute_session_key(const Bytes& S) {
    return sha2::digest(S);
}

Bytes compute_M1(const Bytes& N_padded, const Bytes& g_padded_bytes,
                 const std::string& email_lowercase, const Bytes& salt,
                 const Bytes& A_padded, const Bytes& B_padded, const Bytes& K) {
    Bytes HN = sha2::digest(N_padded);
    Bytes Hg = sha2::digest(g_padded_bytes);
    Bytes xor_HN_Hg(32);
    for (int i = 0; i < 32; i++) xor_HN_Hg[i] = HN[i] ^ Hg[i];

    Bytes h_email = sha2::digest(email_lowercase);

    Bytes m1in;
    m1in.reserve(32 + 32 + salt.size() + A_padded.size() + B_padded.size() + K.size());
    m1in.insert(m1in.end(), xor_HN_Hg.begin(), xor_HN_Hg.end());
    m1in.insert(m1in.end(), h_email.begin(),   h_email.end());
    m1in.insert(m1in.end(), salt.begin(),      salt.end());
    m1in.insert(m1in.end(), A_padded.begin(),  A_padded.end());
    m1in.insert(m1in.end(), B_padded.begin(),  B_padded.end());
    m1in.insert(m1in.end(), K.begin(),         K.end());

    return sha2::digest(m1in);
}

} // namespace srp
