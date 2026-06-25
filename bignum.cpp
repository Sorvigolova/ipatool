#include "bignum.h"
#include <stdexcept>

BIGNUM* bn_new() {
    return BN_new();
}

BIGNUM* bn_from_bytes(const uint8_t* data, int len) {
    return BN_bin2bn(data, len, nullptr);
}

BIGNUM* bn_from_bytes(const Bytes& data) {
    return BN_bin2bn(data.data(), (int)data.size(), nullptr);
}

BIGNUM* bn_from_hex(const std::string& hex) {
    BIGNUM* n = nullptr;
    BN_hex2bn(&n, hex.c_str());
    return n;
}

BIGNUM* bn_from_word(unsigned long w) {
    BIGNUM* n = BN_new();
    BN_set_word(n, w);
    return n;
}

void bn_free(BIGNUM* n) {
    BN_free(n);
}

Bytes bn_to_bytes(const BIGNUM* n) {
    int len = BN_num_bytes(n);
    Bytes out(len);
    BN_bn2bin(n, out.data());
    return out;
}

Bytes bn_to_padded(const BIGNUM* n, int padlen) {
    Bytes out(padlen, 0);
    int len = BN_num_bytes(n);
    if (len > padlen) len = padlen; // truncate defensively, shouldn't happen in practice
    BN_bn2bin(n, out.data() + padlen - len);
    return out;
}

int bn_num_bytes(const BIGNUM* n) {
    return BN_num_bytes(n);
}

BN_CTX* bn_ctx_new() {
    return BN_CTX_new();
}

void bn_ctx_free(BN_CTX* ctx) {
    BN_CTX_free(ctx);
}

BIGNUM* bn_mod_exp(const BIGNUM* base, const BIGNUM* exp, const BIGNUM* mod, BN_CTX* ctx) {
    BIGNUM* result = BN_new();
    BN_mod_exp(result, base, exp, mod, ctx);
    return result;
}

BIGNUM* bn_mod_mul(const BIGNUM* a, const BIGNUM* b, const BIGNUM* mod, BN_CTX* ctx) {
    BIGNUM* result = BN_new();
    BN_mod_mul(result, a, b, mod, ctx);
    return result;
}

BIGNUM* bn_mod_add(const BIGNUM* a, const BIGNUM* b, const BIGNUM* mod, BN_CTX* ctx) {
    BIGNUM* result = BN_new();
    BN_mod_add(result, a, b, mod, ctx);
    return result;
}

BIGNUM* bn_mod_sub(const BIGNUM* a, const BIGNUM* b, const BIGNUM* mod, BN_CTX* ctx) {
    BIGNUM* result = BN_new();
    BN_mod_sub(result, a, b, mod, ctx);
    return result;
}

BIGNUM* bn_mul(const BIGNUM* a, const BIGNUM* b, BN_CTX* ctx) {
    BIGNUM* result = BN_new();
    BN_mul(result, a, b, ctx);
    return result;
}

BIGNUM* bn_add(const BIGNUM* a, const BIGNUM* b) {
    BIGNUM* result = BN_new();
    BN_add(result, a, b);
    return result;
}
