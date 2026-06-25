#pragma once
// bignum.h — thin free-function wrappers around OpenSSL BIGNUM.
//
// Style: plain free functions, caller owns and frees what they create
// (same discipline as raw OpenSSL — no RAII wrapper class by design,
// so this stays a reusable general-purpose bignum module, not something
// tied to SRP's specific needs).
//
// Caller is responsible for calling bn_free() on every BIGNUM* they
// receive from a bn_* constructor function below.

#include <openssl/bn.h>
#include <string>
#include <vector>
#include <cstdint>

using Bytes = std::vector<uint8_t>;

// ── Construction ─────────────────────────────────────────────────────────

// New zero-initialized BIGNUM. Caller must bn_free().
BIGNUM* bn_new();

// Parse big-endian bytes into a BIGNUM. Caller must bn_free().
BIGNUM* bn_from_bytes(const uint8_t* data, int len);
BIGNUM* bn_from_bytes(const Bytes& data);

// Parse a hex string into a BIGNUM. Caller must bn_free().
BIGNUM* bn_from_hex(const std::string& hex);

// BIGNUM holding a small unsigned word value (e.g. the SRP generator g=2).
// Caller must bn_free().
BIGNUM* bn_from_word(unsigned long w);

void bn_free(BIGNUM* n);

// ── Conversion out ───────────────────────────────────────────────────────

// Big-endian byte serialization, no padding (length = BN_num_bytes(n)).
Bytes bn_to_bytes(const BIGNUM* n);

// Big-endian byte serialization, zero-padded on the left to exactly
// padlen bytes. Used throughout SRP where the protocol requires fixed
// width values (e.g. 256 bytes for the 2048-bit modulus N).
Bytes bn_to_padded(const BIGNUM* n, int padlen);

int bn_num_bytes(const BIGNUM* n);

// ── Arithmetic (modular, used by SRP-6a) ────────────────────────────────
// All of these allocate and return a new BIGNUM* — caller must bn_free().
// `ctx` is an OpenSSL BN_CTX scratch context, created once per call site
// with bn_ctx_new() / freed with bn_ctx_free().

BN_CTX* bn_ctx_new();
void    bn_ctx_free(BN_CTX* ctx);

// result = (base ^ exp) mod mod
BIGNUM* bn_mod_exp(const BIGNUM* base, const BIGNUM* exp, const BIGNUM* mod, BN_CTX* ctx);

// result = (a * b) mod mod
BIGNUM* bn_mod_mul(const BIGNUM* a, const BIGNUM* b, const BIGNUM* mod, BN_CTX* ctx);

// result = (a + b) mod mod
BIGNUM* bn_mod_add(const BIGNUM* a, const BIGNUM* b, const BIGNUM* mod, BN_CTX* ctx);

// result = (a - b) mod mod
BIGNUM* bn_mod_sub(const BIGNUM* a, const BIGNUM* b, const BIGNUM* mod, BN_CTX* ctx);

// result = a * b   (plain multiply, no modulus)
BIGNUM* bn_mul(const BIGNUM* a, const BIGNUM* b, BN_CTX* ctx);

// result = a + b   (plain add, no modulus)
BIGNUM* bn_add(const BIGNUM* a, const BIGNUM* b);
