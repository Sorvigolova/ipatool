#pragma once
// srp.h — SRP-6a math for Apple GrandSlam Authentication (GSA).
//
// Group: RFC 5054 Appendix A / pysrp NG_2048 prime, g = 2.
// NOTE: this is NOT the same prime as BN_get_rfc3526_prime_2048() (that's
// the RFC 3526 IKE group) — Apple GSA specifically uses the RFC 5054 one.
//
// Apple's "s2k" x derivation (NOT the textbook SRP-6a x = H(salt||I||":"||P)):
//   p  = PBKDF2-HMAC-SHA256( SHA256(password), salt, iters, 32 )
//   h2 = SHA256( ":" || p )            (empty username, just the colon)
//   x  = SHA256( salt || h2 )
//
// Free-function style throughout — no class, caller passes/owns Bytes.

#include <vector>
#include <cstdint>
#include <string>

using Bytes = std::vector<uint8_t>;

namespace srp {

// 2048-bit SRP modulus N, big-endian, 256 bytes. (RFC 5054 Appendix A)
const Bytes& N_2048();

// Generator g = 2, NOT padded.
const Bytes& g();

// N padded to its own length (no-op, included for symmetry/clarity) and
// g padded to N's byte length — needed throughout because Apple's k/u/M1
// hashes all operate on fixed-width values.
Bytes g_padded(int n_len);

// 32 random bytes — the client's SRP private value 'a'.
Bytes random_private_value();

// A = g^a mod N, padded to n_len bytes.
Bytes compute_A(const Bytes& a, const Bytes& N, const Bytes& g, int n_len);

// k = SHA256( N_padded || g_padded )
Bytes compute_k(const Bytes& N_padded, const Bytes& g_padded);

// u = SHA256( A_padded || B_padded )
Bytes compute_u(const Bytes& A_padded, const Bytes& B_padded);

// Apple's s2k x derivation — see file header comment for the formula.
Bytes compute_x_apple(const std::string& password, const Bytes& salt, int iterations);

// Premaster secret S, padded to n_len bytes:
//   v   = g^x mod N
//   kv  = k*v mod N
//   Bkv = (B - kv) mod N
//   exp = a + u*x
//   S   = Bkv^exp mod N
Bytes compute_premaster_secret(const Bytes& B, const Bytes& k, const Bytes& g,
                               const Bytes& x, const Bytes& N, const Bytes& a,
                               const Bytes& u, int n_len);

// Session key K = SHA256(S)
Bytes compute_session_key(const Bytes& S);

// Client evidence message M1:
//   M1 = SHA256( (H(N) XOR H(g_padded)) || H(email_lowercase) || salt
//                || A_padded || B_padded || K )
Bytes compute_M1(const Bytes& N_padded, const Bytes& g_padded,
                 const std::string& email_lowercase, const Bytes& salt,
                 const Bytes& A_padded, const Bytes& B_padded, const Bytes& K);

} // namespace srp
