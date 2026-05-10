#pragma once
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <ctime>



//RSA

// Modular exponentiation: compute (base ^ exp) % mod
// This is the core of RSA. We use __uint128_t to avoid overflow.
inline uint64_t mod_pow(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1)                                    
            result = (__uint128_t)result * base % mod;
        base = (__uint128_t)base * base % mod;
        exp >>= 1;                                     
    }
    return result;
}

// Extended Euclidean Algorithm: find x such that (a * x) % m == 1
// We use this to compute the RSA private key d from e and phi
inline uint64_t mod_inverse(uint64_t a, uint64_t m) {
    int64_t old_r = a, r = m, old_s = 1, s = 0;
    while (r != 0) {
        int64_t q = old_r / r;
        int64_t t = r;   r   = old_r - q * r;   old_r = t;
                    t = s;   s   = old_s - q * s;   old_s = t;
    }
    return (old_s % (int64_t)m + m) % m;
}

// Check if a number is prime
inline bool is_prime(uint64_t n) {
    if (n < 2) return false;
    for (uint64_t i = 2; i * i <= n; i++)
        if (n % i == 0) return false;
    return true;
}

// Pick a random prime between lo and hi
inline uint64_t random_prime(uint64_t lo, uint64_t hi) {
    uint64_t n;
    do { n = lo + rand() % (hi - lo); } while (!is_prime(n));
    return n;
}

// RSA key pair
struct RSAKey {
    uint64_t n;   
    uint64_t e;   
    uint64_t d;   
};

// Generating a RSA key pair
inline RSAKey rsa_keygen() {
    srand(time(NULL) ^ (uint64_t)&rsa_keygen);  // seed randomly

    // Pick two small primes p and q
    uint64_t p = random_prime(50, 120);
    uint64_t q;
    do { q = random_prime(50, 120); } while (q == p);

    uint64_t n   = p * q;               
    uint64_t phi = (p - 1) * (q - 1);  

    // Public exponent e: must be coprime with phi, 3 is simple and works
    uint64_t e = 3;
    while (phi % e == 0) e += 2;   // make sure gcd(e, phi) == 1

    uint64_t d = mod_inverse(e, phi);  // private key

    return {n, e, d};
}

// Encrypting one number, ciphertext = plaintext^e mod n
inline uint64_t rsa_encrypt(uint64_t msg, uint64_t e, uint64_t n) {
    return mod_pow(msg, e, n);
}

// Decrypting one number, plaintext = ciphertext^d mod n
inline uint64_t rsa_decrypt(uint64_t cipher, uint64_t d, uint64_t n) {
    return mod_pow(cipher, d, n);
}

// Encrypt a short byte array with RSA (each byte encrypted separately)
// Output: each byte becomes a uint64_t (8 bytes), so output is 8× input size
inline int rsa_encrypt_bytes(const uint8_t* in, int in_len,
                              uint64_t e, uint64_t n,
                              uint8_t* out, int out_max) {
    // Each byte → 8 bytes of output
    if (in_len * 8 > out_max) return -1;
    for (int i = 0; i < in_len; i++) {
        uint64_t enc = rsa_encrypt(in[i], e, n);
        memcpy(out + i * 8, &enc, 8);
    }
    return in_len * 8;
}

// Decrypt: each 8-byte block → one byte of original data
inline int rsa_decrypt_bytes(const uint8_t* in, int in_len,
                              uint64_t d, uint64_t n,
                              uint8_t* out, int out_max) {
    int blocks = in_len / 8;
    if (blocks > out_max) return -1;
    for (int i = 0; i < blocks; i++) {
        uint64_t enc;
        memcpy(&enc, in + i * 8, 8);
        out[i] = (uint8_t)rsa_decrypt(enc, d, n);
    }
    return blocks;
}


//AES  
//Use the key to generate a stream of pseudo-random bytes,
//Then XOR them with the message.
//  Key = 8 bytes.  We use a simple LCG (linear congruential generator) to produce the keystream.

// Generate a keystream of `len` bytes from the key
// iv (initialization vector) makes each message unique
inline void make_keystream(const uint8_t key[8], uint64_t iv,
                            uint8_t* stream, int len) {
    // Combine key bytes into a 64-bit seed, XOR with iv
    uint64_t seed = iv;
    for (int i = 0; i < 8; i++) seed ^= (uint64_t)key[i] << (i * 8);

    // LCG: next = (a * current + c) % m
    uint64_t state = seed;
    for (int i = 0; i < len; i++) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        stream[i] = (uint8_t)(state >> 33);  // using upper bits
    }
}

// Encrypt: XOR plaintext with keystream. Also prepend the IV.
// Output format: [ IV (8 bytes) | ciphertext (len bytes) ]
// Returns total output length = len + 8
inline int aes_encrypt(const char* in, int len,
                        const uint8_t key[8], uint64_t iv,
                        char* out, int out_max) {
    if (len + 8 > out_max) return -1;
    // Write IV first so receiver can decrypt
    memcpy(out, &iv, 8);
    // Generate keystream and XOR
    uint8_t stream[2048] = {};
    make_keystream(key, iv, stream, len);
    for (int i = 0; i < len; i++)
        out[8 + i] = in[i] ^ (char)stream[i];
    return len + 8;
}

// Decrypt: read IV from first 8 bytes, regenerate keystream, XOR
inline int aes_decrypt(const char* in, int len,
                        const uint8_t key[8],
                        char* out, int out_max) {
    if (len < 8) return -1;
    uint64_t iv;
    memcpy(&iv, in, 8);
    int data_len = len - 8;
    if (data_len > out_max) return -1;
    uint8_t stream[2048] = {};
    make_keystream(key, iv, stream, data_len);
    for (int i = 0; i < data_len; i++)
        out[i] = in[8 + i] ^ (char)stream[i];
    return data_len;
}