#include "hash.h"

#include <string.h>

/* Wide mixing hash for end-state signatures.
 *
 * 16 u64 accumulators consume 128-byte blocks with an XXH3-style product and
 * scramble every 8 blocks. A word's keyed product enters its own lane and its
 * raw value enters the neighboring lane. Keeping these contributions separate
 * prevents the single-bit cancellation possible when both entered one lane.
 * Keys change with the block index, so exchanging words between blocks changes
 * their keyed contributions. The scalar and AVX2 paths use identical arithmetic.
 * Not cryptographic; the final 64-bit signature still has finite collision risk.
 * The structure and constants follow xxHash (Yann Collet); the code is original. */

#define LANES 16
#define BLOCK 128
#define SCRAMBLE_EVERY 8
#define PRIME32_1 0x9E3779B1ull
#define PRIME64_1 0x9E3779B185EBCA87ull
#define KEY_STEP 0xC2B2AE3D27D4EB4Full   /* odd: key of lane i for block b is KEYS[i] + b * KEY_STEP */

static const uint64_t KEYS[LANES] = {
    0xB8FE6C3923A44BBEull, 0x7C01812CF721AD1Cull, 0xDED46DE9839097DBull, 0x7240A4A4B7B3671Full,
    0xCB79E64ECCC0E578ull, 0x825AD07DCCFF7221ull, 0xB8084674F743248Eull, 0xE36819D5A1A55B3Bull,
    0x0DDEC19E24A0D6DFull, 0x3DE63ABF8F7E7DF6ull, 0x7C53CF4A5D5C2A9Bull, 0xA94A8B6DB4B66919ull,
    0xC7DDB3DB1D3ED96Full, 0x8D3C21D3D7A32C7Bull, 0x64FCD6E2E0BAF9F3ull, 0x9FA8C4D3E8F1B2A5ull,
};

int harp_hash_hw(void) { return __builtin_cpu_supports("avx2"); }

static inline uint64_t keyed_product(uint64_t v, uint64_t key) {
    uint64_t k = v ^ key;
    return (uint64_t)(uint32_t)k * (k >> 32);
}

static inline uint64_t scramble(uint64_t acc, uint64_t key) {
    acc ^= acc >> 47;
    acc ^= key;
    return acc * PRIME32_1;
}

static void init_acc(uint64_t seed, uint64_t acc[LANES]) {
    for (int i = 0; i < LANES; i++) acc[i] = KEYS[i] ^ (seed + PRIME64_1 * (uint64_t)(i + 1));
}

static uint64_t finish(const uint64_t acc[LANES], uint64_t seed, size_t len) {
    uint64_t h = harp_hash_combine(seed, (uint64_t)len * PRIME64_1);
    for (int i = 0; i < LANES; i++) h = harp_hash_combine(h, acc[i]);
    return h;
}

/* Bytes not covered by whole blocks (fewer than BLOCK): whole 8-byte words go to successive
 * lanes with the keys of block index nblocks, a final partial word is zero-padded and tagged
 * with its length. */
static void tail(uint64_t acc[LANES], const uint8_t *p, size_t n, size_t nblocks) {
    const uint64_t step = (uint64_t)nblocks * KEY_STEP;
    int lane = 0;
    while (n >= 8) {
        uint64_t w;
        memcpy(&w, p, 8);
        acc[lane] += keyed_product(w, KEYS[lane] + step);
        acc[lane ^ 1] += w;
        lane++;
        p += 8;
        n -= 8;
    }
    if (n) {
        uint64_t w = 0;
        memcpy(&w, p, n);
        acc[lane] += keyed_product(w, (KEYS[lane] + step) ^ (uint64_t)n);
        acc[lane ^ 1] += w;
    }
}

static void blocks_sw(uint64_t acc[LANES], const uint8_t *p, size_t nblocks) {
    for (size_t b = 0; b < nblocks; b++) {
        const uint64_t step = (uint64_t)b * KEY_STEP;
        uint64_t w[LANES];
        memcpy(w, p + b * BLOCK, BLOCK);
        for (int i = 0; i < LANES; i++) {
            acc[i] += keyed_product(w[i], KEYS[i] + step);
            acc[i ^ 1] += w[i];
        }
        if ((b + 1) % SCRAMBLE_EVERY == 0)
            for (int i = 0; i < LANES; i++) acc[i] = scramble(acc[i], KEYS[(i + 5) & (LANES - 1)]);
    }
}

#include <immintrin.h>

__attribute__((target("avx2")))
static inline __m256i mul64x32(__m256i a, __m256i prime) {
    /* Exact (a * prime) mod 2^64 for a 32-bit prime: lo(a)*p + (hi(a)*p) << 32. */
    __m256i lo = _mm256_mul_epu32(a, prime);
    __m256i hi = _mm256_mul_epu32(_mm256_srli_epi64(a, 32), prime);
    return _mm256_add_epi64(lo, _mm256_slli_epi64(hi, 32));
}

__attribute__((target("avx2")))
static void blocks_hw(uint64_t acc[LANES], const uint8_t *p, size_t nblocks) {
    __m256i a0 = _mm256_loadu_si256((const __m256i *)(acc + 0));
    __m256i a1 = _mm256_loadu_si256((const __m256i *)(acc + 4));
    __m256i a2 = _mm256_loadu_si256((const __m256i *)(acc + 8));
    __m256i a3 = _mm256_loadu_si256((const __m256i *)(acc + 12));
    __m256i k0 = _mm256_loadu_si256((const __m256i *)(KEYS + 0));
    __m256i k1 = _mm256_loadu_si256((const __m256i *)(KEYS + 4));
    __m256i k2 = _mm256_loadu_si256((const __m256i *)(KEYS + 8));
    __m256i k3 = _mm256_loadu_si256((const __m256i *)(KEYS + 12));
    const __m256i kstep = _mm256_set1_epi64x((long long)KEY_STEP);
    const __m256i prime = _mm256_set1_epi64x((long long)PRIME32_1);
    uint64_t skeys[LANES];
    for (int i = 0; i < LANES; i++) skeys[i] = KEYS[(i + 5) & (LANES - 1)];
    const __m256i s0 = _mm256_loadu_si256((const __m256i *)(skeys + 0));
    const __m256i s1 = _mm256_loadu_si256((const __m256i *)(skeys + 4));
    const __m256i s2 = _mm256_loadu_si256((const __m256i *)(skeys + 8));
    const __m256i s3 = _mm256_loadu_si256((const __m256i *)(skeys + 12));
#define STEP(acc, key, off)                                                                   \
    do {                                                                                      \
        __m256i v = _mm256_loadu_si256((const __m256i *)(p + (off)));                         \
        __m256i k = _mm256_xor_si256(v, key);                                                 \
        __m256i prod = _mm256_mul_epu32(k, _mm256_shuffle_epi32(k, _MM_SHUFFLE(2, 3, 0, 1))); \
        __m256i sw = _mm256_permute4x64_epi64(v, _MM_SHUFFLE(2, 3, 0, 1));                    \
        acc = _mm256_add_epi64(acc, _mm256_add_epi64(prod, sw));                              \
    } while (0)
#define SCR(acc, key)                                                                         \
    do {                                                                                      \
        __m256i x = _mm256_xor_si256(acc, _mm256_srli_epi64(acc, 47));                        \
        x = _mm256_xor_si256(x, key);                                                         \
        acc = mul64x32(x, prime);                                                             \
    } while (0)
    for (size_t b = 0; b < nblocks; b++) {
        STEP(a0, k0, 0);
        STEP(a1, k1, 32);
        STEP(a2, k2, 64);
        STEP(a3, k3, 96);
        p += BLOCK;
        k0 = _mm256_add_epi64(k0, kstep); k1 = _mm256_add_epi64(k1, kstep);   /* keys of the next block */
        k2 = _mm256_add_epi64(k2, kstep); k3 = _mm256_add_epi64(k3, kstep);
        if ((b + 1) % SCRAMBLE_EVERY == 0) { SCR(a0, s0); SCR(a1, s1); SCR(a2, s2); SCR(a3, s3); }
    }
#undef STEP
#undef SCR
    _mm256_storeu_si256((__m256i *)(acc + 0), a0);
    _mm256_storeu_si256((__m256i *)(acc + 4), a1);
    _mm256_storeu_si256((__m256i *)(acc + 8), a2);
    _mm256_storeu_si256((__m256i *)(acc + 12), a3);
}

static uint64_t hash_impl(uint64_t seed, const uint8_t *p, size_t len, int hw) {
    uint64_t acc[LANES];
    init_acc(seed, acc);
    size_t nblocks = len / BLOCK;
    if (hw) blocks_hw(acc, p, nblocks); else blocks_sw(acc, p, nblocks);
    tail(acc, p + nblocks * BLOCK, len - nblocks * BLOCK, nblocks);
    return finish(acc, seed, len);
}

uint64_t harp_hash64(uint64_t seed, const void *data, size_t len) {
    return hash_impl(seed, data, len, harp_hash_hw());
}

uint64_t harp_hash_combine(uint64_t a, uint64_t b) {
    uint64_t x = a ^ (b + 0x9E3779B97F4A7C15ull + (a << 6) + (a >> 2));
    x ^= x >> 31; x *= 0x7FB5D329728EA185ull; x ^= x >> 27; x *= 0x81DADEF4BC2DD44Dull; x ^= x >> 33;
    return x;
}
