#ifndef HARPRUN_HASH_H
#define HARPRUN_HASH_H
#include <stddef.h>
#include <stdint.h>

/* Version of the signature: the hash below and what the runner feeds into it. Signatures of
 * different versions are not comparable; stored references carry the version they were made with.
 * 1 is the definition of the first release (a word's keyed product goes to its own lane and its
 * raw value to the neighboring lane); nothing earlier was released or stamped in a pack. */
#define HARP_SIG_VERSION 1u

/* 64-bit hash of a byte range, sensitive to the position of every byte (16-lane mixer, AVX2
 * path with an identical scalar path); the same bytes give the same value on every x86-64 CPU. */
uint64_t harp_hash64(uint64_t seed, const void *data, size_t len);
uint64_t harp_hash_combine(uint64_t a, uint64_t b);
int harp_hash_hw(void); /* nonzero when the AVX2 path is in use */

#endif
