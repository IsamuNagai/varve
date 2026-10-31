/*
 * Varve proof-of-work vector generator (RandomX v2 with the Varve salt).
 *
 * Build with tools/randomx/build_and_check.sh, which fetches the pinned
 * RandomX commit, verifies it, applies tools/randomx/varve-salt.patch, and
 * compares this program's output against test-vectors/pow.json.
 *
 * Usage: pow_vectors [portable|fast]
 *   portable  interpreter, software AES (RANDOMX_FLAG_DEFAULT | RANDOMX_FLAG_V2)
 *   fast      best flags for this CPU: JIT, hardware AES where available
 */
#include <stdio.h>
#include <string.h>
#include "randomx.h"

static void hex(const unsigned char *b, int n) {
  for (int i = 0; i < n; i++) printf("%02x", b[i]);
}

static unsigned long long splitmix64(unsigned long long *x) {
  unsigned long long z = (*x += 0x9E3779B97F4A7C15ULL);
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
  return z ^ (z >> 31);
}

/* 4 keys x 16 headers = 64 vectors. Header 0 is all zero, header 1 all 0xFF,
 * header 2 the pattern 0..115, the rest pseudo-random (splitmix64, fixed seeds). */
static void make_input(int k, int n, unsigned char *in) {
  if (n == 0) { memset(in, 0x00, 116); return; }
  if (n == 1) { memset(in, 0xFF, 116); return; }
  if (n == 2) { for (int i = 0; i < 116; i++) in[i] = (unsigned char)i; return; }
  unsigned long long st = 0x5641525645504F57ULL ^ ((unsigned long long)k << 32) ^ (unsigned long long)n;
  for (int i = 0; i < 116; i++) in[i] = (unsigned char)(splitmix64(&st) >> 56);
}

int main(int argc, char **argv) {
  const char *keys[4] = {"VARVE/pow/test-key/v1", "VARVE/pow/test-key/v2", "", "VARVE/pow/test-key/a-much-longer-key-string-used-to-test-arbitrary-key-lengths-0123456789"};
  unsigned char input[116];

  randomx_flags fl = RANDOMX_FLAG_DEFAULT | RANDOMX_FLAG_V2;
  if (argc > 1 && strcmp(argv[1], "fast") == 0) fl = randomx_get_flags() | RANDOMX_FLAG_V2;
  else if (argc > 1 && strcmp(argv[1], "portable") != 0) { fprintf(stderr, "usage: %s [portable|fast]\n", argv[0]); return 2; }

  for (int k = 0; k < 4; k++) {
    randomx_cache *c = randomx_alloc_cache(fl);
    if (!c) { fprintf(stderr, "cache allocation failed\n"); return 1; }
    randomx_init_cache(c, keys[k], strlen(keys[k]));
    randomx_vm *vm = randomx_create_vm(fl, c, NULL);
    if (!vm) { fprintf(stderr, "vm creation failed\n"); return 1; }
    for (int n = 0; n < 16; n++) {
      unsigned char out[RANDOMX_HASH_SIZE];
      make_input(k, n, input);
      randomx_calculate_hash(vm, input, sizeof input, out);
      printf("%s ", strlen(keys[k]) ? keys[k] : "(empty)");
      hex(input, sizeof input);
      printf(" ");
      hex(out, RANDOMX_HASH_SIZE);
      printf("\n");
    }
    randomx_destroy_vm(vm);
    randomx_release_cache(c);
  }
  return 0;
}
