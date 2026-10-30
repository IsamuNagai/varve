/*
 * Generates test-vectors/pow.json entries for Varve proof of work.
 *
 * Build RandomX (github.com/tevador/RandomX) with, in src/configuration.h:
 *   #define RANDOMX_ARGON_SALT "VarveRX\x01"
 * then: g++ -O2 -o pow_vectors pow_vectors.c -I<RandomX>/src <RandomX>/build/librandomx.a -lpthread
 */
#include <stdio.h>
#include <string.h>
#include "randomx.h"
static void hex(const unsigned char *b, int n){for(int i=0;i<n;i++)printf("%02x",b[i]);}
int main(void){
  const char *keys[2] = {"VARVE/pow/test-key/v1", "VARVE/pow/test-key/v2"};
  unsigned char input[116]; for(int i=0;i<116;i++) input[i]=(unsigned char)i;
  randomx_flags fl = RANDOMX_FLAG_DEFAULT | RANDOMX_FLAG_V2;   /* portable interpreter, light mode; use randomx_get_flags() | RANDOMX_FLAG_V2 to cross-check the JIT */
  for (int k=0;k<2;k++){
    randomx_cache *c = randomx_alloc_cache(fl); randomx_init_cache(c, keys[k], strlen(keys[k]));
    randomx_vm *vm = randomx_create_vm(fl, c, NULL);
    for (int n=0;n<2;n++){ unsigned char out[RANDOMX_HASH_SIZE]; input[115]=(unsigned char)n;
      randomx_calculate_hash(vm, input, sizeof input, out);
      printf("key=\"%s\" input=bytes(0..114)||%02x hash=", keys[k], n); hex(out,32); printf("\n"); }
    randomx_destroy_vm(vm); randomx_release_cache(c);
  }
  return 0;
}
