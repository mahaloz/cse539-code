#include <cmath>
#include <numeric>

#include <bsd/stdlib.h>
#include <x86intrin.h>

#define _64_CHOOSE_32 1832624140942590534ULL

uint64_t unrank(uint64_t rank)
{
int j = 64;
uint64_t binom = _64_CHOOSE_32;

uint64_t val = 0;
uint64_t bitmask = 0x8000000000000000ULL;

for (int i = 0; i < 31; ++i)
{
// in while body: binomial(j,32-i) -> binomial(j-1,32-i)
while (binom > rank) { binom *= j-32+i; binom /= j; j--; bitmask >>= 1; }
val |= bitmask;
rank -= binom;
// binomial(j,32-i) -> binomial(j,32-i-1)
binom *= 32-i;
binom /= j-32+i+1;
}
while (binom > rank) { binom*=j-1; binom/=j; j--; bitmask >>= 1; }

return val;
}

void test()
{
uint64_t hash[2];
arc4random_buf(&hash, sizeof(hash)); // should actually be the root hash

uint64_t challenge[2] = {
unrank(hash[0] % _64_CHOOSE_32), // ignoring modulo bias; thus, we lose
unrank(hash[1] % _64_CHOOSE_32) // (less than) 1-bit entropy per limb
};

__m128i x;
arc4random_buf(&x, sizeof(x)); // some row from the transposed proof

uint32_t compressed_x[2] = {
static_cast<uint32_t>(_pext_u64(_mm_extract_epi64(x, 0), challenge[0])),
static_cast<uint32_t>(_pext_u64(_mm_extract_epi64(x, 1), challenge[1]))
};

__m128i decompressed_x = _mm_set_epi64x(
_pdep_u64(compressed_x[1], challenge[1]),
_pdep_u64(compressed_x[0], challenge[0])
// _pdep_u64(static_cast<unsigned __int64>(compressed_x[0]), challenge[0]),
// _pdep_u64(static_cast<unsigned __int64>(compressed_x[1]), challenge[1])
);

printf("%016lx %016lx\n%016llx %016llx->%016llx %016llx\n", challenge[0], challenge[1], x[0]&challenge[0], x[1]&challenge[1], decompressed_x[0],
decompressed_x[1]);
printf("%u,%u\n\n", _popcnt64(challenge[0]),_popcnt64(challenge[1]));
}

int main(int argc, char * argv[])
{
for (int i = 0; i < 10; ++i) test();
return 0;
}