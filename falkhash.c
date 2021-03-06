/* #pragma warning(push, 0) */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

#ifdef _MSC_VER
#include <intrin.h>
#else
#include <x86intrin.h>
#endif
/* #pragma warning(pop) */

/* Discard SAL annotations if you're not using MSVC :( */
#ifndef _MSC_VER
#define _In_
#define _In_reads_bytes_(x)
#endif

/* falkhash()
 *
 * Summary:
 *
 * Performs a falkhash and returns the result.
 */
__m128i
falkhash_v1(
		_In_reads_bytes_(len) void     *pbuf,
		_In_                  uint64_t  len,
		_In_                  uint64_t  pseed)
{
	uint8_t *buf = (uint8_t*)pbuf;

	uint64_t iv[2];

	__m128i hash, seed;

	/* Create the 128-bit seed. Low and high 64-bits gets (seed + len). */
	iv[0] = iv[1] = pseed  + len;

	/* Load the IV into a __m128i */
	seed = _mm_loadu_si128((__m128i*)iv);

	/* Hash starts out with the seed */
	hash = seed;

	while(len){
		uint8_t tmp[0x50];

		__m128i piece[5];

		/* If the data is smaller than one chunk, pad it with 0xff */
		if(len < 0x50){
			memset(tmp, 0xff, 0x50);
			memcpy(tmp, buf, len);
			buf = tmp;
			len = 0x50;
		}

		/* Load up the data into __m128is */
		piece[0] = _mm_loadu_si128((__m128i*)(buf + 0*0x10));
		piece[1] = _mm_loadu_si128((__m128i*)(buf + 1*0x10));
		piece[2] = _mm_loadu_si128((__m128i*)(buf + 2*0x10));
		piece[3] = _mm_loadu_si128((__m128i*)(buf + 3*0x10));
		piece[4] = _mm_loadu_si128((__m128i*)(buf + 4*0x10));

		/* aesenc all into piece[0] */
		piece[0] = _mm_aesenc_si128(piece[0], piece[1]);
		piece[0] = _mm_aesenc_si128(piece[0], piece[2]);
		piece[0] = _mm_aesenc_si128(piece[0], piece[3]);
		piece[0] = _mm_aesenc_si128(piece[0], piece[4]);

		/* Finalize  by mixing with itself */
		piece[0] = _mm_aesenc_si128(piece[0], piece[0]);

		/* aesenc the piece into the hash */
		hash = _mm_aesenc_si128(hash, piece[0]);

		buf += 0x50;
		len -= 0x50;
	}

	hash = _mm_aesenc_si128(hash, hash);
	hash = _mm_aesenc_si128(hash, hash);
	hash = _mm_aesenc_si128(hash, hash);
	hash = _mm_aesenc_si128(hash, hash);

	return hash;
}

void
print_m128(_In_ __m128i val)
{
	uint64_t n[2];

	_mm_storeu_si128((__m128i*)n, val);

	printf("%.16"PRIx64"_%.16"PRIx64"\n", n[1], n[0]);

	return;
}

#define FALKTP_TEST_SIZE (32 * 1024)

#if 0
int
main(void)
{
	uint8_t  *data;
	uint64_t  it, i;

	volatile __m128i hash;

	data = malloc(FALKTP_TEST_SIZE);
	if(!data){
		perror("malloc() error ");
		return -1;
	}

	memset(data, 0x41, FALKTP_TEST_SIZE);

	it = __rdtsc();
	for(i = 0; i < 1000000; i++){
		hash = falkhash(data, FALKTP_TEST_SIZE, 0x1337133713371337ULL);
	}
	printf("%10.6f cycles/byte\n",
			(double)(__rdtsc() - it) / (i * FALKTP_TEST_SIZE));

	print_m128(hash);

	free(data);
	return 0;
}
#endif

uint64_t falkhash_test(uint8_t *data, uint64_t len, uint32_t seed, void *out)
{
    uint64_t hash[2];
    *(__m128i *)out = falkhash_v1(data, len, seed);
    return 0;
}
