/* Copyright (C) 2019  Anonymous
 *
 * This is a pre-release version of the DPF++ library distributed anonymously
 * for peer review. A public release of the software will be published under the
 * LPGL v2.1 license in the near future. Please do not redistribute this version
 * of the software.
 */

#ifndef DPFPP_PRG_AES_IMPL_H__
#define DPFPP_PRG_AES_IMPL_H__

#include "prg.h"
#include "aes.h"

namespace dpf
{

template<>
inline void PRG(const AES_KEY & prgkey, const __m128i & seed, void * outbuf, const uint32_t len, const uint32_t from)
{
	__m128i * outbuf128 = reinterpret_cast<__m128i *>(outbuf);
	for (size_t i = 0; i < len; ++i)
	{
		outbuf128[i] = _mm_xor_si128(seed, _mm_set_epi64x(0, from+i));
	}
	AES_ecb_encrypt_blks(outbuf128, static_cast<unsigned int>(len), &prgkey);
	for (size_t i = 0; i < len; ++i) 
	{
		outbuf128[i] = _mm_xor_si128(outbuf128[i], _mm_set_epi64x(0, from+i));
		outbuf128[i] = _mm_xor_si128(outbuf128[i], seed);
	}
} // PRG<AES_KEY>

inline void PRG_aes(const AES_KEY & prgkey, const __m128i & seed, void * outbuf, const uint32_t len, const uint32_t from = 0)
{
	__m128i * outbuf128 = reinterpret_cast<__m128i *>(outbuf);
	for (size_t i = 0; i < len; ++i)
	{
		outbuf128[i] = _mm_xor_si128(seed, _mm_set_epi64x(0, from+i));
	}
	AES_ecb_encrypt_blks(outbuf128, static_cast<unsigned int>(len), &prgkey);
	for (size_t i = 0; i < len; ++i) 
	{
		outbuf128[i] = _mm_xor_si128(outbuf128[i], _mm_set_epi64x(0, from+i));
		outbuf128[i] = _mm_xor_si128(outbuf128[i], seed);
	}
} // PRG<AES_KEY>


inline void PRG_aes(const AES_KEY & prgkey, const __m256i & seed, void * outbuf, const uint32_t len, const uint32_t from = 0)
{
	 __m256i * outbuf256 = reinterpret_cast<__m256i *>(outbuf);
	 for (size_t i = 0; i < len; ++i)
	 {
	 	outbuf256[i] = _mm256_xor_si256(seed, _mm256_set_epi64x(0, 0, 0, from+i));
	 }
	
	 AES_ecb_encrypt_blks(reinterpret_cast<__m128i *>(outbuf256), static_cast<unsigned int>(len), &prgkey);
	
	 for (size_t i = 0; i < len; ++i) 
	 {
		outbuf256[i] = _mm256_xor_si256(outbuf256[i], _mm256_set_epi64x(0, 0, 0, from+i));
		outbuf256[i] = _mm256_xor_si256(outbuf256[i], seed);
	 }
} // PRG<AES_KEY>

inline std::ostream & operator<<(std::ostream & os, const AES_KEY & prgkey)
{
	return os.write(reinterpret_cast<const char *>(&prgkey.rd_key[0]), sizeof(__m128i));
} // operator<<

} // namespace dpf

#endif // DPFPP_PRG_AES_IMPL_H