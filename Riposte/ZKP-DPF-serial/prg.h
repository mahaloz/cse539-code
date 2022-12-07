/* Copyright (C) 2019  Anonymous
 *
 * This is a pre-release version of the DPF++ library distributed anonymously
 * for peer review. A public release of the software will be published under the
 * LPGL v2.1 license in the near future. Please do not redistribute this version
 * of the software.
 */

#ifndef DPFPP_PRG_H__
#define DPFPP_PRG_H__

#include <cstring>

#include "aes.h"
#include "lowmc.h"
#include "lowmc.cpp"

namespace dpf
{

template<typename node_t, typename prgkey_t>
inline void PRG(const prgkey_t & prgkey, const node_t seed, void * outbuf, const uint32_t len, const uint32_t from = 0);
template<typename node_t, typename prgkey_t>
inline void PRG2(const prgkey_t & prgkey, const node_t seed, void * outbuf, const uint32_t len, const uint32_t from = 0);
template<>
inline void PRG(const AES_KEY & prgkey, const __m128i seed, void * outbuf, const uint32_t len, const uint32_t from)
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
} // PRG

template<>
inline void PRG2(const LowMC<__m256i> & prgkey, const __m256i seed, void * outbuf, const uint32_t len, const uint32_t from)
{
 
	__m256i * outbuf256 = reinterpret_cast<__m256i *>(outbuf);

	for (size_t i = 0; i < len; ++i)
	{
		auto tmp = _mm256_xor_si256(seed, _mm256_set_epi64x(0, 0, 0, from+i));
		std::cout << "tmp: " << i << " : (PRG): " << tmp[0] << " " << tmp[1] << " " << tmp[2] << " " << tmp[3] << std::endl;
		outbuf256[i] = prgkey.encrypt(tmp);
		outbuf256[i] = _mm256_xor_si256(outbuf256[i], tmp);
	}

} // PRG
template<>
inline void PRG(const LowMC<__m256i> & prgkey, const __m256i seed, void * outbuf, const uint32_t len, const uint32_t from)
{
 
	__m256i * outbuf256 = reinterpret_cast<__m256i *>(outbuf);
 
	for (size_t i = 0; i < len; ++i)
	{
		auto tmp = _mm256_xor_si256(seed, _mm256_set_epi64x(0, 0, 0, from+i));
		 
		outbuf256[i] = prgkey.encrypt(tmp);
		outbuf256[i] = _mm256_xor_si256(outbuf256[i], tmp);
	}

} // PRG
template<>
inline void PRG(const LowMC<__m128i> & prgkey, const __m128i seed, void * outbuf, const uint32_t len, const uint32_t from)
{
	__m128i * outbuf128 = reinterpret_cast<__m128i *>(outbuf);
	for (size_t i = 0; i < len; ++i)
	{
		auto tmp = _mm_xor_si128(seed, _mm_set_epi64x(0, from+i));
		outbuf128[i] = prgkey.encrypt(tmp);
		outbuf128[i] = _mm_xor_si128(outbuf128[i], tmp);
	}
} // PRG

} // namespace dpf

#endif
