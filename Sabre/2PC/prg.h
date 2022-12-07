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
//#include "block.h"
// #include "lowmc.h"
#include "lowmc.h"

namespace dpf
{

template<typename node_t, typename prgkey_t>
inline void PRG(const prgkey_t & prgkey, const node_t seed, void * outbuf, const uint32_t len, const uint32_t from = 0);

template<typename prgkey_t>
inline void PRG_parallel(const prgkey_t & prgkey, std::array<__m128i, blocklen>& seed, void * outbuf, const uint32_t len,  const uint32_t from = 0);
template<typename prgkey_t>
inline void PRG_parallel(const prgkey_t & prgkey, std::array<uint64_t, blocklen>& seed, void * outbuf, const uint32_t len,  const uint32_t from = 0);

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
		block<__m256i> tmp2 = _mm256_set_epi64x(0, 0, 0, from+i);
 
		auto tmp = _mm256_xor_si256(seed, tmp2.mX);
		 
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

template<typename prgkey_t>
inline void PRG_parallel(const prgkey_t & prgkey, std::array<__m128i, blocklen>& seed, void * outbuf, const uint32_t len,  const uint32_t from)
{
	std::array<__m128i, blocklen> * outbuf128 = reinterpret_cast<std::array<__m128i, blocklen> *>(outbuf);
	std::array<__m128i, blocklen> tmp = seed;
 
    outbuf128[0] =  prgkey.encrypt_(tmp);
   	for(size_t j = 0; j < blocklen; ++j) outbuf128[0][j] ^= tmp[j];

   	const auto ones = _mm_set1_epi64x(-1);

	for (size_t i = 1; i < len; ++i)
	{
		uint64_t bitset = i ^ (i-1);
        while (bitset != 0)
        {
            uint64_t t = bitset & -bitset;
            int j = __builtin_ctzl(bitset);                
            tmp[j] ^= ones;
            bitset ^= t;
        }
        outbuf128[i] =  prgkey.encrypt_(tmp);
 
  	  for(size_t j = 0; j < blocklen; ++j) outbuf128[i][j] ^= tmp[j];
	}

} // PRG_parallel


//  template<typename randomness_prgkey_t>
// inline void PRG_parallel(const randomness_prgkey_t & prgkey, std::array<__m128i, blocklen>& seed, void * outbuf, const uint32_t len,  const uint32_t from)
// {
// 	std::array<__m128i, blocklen> * outbuf128 = reinterpret_cast<std::array<__m128i, blocklen> *>(outbuf);
// 	std::array<__m128i, blocklen> tmp = seed;
 
//     outbuf128[0] =  prgkey.encrypt_(tmp);
//    	for(size_t j = 0; j < blocklen; ++j) outbuf128[0][j] ^= tmp[j];

//    	const auto ones = _mm_set1_epi64x(-1);

// 	for (size_t i = 1; i < len; ++i)
// 	{
// 		uint64_t bitset = i ^ (i-1);
//         while (bitset != 0)
//         {
//             uint64_t t = bitset & -bitset;
//             int j = __builtin_ctzl(bitset);                
//             tmp[j] ^= ones;
//             bitset ^= t;
//         }
//         outbuf128[i] =  prgkey.encrypt_(tmp);
 
//   	  for(size_t j = 0; j < blocklen; ++j) outbuf128[i][j] ^= tmp[j];
// 	}

// } // PRG_parallel
// inline void PRG_array_aes(const AES_KEY & prgkey, std::array<__m128i, blocklen>& seed, void * outbuf, const uint32_t len, const uint32_t from)
// {	

// 	std::array<uint64_t, len_> * outbuf128 = (std::array<uint64_t, len_> *) malloc(blocklen * sizeof(std::array<uint64_t, len_>));
	
// 	std::array<uint64_t, blocklen> * outbuf128_T = reinterpret_cast<std::array<uint64_t, blocklen> *>(outbuf);

//     for (size_t i = 0; i < blocklen; ++i) 
// 	{		
//       PRG(prgkey, seed[i], &outbuf128[i], len_, 0); 
// 	}

// 	for(size_t i = 0; i < len_; ++i)
// 	{
// 		for(size_t j = 0; j < blocklen; ++j)
// 		{
// 			for(size_t k = 0; k < 64; ++k)
// 			{
// 				bool set = true;
				
// 				if(((outbuf128[j][i] & (1ULL << k)) >> k) == 1)
// 				{ 
// 				 set = true;
// 				}
// 				else 
// 				{
// 				 set = false;
// 				}

// 			  	if(set)  outbuf128_T[i][j] |=  (1ULL << k);
// 			  	if(!set) outbuf128_T[i][j] |= ~(1ULL << k);
// 			}

// 		}
// 	}

// } // PRG_array_aes


template<typename prgkey_t>
inline void PRG_parallel(const prgkey_t & prgkey, std::array<uint64_t, blocklen>& seed, void * outbuf, const uint32_t len,  const uint32_t from)
{
	std::array<uint64_t, blocklen> * outbuf128 = reinterpret_cast<std::array<uint64_t, blocklen> *>(outbuf);
	std::array<uint64_t, blocklen> tmp = seed;
 
    outbuf128[0] =  prgkey.encrypt_(tmp);
   	for(size_t j = 0; j < blocklen; ++j) outbuf128[0][j] ^= tmp[j];

   	const uint64_t ones = -1;//_mm_set1_epi64x(-1);

	for (size_t i = 1; i < len; ++i)
	{
		uint64_t bitset = i ^ (i-1);
        while (bitset != 0)
        {
            uint64_t t = bitset & -bitset;
            int j = __builtin_ctzl(bitset);                
            tmp[j] ^= ones;
            bitset ^= t;
        }
        outbuf128[i] =  prgkey.encrypt_(tmp);
 
  	  for(size_t j = 0; j < blocklen; ++j) outbuf128[i][j] ^= tmp[j];
	}

} // PRG_parallel
} // namespace dpf

#endif
