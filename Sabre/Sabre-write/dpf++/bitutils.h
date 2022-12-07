/* Copyright (C) 2019  Anonymous
 *
 * This is a pre-release version of the DPF++ library distributed anonymously
 * for peer review. A public release of the software will be published under the
 * LPGL v2.1 license in the near future. Please do not redistribute this version
 * of the software.
 */

#ifndef DPF_BITUTILS_H__
#define DPF_BITUTILS_H__

#include <bitset>       // std::bitset

#include <x86intrin.h>  // SSE and AVX intrinsics

namespace dpf
{

static const __m128i bool128_mask[2] = {
	_mm_set_epi64x(0,1),                                        // 0b00...0001
	_mm_set_epi64x(1,0)                                         // 0b00...0001 << 64
};
static const __m256i bool256_mask[4] = {
	_mm256_set_epi64x(0,0,0,1),                                 // 0b00...0001
	_mm256_set_epi64x(0,0,1,0),                                 // 0b00...0001 << 64
	_mm256_set_epi64x(0,1,0,0),                                 // 0b00...0001 << 128
	_mm256_set_epi64x(1,0,0,0)                                  // 0b00...0001 << 192
};

static const __m128i lsb128_mask[4] = {
	_mm_setzero_si128(),                                        // 0b00...0000
	_mm_set_epi64x(0,1),                                        // 0b00...0001
	_mm_set_epi64x(0,2),                                        // 0b00...0010
	_mm_set_epi64x(0,3)                                         // 0b00...0011
};
static const __m128i lsb128_mask_inv[4] = {
	_mm_set1_epi8(-1),                                          // 0b11...1111
	_mm_set_epi64x(-1,-2),                                      // 0b11...1110
	_mm_set_epi64x(-1,-3),                                      // 0b11...1101
	_mm_set_epi64x(-1,-4)                                       // 0b11...1100
};
static const __m128i if128_mask[2] = {
	_mm_setzero_si128(),                                        // 0b00...0000
	_mm_set1_epi8(-1)                                           // 0b11...1111
};

static const __m256i lsb256_mask[4] = {
	_mm256_setzero_si256(),                                     // 0b00...0000
	_mm256_set_epi64x(0,0,0,1),                                 // 0b00...0001
	_mm256_set_epi64x(0,0,0,2),                                 // 0b00...0010
	_mm256_set_epi64x(0,0,0,3)                                  // 0b00...0011
};
static const __m256i lsb256_mask_inv[4] = {
	_mm256_set1_epi8(-1),                                       // 0b11...1111
	_mm256_set_epi64x(-1,-1,-1,-2),                             // 0b11...1110
	_mm256_set_epi64x(-1,-1,-1,-3),                             // 0b11...1101
	_mm256_set_epi64x(-1,-1,-1,-4)                              // 0b11...1100
};
static const __m256i if256_mask[2] = {
	_mm256_setzero_si256(),                                     // 0b00...0000
	_mm256_set1_epi8(-1)                                        // 0b11...1111
};
inline __m128i xor_if(const __m128i & block1, const __m128i & block2, __m128i flag)
{
 return _mm_xor_si128(block1, _mm_and_si128(block2, flag));
}

 inline __m256i xor_if(const __m256i & block1, const __m256i & block2, __m256i flag)
{
 return _mm256_xor_si256(block1, _mm256_and_si256(block2, flag));
}

inline __m128i xor_if(const __m128i & block1, const __m128i & block2, bool flag)
{
	return _mm_xor_si128(block1, _mm_and_si128(block2, if128_mask[flag ? 1 : 0]));
}
inline __m256i xor_if(const __m256i & block1, const __m256i & block2, bool flag)
{
	return _mm256_xor_si256(block1, _mm256_and_si256(block2, if256_mask[flag ? 1 : 0]));
}

inline uint8_t get_lsb(const __m128i & block, uint8_t bits = 0b01)
{
	__m128i vcmp = _mm_xor_si128(_mm_and_si128(block, lsb128_mask[bits]), lsb128_mask[bits]);
	return static_cast<uint8_t>(_mm_testz_si128(vcmp, vcmp));
}
inline uint8_t get_lsb(const __m256i & block, uint8_t bits = 0b01)
{
	__m256i vcmp = _mm256_xor_si256(_mm256_and_si256(block, lsb256_mask[bits]), lsb256_mask[bits]);
	return static_cast<uint8_t>(_mm256_testz_si256(vcmp, vcmp));
}
template <typename __mX>
inline uint8_t get_lsb01(const __mX & block) { return get_lsb(block, 0b01); }
template <typename __mX>
inline uint8_t get_lsb10(const __mX & block) { return get_lsb(block, 0b10); }


inline __m128i clear_lsb(const __m128i & block, uint8_t bits = 0b01)
{
	return _mm_and_si128(block, lsb128_mask_inv[bits]);
}
inline __m256i clear_lsb(const __m256i & block, uint8_t bits = 0b01)
{
	return _mm256_and_si256(block, lsb256_mask_inv[bits]);
}

// template<typename row_t = __m256i >	
// inline std::array<row_t, 128> bitsliced_clear_lsb(std::array<row_t, 128>& block, uint8_t bits = 0b11)
// {
// 	if(bits == 0b11)
// 	{
// 	 block[0] = _mm_set_epi64x(0, 0); 
// 	 block[1] = _mm_set_epi64x(0, 0); 
// 	}
// 	if(bits == 0b01)
// 	{
// 	  block[0] = _mm_set_epi64x(0, 0); 
// 	}
// 	return block;
// }

template<typename row_t = __m256i, size_t nrows >	
inline row_t bitslicled_get_lsb(std::array<row_t, nrows> block, uint8_t bit = 0b01)
{	
	if(bit == 0b01)	
	{
	 return block[0];
	}
	else if (bit == 0b10)
	{
	 return block[1];
	}
	else
	{
      return block[0];
	}
}

template <typename __mX>
inline __mX clear_lsb01(const __mX & block) { return clear_lsb(block, 0b01); }
template <typename __mX>
inline __mX clear_lsb10(const __mX & block) { return clear_lsb(block, 0b10); }
template <typename __mX>
inline __mX clear_lsb11(const __mX & block) { return clear_lsb(block, 0b11); }


inline void set_ones(__m128i & input)
{
	input = _mm_set1_epi64x(-1);
}

inline void set_ones(__m256i & input)
{
	input = _mm256_set1_epi64x(-1);
}



inline void set_zeros(__m128i & input)
{
	input = _mm_setzero_si128();
}

inline void set_zeros(__m256i & input)
{
	input = _mm256_setzero_si256();
}

// inline void zeros(block<__m128i> & input)
// {
// 	input = _mm_setzero_si128();
// }

// inline void zeros(block<__m256i> & input)
// {
// 	input = _mm256_setzero_si256();
// }


inline __m128i set_lsb(const __m128i & block, const bool val = true)
{
	return _mm_or_si128(clear_lsb(block, 0b01), lsb128_mask[val ? 0b01 : 0b00]);
}
inline __m256i set_lsb(const __m256i & block, const bool val = true)
{
	return _mm256_or_si256(clear_lsb(block, 0b01), lsb256_mask[val ? 0b01 : 0b00]);;
}

inline __m128i set_lsbs(const __m128i & block, const bool bits[2])
{
	int i = (bits[0] ? 1 : 0) + 2 * (bits[1] ? 1 : 0);
	return _mm_or_si128(clear_lsb(block, 0b11), lsb128_mask[i]);
}
inline __m256i set_lsbs(const __m256i & block, const bool bits[2])
{
	int i = (bits[0] ? 1 : 0) + 2 * (bits[1] ? 1 : 0);
	return _mm256_or_si256(clear_lsb(block, 0b11), lsb256_mask[i]);
}

} // namespace lowmc

#endif // DPF_BITUTILS_H__
