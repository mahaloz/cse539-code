/** Sabre, an anonymous bulletin board with speedier ripostes
 *  Copyright (C) 2020  Sabre authors
 *
 *  @file    block.h
 *  @brief   Implements the block<> datatype, prividing a uniform interface for
 *           various sized vector and non-vector integers.
 *
 *  @author  Ryan Henry        <ryan.henry@ucalgary.ca>
 *  @author  Adithya Vadapalli <avadapal@iu.edu>
 *  @author  Kyle Storrier     <kyle.storrier@ucalgary.ca>
 *
 *  @license GNU Public License (version 2); see LICENSE for full license text
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation; either version 2 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License along
 *    with this program; if not, write to the Free Software Foundation, Inc.,
 *    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 **/

#ifndef LOWMC_BLOCK_H__
#define LOWMC_BLOCK_H__

#include <bitset>       // std::bitset
#include <string>       // std::string
#include <iostream>     // std::istream and std::ostream

#include <x86intrin.h>  // SSE and AVX intrinsics

// namespace lowmc
// {

template <typename __mX>
union block
{
  public:
	typedef __mX value_type;

	block(const uint64_t input = 0ULL) : bits(input) { }
	block(const __mX & val) : mX(val) { }
	block(const std::string bit_string) : bits(bit_string) { }
	inline operator __mX() const { return mX; }
	inline block<__mX> & operator=(const __mX & val) { mX = val; return *this; }
	inline bool operator==(const __mX & rhs) const;
	inline bool operator!=(const __mX & rhs) const { return !(*this == rhs); }
	inline typename std::bitset<sizeof(__mX) * 8>::reference operator[](const size_t pos) { return bits[pos]; }
	inline const bool operator[](const size_t pos) const { return bits[pos]; }
	constexpr inline size_t size() const { return sizeof(__mX) * 8; }
	inline const unsigned parity() const { return bits.count() % 2; }
	inline void shiftr(const size_t pos) { bits >>= pos; }
 	inline void shiftl(const size_t pos) { bits <<= pos; }
	std::bitset<8 * sizeof(__mX)> bits;
  //private:
	block(std::bitset<8 * sizeof(__mX)> & bitset) : bits(bitset) { }
	__mX mX;
	
};

template<>
inline bool block<__m128i>::operator==(const __m128i & rhs) const
{
	auto vcmp = _mm_xor_si128(*this, rhs);
	return _mm_testz_si128(vcmp, vcmp);
}
template<>
inline bool block<__m256i>::operator==(const __m256i & rhs) const
{
	auto vcmp = _mm256_xor_si256(*this, rhs);
	return _mm256_testz_si256(vcmp, vcmp);
}
 
template<typename __mX>
inline block<__mX> operator|(const block<__mX> & block1, const block<__mX> & block2);
 
template<>
inline block<__m256i> operator|(const block<__m256i> & block1, const block<__m256i> & block2)
{
	return _mm256_or_si256(block1, block2);
}
template<>
inline block<__m128i> operator|(const block<__m128i> & block1, const block<__m128i> & block2)
{
	return _mm_or_si128(block1, block2);
}

template<typename __mX>
inline block<__mX> operator&(const block<__mX> & block1, const block<__mX> & block2);
 
template<>
inline block<__m256i> operator&(const block<__m256i> & block1, const block<__m256i> & block2)
{
	return _mm256_and_si256(block1, block2);
}
template<>
inline block<__m128i> operator&(const block<__m128i> & block1, const block<__m128i> & block2)
{
	return _mm_and_si128(block1, block2);
}

template<typename __mX>
inline block<__mX> operator^(const block<__mX> & block1, const block<__mX> & block2);
 
template<>
inline block<__m256i> operator^(const block<__m256i> & block1, const block<__m256i> & block2)
{
	return _mm256_xor_si256(block1, block2);
}

template<>
inline block<__m128i> operator^(const block<__m128i> & block1, const block<__m128i> & block2)
{
	return _mm_xor_si128(block1, block2);
}

template<typename __mX>
inline block<__mX> & operator^=(block<__mX> & block1, const block<__mX> & block2);
 
template<>
inline block<__m256i> & operator^=(block<__m256i> & block1, const block<__m256i> & block2)
{
	block1 = _mm256_xor_si256(block1, block2);
	return block1;
}
template<>
inline block<__m128i> & operator^=(block<__m128i> & block1, const block<__m128i> & block2)
{
	block1 = _mm_xor_si128(block1, block2);
	return block1;
}


template<typename __mX>
inline block<__mX> operator~(const block<__mX> & block);
 
template<>
inline block<__m256i> operator~(const block<__m256i> & block)
{
	return ~static_cast<__m256i>(block);
}
template<>
inline block<__m128i> operator~(const block<__m128i> & block)
{
	return ~static_cast<__m128i>(block);
}

template<typename __mX>
inline block<__mX> operator<<(const block<__mX> & block, const long & shift);
template<>
inline block<__m256i> operator<<(const block<__m256i> & block , const long & shift)
{
	return _mm256_or_si256(_mm256_slli_epi64(block, shift), _mm256_blend_epi32(_mm256_setzero_si256(), _mm256_permute4x64_epi64(_mm256_srli_epi64(block, 64 - shift), _MM_SHUFFLE(2,1,0,0)), _MM_SHUFFLE(3,3,3,0)));
}
template<>
inline block<__m128i> operator<<(const block<__m128i> & block, const long & shift)
{
  return _mm_or_si128(_mm_slli_epi64(block, shift), _mm_srli_epi64(_mm_slli_si128(block, 8), 64 - shift));
}
template<typename __mX>
inline block<__mX> & operator<<=(block<__mX> & block, const long & shift)
{
	block = block << shift;
	return block;
}

template<typename __mX>
inline block<__mX> operator>>(const block<__mX> & block, const long & shift);
template<>
inline block<__m256i> operator>>(const block<__m256i> & block, const long & shift)
{
	return _mm256_or_si256(_mm256_srli_epi64(block, shift), _mm256_blend_epi32(_mm256_setzero_si256(), _mm256_permute4x64_epi64(_mm256_slli_epi64(block, 64 - shift), _MM_SHUFFLE(0,3,2,1)), _MM_SHUFFLE(0,3,3,3)));
}
template<>
inline block<__m128i> operator>>(const block<__m128i> & block, const long & shift)
{
	return _mm_or_si128(_mm_srli_epi64(block, shift), _mm_slli_epi64(_mm_srli_si128(block, 8), 64 - shift));
}
template<typename __mX>
inline block<__mX> & operator>>=(block<__mX> & block, const long & shift)
{
	block = block >> shift;
	return block;
}

//} // namespace lowmc

#endif // LOWMC_BLOCK_H__
