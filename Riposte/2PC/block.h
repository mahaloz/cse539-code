/* Copyright (C) 2019  Anonymous
 *
 * This is a pre-release version of the DPF++ library distributed anonymously
 * for peer review. A public release of the software will be published under the
 * LPGL v2.1 license in the near future. Please do not redistribute this version
 * of the software.
 */

#ifndef DPFPP_BLOCK_H__
#define DPFPP_BLOCK_H__

#include <bitset>       // std::bitset
#include <vector>       // std::vector
#include <string>       // std::string
#include <iostream>     // std::istream and std::ostream

#include <x86intrin.h>  // SSE and AVX intrinsics



namespace dpf
{

static const __m128i bool128_mask[2] = {
	_mm_set_epi64x(0,1),                                        // 0b00...0001
	_mm_set_epi64x(1,0)                                         // 0b00...0001 << 64
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

static const __m256i bool256_mask[4] = {
	_mm256_set_epi64x(0,0,0,1),                                 // 0b00...0001
	_mm256_set_epi64x(0,0,1,0),                                 // 0b00...0001 << 64
	_mm256_set_epi64x(0,1,0,0),                                 // 0b00...0001 << 128
	_mm256_set_epi64x(1,0,0,0)                                  // 0b00...0001 << 192
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

template <typename __mX>
union block
{
 public:
  block(const uint64_t input = 0ULL) : bits(input) { }
  block(const __mX & val) : mX(val) { }
  block(const std::string bit_string) : bits(bit_string) { }
  inline operator __mX() const { return mX; }
  inline block<__mX> & operator=(const __mX & val) { mX = val; return *this; }
  inline bool operator==(const __mX & rhs) const;
  inline bool operator!=(const __mX & rhs) const { return !(*this == rhs); }
  inline typename std::bitset<sizeof(__mX) * 8>::reference operator[](const size_t pos) { return bits[pos]; }
  inline const bool operator[] (const size_t pos) const { return bits[pos]; }
  constexpr inline size_t size() const { return sizeof(__mX) * 8; }
  inline const unsigned parity() const { return bits.count() % 2; }
  inline void shiftr(const size_t pos) { bits >>= pos; }
  inline void shiftl(const size_t pos) { bits <<= pos; }
  inline   block<__mX> shiftr_bits(const size_t pos) const{ return bits >> pos; } 
 //private:
  block(std::bitset<8 * sizeof(__mX)> & bitset) : bits(bitset) { }
  __mX mX;
  std::bitset<8 * sizeof(__mX)> bits;
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

inline __m128i xor_if(const __m128i & block1, const __m128i & block2, bool flag)
{
	return _mm_xor_si128(block1, _mm_and_si128(block2, if128_mask[flag ? 1 : 0]));
}
inline __m256i xor_if(const __m256i & block1, const __m256i & block2, bool flag)
{
	return _mm256_xor_si256(block1, _mm256_and_si256(block2, if256_mask[flag ? 1 : 0]));
}

//#define get_lsb01(BLOCK) get_lsb((BLOCK), 0b01)
//#define get_lsb10(BLOCK) get_lsb((BLOCK), 0b10)
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

//#define clear_lsb01(BLOCK) clear_lsb((BLOCK), 0b01)
//#define clear_lsb10(BLOCK) clear_lsb((BLOCK), 0b10)
//#define clear_lsb11(BLOCK) clear_lsb((BLOCK), 0b11)
inline __m128i clear_lsb(const __m128i & block, uint8_t bits = 0b01)
{
	return _mm_and_si128(block, lsb128_mask_inv[bits]);
}

inline __m256i clear_lsb(const __m256i & block, uint8_t bits = 0b01)
{
	return _mm256_and_si256(block, lsb256_mask_inv[bits]);
}

inline std::array<__m128i, blocklen> clear_lsb_parallel(std::array<__m128i, blocklen>& block, uint8_t bits = 0b11)
{
	if(bits == 0b11)
	{
	 block[0] = _mm_set_epi64x(0, 0); 
	 block[1] = _mm_set_epi64x(0, 0); 
	}
	if(bits == 0b01)
	{
	  block[0] = _mm_set_epi64x(0, 0); 
	}
	return block;
}

inline std::array<uint64_t, blocklen> clear_lsb_parallel(std::array<uint64_t, blocklen>& block, uint8_t bits = 0b11)
{
	if(bits == 0b11)
	{
	 block[0] = 0;// _mm_set_epi64x(0, 0); 
	 block[1] = 0;//_mm_set_epi64x(0, 0); 
	}
	if(bits == 0b01)
	{
	  block[0] = 0;//_mm_set_epi64x(0, 0); 
	}
	return block;
}
 

inline std::array<__m128i, blocklen> set_lsb_parallel(std::array<__m128i, blocklen>& block, uint8_t bits = 0b01)
{
	block[0] = _mm_set1_epi64x(-1);

	return block;
}

template<typename T>	
inline T get_lsb_array(std::array<T, blocklen> block)
{
	return block[0];
}

 template<typename T>	
 inline T get_lsb_parallel(std::array<T, blocklen> block, uint8_t bit)
{	
	if(bit == 0b01)	return block[0];
	if(bit == 0b10) return block[1];
}


inline block<__m256i> set_vals(__m256i x, uint64_t val)
{ 
 return _mm256_set_epi64x(0, 0, 0, val);
}
 
inline block<__m128i> set_vals(__m128i x, uint64_t val)
{ 	
 return _mm_set_epi64x(0, val);
}

__m128i set_lsb(const __m128i & block, const bool val = true);
inline __m128i set_lsb(const __m128i & block, const bool val)
{
	return _mm_or_si128(clear_lsb(block, 0b01), lsb128_mask[val ? 0b01 : 0b00]);
}
__m256i set_lsb(const __m256i & block, const bool val = true);
inline __m256i set_lsb(const __m256i & block, const bool val)
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

} // namespace dpf

#endif
