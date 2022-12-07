/* Copyright (C) 2019  Anonymous
 *
 * This is a pre-release version of the DPF++ library distributed anonymously
 * for peer review. A public release of the software will be published under the
 * LPGL v2.1 license in the near future. Please do not redistribute this version
 * of the software.
 */

#ifndef DPFPP_DPF_H__
#define DPFPP_DPF_H__

#include <type_traits>  // std::is_same<>
#include <limits>       // std::numeric_limits<>
#include <climits>      // CHAR_BIT
#include <cmath>        // std::log2, std::ceil, std::floor
#include <stdexcept>    // std::runtime_error
#include <array>        // std::array<>
#include <iostream>     // std::istream and std::ostream
#include <vector>       // std::vector<>
#include <memory>       // std::shared_ptr<>
#include <utility>      // std::move
#include <algorithm>    // std::copy
#include <cstring>      // std::memcpy

#include <bsd/stdlib.h> // arc4random_buf
#include <x86intrin.h>  // SSE and AVX intrinsics

#include "bitutils.h"
#include "../block.h"
#include "prg.h"
 
#include "prg_aes_impl.h"
#ifdef DPFPP_DO_LOWMC
	#include "prg_lowmc_impl.h"
#endif

#include "common.h"

constexpr int L = 0;
constexpr int R = 1;

namespace dpf
{




template <typename node_t>
node_t init_val(uint64_t val);
template <> __m128i init_val(uint64_t val) { return _mm_set_epi64x(0, val); }
template <> __m256i init_val(uint64_t val) { return _mm256_set_epi64x(0, 0, 0, val); }


template<typename leaf_t = __m128i, typename node_t = __m128i, typename prgkey_t = AES_KEY>
struct dpf_key;

template<typename leaf_t = __m128i, typename node_t = __m128i, typename prgkey_t = lowmc::bitsliced_lowmc<128,19,32,256>, size_t ndpfs = 256>
struct bitsliced_dpf_key;
	
using slicerow_t = block<__m128i>;
using sliceblock_t = std::array<slicerow_t, blocklen>; 

using slicerow256_t = block<__m256i>;
using sliceblock256_t = std::array<slicerow_t, blocklen>; 

template<typename leaf_t, typename node_t, typename prgkey_t>
inline leaf_t eval(const dpf_key <leaf_t, node_t, prgkey_t> & dpfkey, const size_t input);

template<typename leaf_t, typename node_t, typename prgkey_t>
inline void evalinterval(const dpf_key<leaf_t, node_t, prgkey_t> & dpfkey, const size_t from, const size_t to, leaf_t * output, uint8_t * t = NULL);

template<typename leaf_t, typename node_t, typename prgkey_t>
inline void evalfull(const dpf_key<leaf_t, node_t, prgkey_t> & dpfkey, leaf_t * output, uint8_t * t = NULL);

template<typename leaf_t, typename node_t, typename prgkey_t>
inline leaf_t __reeval(const dpf_key<leaf_t, node_t, prgkey_t> & dpfkey, const size_t input,
	node_t * S, std::array<node_t, dpf_key<leaf_t, node_t, prgkey_t>::nodes_per_leaf> & final, uint8_t * T, const size_t from_bit);

template<class iterator, typename leaf_t, typename node_t, typename prgkey_t>
inline std::vector<leaf_t> evallist(const dpf_key<leaf_t, node_t, prgkey_t> & dpfkey, iterator begin, iterator end, size_t size_hint = 0);

template<typename node_t, typename prgkey_t>
static inline void expand(const prgkey_t & prgkey, const node_t & seed, node_t s[2], uint8_t t[2], int lsbmask = 0b00)
{
	dpf::PRG(prgkey, clear_lsb(seed, 0b11), s, 2);
	t[L] = get_lsb(s[L]);
	s[L] = clear_lsb(s[L], lsbmask);
	t[R] = get_lsb(s[R]);
	s[R] = clear_lsb(s[R], lsbmask);
} // dpf::expand

template<typename node_t, typename prgkey_t>
static inline void traverse2(const prgkey_t & prgkey, const node_t & seed,
	const uint8_t cw_t[2], const node_t & cw, const uint8_t prev_t,
	node_t s[2], uint8_t t[2], int lsbmask = 0b11)
{
	dpf::PRG(prgkey, clear_lsb(seed, 0b11), s, 2);
	t[L] = get_lsb(s[L]) ^ (cw_t[L] & prev_t);;
	s[L] = clear_lsb(xor_if(s[L], cw, !prev_t), lsbmask);
	t[R] = get_lsb(s[R]) ^ (cw_t[R] & prev_t);;
	s[R] = clear_lsb(xor_if(s[R], cw, !prev_t), lsbmask);
} // dpf::expand

template<typename node_t, typename prgkey_t>
static inline void traverse(const prgkey_t & prgkey, const node_t & seed, const bool direction,
	const uint8_t cw_t, const node_t & cw, const uint8_t prev_t,
	node_t & s, uint8_t & t, int lsbmask = 0b00)
{
	dpf::PRG(prgkey, clear_lsb(seed, 0b11), &s, 1, direction);
	t = get_lsb(s) ^ (cw_t & prev_t);
	s = clear_lsb(xor_if(s, cw, !prev_t), lsbmask);
} // dpf::traverse

 


template<typename finalizer_t, typename prgkey_t>
static inline void stretch_leaf(const prgkey_t & prgkey, const typename finalizer_t::value_type & seed, finalizer_t & s)
{

	dpf::PRG(prgkey, clear_lsb(seed, 0b11), &s, s.size());
} // dpf::stretch_leaf





template<typename leaf_t, typename node_t, typename prgkey_t, size_t ndpfs>
class bitsliced_dpf_key
{
  public:


	static constexpr size_t bits_per_leaf = std::is_same<leaf_t, bool>::value ? 1 : sizeof(leaf_t) * CHAR_BIT;
	static constexpr bool is_packed = (sizeof(leaf_t) < sizeof(node_t));
	static constexpr size_t leaves_per_node = bitsliced_dpf_key::is_packed ? sizeof(node_t) * CHAR_BIT / bits_per_leaf : 1;
	static constexpr size_t nodes_per_leaf = bitsliced_dpf_key::is_packed ? 1 : std::ceil(static_cast<double>(bits_per_leaf) / (sizeof(node_t) * CHAR_BIT));
	using finalizer_t = std::array<std::array<node_t, nodes_per_leaf>, ndpfs>;
                         
	inline static constexpr size_t depth(const size_t nitems) { return std::ceil(std::log2(std::ceil(static_cast<double>(nitems) / bitsliced_dpf_key::leaves_per_node))); }
    inline constexpr size_t depth() const { return bitsliced_dpf_key::depth(nitems); }

	inline static constexpr size_t input_bits(const size_t nitems) { return std::ceil(std::log2(nitems)); }
	inline constexpr size_t input_bits() const { return bitsliced_dpf_key::input_bits(nitems); }

	inline static constexpr size_t nodes_in_interval(const size_t from, const size_t to) { return (to < from) ? 0 : std::max(1.0, std::ceil(static_cast<double>(to+1) / leaves_per_node) - std::floor(static_cast<double>(from) / leaves_per_node)); }

	// inline static constexpr size_t interval_bytes(const size_t from, const size_t to) { return nodes_in_interval(from, to) * (is_packed ? sizeof(node_t) : sizeof(leaf_t)); }
	// inline constexpr size_t full_bytes() { return interval_bytes(0, nitems-1); }

	 inline static constexpr size_t nodes_at_leaf_layer(const size_t nitems) { return std::ceil(static_cast<double>(nitems) / bitsliced_dpf_key::leaves_per_node); }
	 inline constexpr size_t nodes_at_leaf_layer() const { return bitsliced_dpf_key::nodes_at_leaf_layer(nitems); }

   size_t nitems;
	 
   std::array<node_t, ndpfs> root;
	 
   std::vector<std::array<node_t, ndpfs>> cw;
	 finalizer_t  finalizer;
};



 inline void set_ones(block<__m128i> & input)
{
 input = _mm_set1_epi64x(-1);
}

inline void set_ones(block<__m256i> & input)
{
 input = _mm256_set1_epi64x(-1);
}
 

template<typename row_t = __m256i, typename lowmc>
inline void PRG_bit_sliced(const lowmc & prgkey, const std::array<block<row_t> , blocklen>& seed, void * outbuf, const uint32_t len)
{
	std::array<block<row_t> , blocklen> * outbuf128 = reinterpret_cast<std::array<block<row_t> , blocklen> *>(outbuf);
	std::array<block<row_t> , blocklen> tmp = seed;
    outbuf128[0] = prgkey.encrypt(seed);

   	for(size_t j = 0; j < blocklen; ++j) outbuf128[0][j] ^= tmp[j];

   	const block<row_t> ones = _mm256_set1_epi64x(-1);

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
 
        outbuf128[i] =  prgkey.encrypt(tmp);
 
  	    for(size_t j = 0; j < blocklen; ++j) outbuf128[i][j] ^= tmp[j];
	}

} // PRG_bit_sliced


 
template<size_t rows>
inline std::array<block<__m128i>, rows> bitsliced_clear_lsb(std::array<block<__m128i>, rows>& block, uint8_t bits = 0b11)
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

template<size_t rows>
inline std::array<block<__m256i>, rows> bitsliced_clear_lsb(std::array<block<__m256i>, rows>& block, uint8_t bits = 0b11)
{
	if(bits == 0b11)
	{
	 block[0] = _mm256_setzero_si256(); 
	 block[1] = _mm256_setzero_si256(); 
	}
	if(bits == 0b01)
	{
	  block[0] = _mm256_setzero_si256(); 
	}
	return block;
}

 

template<typename prgkey_t, typename row_t = __m256i>
static inline void bitsliced_traverse2(
										 prgkey_t& prgkey, const std::array<block<row_t>, blocklen> & cw,  const block<row_t> cw_t[2], 
										 std::array<block<row_t> , blocklen>& seed, std::array<block<row_t> , blocklen> s[2], block<row_t> t[2], 
										 block<row_t> prev_t, int lsbmask = 0b11
										)
{	 
	 PRG_bit_sliced(prgkey, bitsliced_clear_lsb(seed, 0b11), s,2);	 
 
	 t[L] = bitslicled_get_lsb(s[L]) ^ (cw_t[L] & prev_t);

	 for(size_t j = 0; j < blocklen; ++j)
	 {
	   s[L][j] =  xor_if(s[L][j].mX, cw[j].mX, (prev_t.mX ^  _mm256_set1_epi64x(-1)));  
	 }	

	 s[L] = bitsliced_clear_lsb(s[L], lsbmask);

	 t[R] = bitslicled_get_lsb(s[R]) ^ (cw_t[R] & prev_t);
	 
	 for(size_t j = 0; j < blocklen; ++j)
	 {
	   s[R][j] =  xor_if(s[R][j].mX, cw[j].mX, (prev_t.mX ^  _mm256_set1_epi64x(-1)));  
	 }

	 s[R] = bitsliced_clear_lsb(s[R], lsbmask); 
 
} //expand


std::array<block<__m256i> , 128>  ___transpose(const std::array<__m128i, 256>& input)
{
  
      std::array<block<__m256i> , 128>   inputT;
  
	  for(size_t i = 0; i < 128; ++i)
	  {
	    for(size_t j = 0; j < 256; ++j)
	    {
	      inputT[i].bits[j] = (block<__m128i>(input[j])).bits[i]; 
	    }
	  }
	 
	 return inputT;
}

std::array<block<__m256i> , 256>  ___transpose(const std::array<__m256i, 256> input)
{
  
      std::array<block<__m256i> , 256>   inputT;
  
	  for(size_t i = 0; i < 256; ++i)
	  {
	    for(size_t j = 0; j < 256; ++j)
	    {
	      inputT[i].bits[j] = (block<__m256i>(input[j])).bits[i]; 
	    }
	  }
	 
	 return inputT;
}

std::array<block<__m128i> , 256>  _transpose(const std::array<block<__m256i>, 128>& input)
{
  
std::array<block<__m128i> , 256>   inputT;
  
  for(size_t i = 0; i < 256; ++i)
  {
    for(size_t j = 0; j < 128; ++j)
    {
      inputT[i].bits[j] = (block<__m256i>(input[j])).bits[i]; 
    }
  }
 
  return inputT;
}

static inline void trans(uint8_t const * inp, uint8_t * out, size_t nrows, size_t ncols)
{
    #define INP(x,y) inp[(x)*ncols/8 + (y)/8]
    #define OUT(x,y) out[(y)*nrows/8 + (x)/8]

    for (size_t row = 0; row < nrows; row += sizeof(__m256i))
    {
      for (size_t col = 0; col < ncols; col += 8)
      {
        __m256i x = _mm256_setr_epi8(INP(row + 0, col), INP(row + 1, col), INP(row + 2, col), INP(row + 3, col),
        INP(row + 4, col), INP(row + 5, col), INP(row + 6, col), INP(row + 7, col),
        INP(row + 8, col), INP(row + 9, col), INP(row + 10, col), INP(row + 11, col),
        INP(row + 12, col), INP(row + 13, col), INP(row + 14, col), INP(row + 15, col),
        INP(row + 16, col), INP(row + 17, col), INP(row + 18, col), INP(row + 19, col),
        INP(row + 20, col), INP(row + 21, col), INP(row + 22, col), INP(row + 23, col),
        INP(row + 24, col), INP(row + 25, col), INP(row + 26, col), INP(row + 27, col),
        INP(row + 28, col), INP(row + 29, col), INP(row + 30, col), INP(row + 31, col));

        *(uint32_t*)&OUT(row, col+7)= _mm256_movemask_epi8(_mm256_slli_epi64(x, 0));
        *(uint32_t*)&OUT(row, col+6)= _mm256_movemask_epi8(_mm256_slli_epi64(x, 1));
        *(uint32_t*)&OUT(row, col+5)= _mm256_movemask_epi8(_mm256_slli_epi64(x, 2));
        *(uint32_t*)&OUT(row, col+4)= _mm256_movemask_epi8(_mm256_slli_epi64(x, 3));
        *(uint32_t*)&OUT(row, col+3)= _mm256_movemask_epi8(_mm256_slli_epi64(x, 4));
        *(uint32_t*)&OUT(row, col+2)= _mm256_movemask_epi8(_mm256_slli_epi64(x, 5));
        *(uint32_t*)&OUT(row, col+1)= _mm256_movemask_epi8(_mm256_slli_epi64(x, 6));
        *(uint32_t*)&OUT(row, col+0)= _mm256_movemask_epi8(_mm256_slli_epi64(x, 7));
      }
    }
}
 
template<typename finalizer_t, typename prgkey_t, typename row_t = __m256i>
static inline void stretch_leaf_bitsliced(const prgkey_t & prgkey, std::array<block<row_t> , blocklen> seed, finalizer_t & s)
{
	std::array<block<row_t> , blocklen> seed_ = bitsliced_clear_lsb(seed, 0b11);	
	PRG_bit_sliced(prgkey, seed_,  s, 2);
} // dpf::stretch_leaf_bitsliced

std::array<block<__m128i> , nitems>  _transpose(const block<__m256i> * input)
{
  
std::array<block<__m128i> , nitems>   inputT;
  
  for(size_t i = 0; i < nitems; ++i)
  {
    for(size_t j = 0; j < 128; ++j)
    {
      inputT[i].bits[j] = (block<__m256i>(input[j])).bits[i]; 
    }
  }
 
  return inputT;
}
 

template<typename leaf_t, typename node_t, typename prgkey_t, typename row_t = __m256i>
static inline auto stretch_leaf_AES(const AES_KEY& aeskey,  bitsliced_dpf_key<leaf_t, node_t, prgkey_t> & dpfkey, std::array<node_t, ndpfs> seed,
									 leaf_t & out, size_t i, block<row_t> * t)
{
    constexpr size_t len = bitsliced_dpf_key<leaf_t, node_t, prgkey_t>::nodes_per_leaf;
   
	std::array<node_t, bitsliced_dpf_key<leaf_t, node_t, prgkey_t>::nodes_per_leaf> temp;

    for(size_t j = 0; j < ndpfs; ++j)
    {
      dpf::PRG_aes(aeskey, seed[j], &temp, len);
      for(size_t k = 0; k < len; ++k)
      {
          out[k] ^= temp[k];
      } 
    }
} // dpf::stretch_leaf

 
 void print_m128_(__m128i inp)
{

  block<__m128i> out__  = inp;	  
  printf("----> \n");
  
  for(size_t i = 0; i < 128; ++i)
  {
  	bool x = out__.bits[i];
  	printf("%d",x);
  }	

  printf("\n\n");  
 
}

inline auto get_bytes_from_bits(const __m256i & t, int which)
{
    static const unsigned char mask1a[32] = {
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01,
        0x02, 0x02, 0x02, 0x02,
        0x02, 0x02, 0x02, 0x02,
        0x03, 0x03, 0x03, 0x03,
        0x03, 0x03, 0x03, 0x03
    };

    static const unsigned char mask2a[32] = {
        0x01, 0x02, 0x04, 0x08,
        0x10, 0x20, 0x40, 0x80,
        0x01, 0x02, 0x04, 0x08,
        0x10, 0x20, 0x40, 0x80,
        0x01, 0x02, 0x04, 0x08,
        0x10, 0x20, 0x40, 0x80,
        0x01, 0x02, 0x04, 0x08,
        0x10, 0x20, 0x40, 0x80,
    };

    __m256i mask2 = _mm256_loadu_si256((__m256i*)mask2a);
    __m256i mask1 = _mm256_loadu_si256((__m256i*)mask1a);

    auto y = _mm256_permutevar8x32_epi32(t, _mm256_set1_epi32(which));
    auto z = _mm256_shuffle_epi8(y, mask1);
    return _mm256_and_si256(z, mask2);
}

template<typename leaf_t, typename node_t, typename prgkey_t, typename row_t = __m256i>
inline void bitsliced_finalize(const AES_KEY& aeskey, const prgkey_t & prgkey, bitsliced_dpf_key<leaf_t, node_t, prgkey_t> & dpfkey,  
                                std::array<block<__m256i> , blocklen>  * s, size_t nnodes, block<row_t> * t, leaf_t * output, size_t itr)
{
     constexpr size_t len = bitsliced_dpf_key<leaf_t, node_t, prgkey_t>::nodes_per_leaf;
     
 
     for(size_t i = 0; i < nitems; ++i)
     { 

        if(itr > 0)
        {
          while(progress[itr] >= progress[itr-1]) 
          {
            std::this_thread::yield();
          }
        }

        if(itr == ncores - 1)
        {
          while((progress[itr] - progress[0]) < 64)
          {
            std::this_thread::yield();
          }
        }

        std::array<node_t, ndpfs> seeds;
        auto inp = reinterpret_cast<uint8_t *>(&s[i]);
        auto out = reinterpret_cast<uint8_t *>(&seeds);
        trans(inp, out, blocklen, ndpfs);        
        stretch_leaf_AES(aeskey, dpfkey, seeds, output[i], i, t);

        __m256i tt_[8] = {
                get_bytes_from_bits(t[i], 0),
                get_bytes_from_bits(t[i], 1),
                get_bytes_from_bits(t[i], 2),
                get_bytes_from_bits(t[i], 3),
                get_bytes_from_bits(t[i], 4),
                get_bytes_from_bits(t[i], 5),
                get_bytes_from_bits(t[i], 6),
                get_bytes_from_bits(t[i], 7)
        };

        const char * tt = reinterpret_cast<const char *>(tt_);
     
        for (size_t j = 0; j < len; ++j)
        {
          for(size_t k = 0; k < ndpfs; ++k) 
          {
             if(tt[k])
             { 
                 output[i][j] ^= dpfkey.finalizer[k][j];
             }
          } 
        }

        progress[itr] = i + 1;
     }

    printf("nodes_per_leaf =  %zu\n",dpfkey.nodes_per_leaf); 
}
 
 
 


template<typename leaf_t, typename node_t, typename prgkey_t, typename row_t = __m256i>
inline void __evalinterval_bitsliced(const AES_KEY& aeskey, const prgkey_t& prgkey, bitsliced_dpf_key<leaf_t, node_t, prgkey_t> & dpfkey, 
										    block<row_t>* flags, size_t from, size_t to, leaf_t* output, size_t itr)
{
	
	std::array<block<row_t> , blocklen> root_array = ___transpose(dpfkey.root);
 
	auto nbits = dpfkey.input_bits();
	
	auto nodes_in_interval = dpfkey.nodes_in_interval(from, to);

	auto nodes_per_leaf = dpfkey.nodes_per_leaf;
	
	std::vector<std::array<block<row_t> , blocklen>> cw_array;
 	
	block<row_t> * t[2] = {flags, flags + nodes_in_interval /2 };

 	std::array<block<row_t>, blocklen> * outs =(std::array<block<row_t>, blocklen> *) std::aligned_alloc(sizeof(row_t),  nitems * sizeof(std::array<block<row_t>, blocklen>));
	std::array<block<row_t>, blocklen> * s[2] = {outs, outs + nodes_in_interval /2 };
 
	size_t depth = dpfkey.depth();

	cw_array.reserve(depth + 1);	
 
 	for(size_t d = 0; d < depth; ++d)
 	{
 		cw_array[d] = ___transpose(dpfkey.cw[d]);
 	}

  	size_t curlayer = depth % 2;	 
	 s[curlayer][0] = root_array;
 

   	t[curlayer][0] = bitslicled_get_lsb(root_array, 0b01);
  
  	const size_t from_node = std::floor(static_cast<double>(from) / nodes_per_leaf);
 
    for(size_t layer = 0; layer < depth; ++layer)
    {
      	
      block<row_t> cw_t[2] = { bitslicled_get_lsb(cw_array[layer], 0b01), bitslicled_get_lsb(cw_array[layer], 0b10) };
  		curlayer = 1-curlayer;
  		
  		size_t i=0, j=0;
  		auto nextbit = (from_node >> (nbits-layer-1)) & 1;
  		size_t nodes_in_prev_layer = std::ceil(static_cast<double>(nodes_in_interval) / (1ULL << (depth-layer)));
  		size_t nodes_in_cur_layer = std::ceil(static_cast<double>(nodes_in_interval) / (1ULL << (depth-layer-1)));
  	
  		 for(i = nextbit, j = nextbit; j < nodes_in_prev_layer-1; ++j, i+=2)
  		 { 
   	   	    bitsliced_traverse2(prgkey, cw_array[layer], cw_t, s[1-curlayer][j], &s[curlayer][i], &t[curlayer][i], t[1-curlayer][j]);
  		 }

  		 if(nodes_in_prev_layer > j)
  		 {
  		   if(i < nodes_in_cur_layer - 1) bitsliced_traverse2(prgkey,  cw_array[layer], cw_t, s[1-curlayer][j], &s[curlayer][i],  &t[curlayer][i], t[1-curlayer][j]);
  		 }
     }

 	
    bitsliced_finalize(aeskey, prgkey, dpfkey, s[0], nodes_in_interval, t[0], output, itr); 
}


template<typename leaf_t, typename node_t, typename prgkey_t>
struct dpf_key final
{
  public:
	static constexpr size_t bits_per_leaf = std::is_same<leaf_t, bool>::value ? 1 : sizeof(leaf_t) * CHAR_BIT;
	static constexpr bool is_packed = (sizeof(leaf_t) < sizeof(node_t));
	static constexpr size_t leaves_per_node = dpf_key::is_packed ? sizeof(node_t) * CHAR_BIT / bits_per_leaf : 1;
	static constexpr size_t nodes_per_leaf = dpf_key::is_packed ? 1 : std::ceil(static_cast<double>(bits_per_leaf) / (sizeof(node_t) * CHAR_BIT));
	
	// static_assert(leaves_per_node * bits_per_leaf == sizeof(node_t) * CHAR_BIT
	//     || nodes_per_leaf * sizeof(node_t) == sizeof(leaf_t));

	using finalizer_t = std::array<node_t, nodes_per_leaf>;
	typedef std::pair<finalizer_t, finalizer_t> (*finalizer_callback)(const prgkey_t &, const size_t, const leaf_t &, const node_t[2], const uint8_t[2]);

	inline static constexpr size_t depth(const size_t nitems) { return std::ceil(std::log2(std::ceil(static_cast<double>(nitems) / dpf_key::leaves_per_node))); }
	inline constexpr size_t depth() const { return dpf_key::depth(nitems); }

	inline static constexpr size_t input_bits(const size_t nitems) { return std::ceil(std::log2(nitems)); }
	inline constexpr size_t input_bits() const { return dpf_key::input_bits(nitems); }

	inline static constexpr size_t nodes_in_interval(const size_t from, const size_t to) { return (to < from) ? 0 : std::max(1.0, std::ceil(static_cast<double>(to+1) / leaves_per_node) - std::floor(static_cast<double>(from) / leaves_per_node)); }

	inline static constexpr size_t interval_bytes(const size_t from, const size_t to) { return nodes_in_interval(from, to) * (is_packed ? sizeof(node_t) : sizeof(leaf_t)); }
	inline constexpr size_t full_bytes() { return interval_bytes(0, nitems-1); }

	inline static constexpr size_t nodes_at_leaf_layer(const size_t nitems) { return std::ceil(static_cast<double>(nitems) / dpf_key::leaves_per_node); }
	inline constexpr size_t nodes_at_leaf_layer() const { return dpf_key::nodes_at_leaf_layer(nitems); }

	inline dpf_key(dpf_key &&) = default;
	inline dpf_key & operator=(dpf_key &&) = default;
	inline dpf_key(const dpf_key &) = default;
	inline dpf_key & operator=(const dpf_key &) = default;

	inline bool operator==(const dpf_key & rhs) const { return nitems == rhs.nitems && root == rhs.root && cw == rhs.cw && finalizer == rhs.finalizer; }
	inline bool operator!=(const dpf_key & rhs) const { return !(*this == rhs); }

	static inline auto deserialize(const prgkey_t & prgkey, std::istream & is)
	{
		size_t nitems;
		is.read(reinterpret_cast<char*>(&nitems), sizeof(size_t));

		node_t root;
		is.read(reinterpret_cast<char*>(&root), sizeof(node_t));

		size_t cwlen;
		is.read(reinterpret_cast<char*>(&cwlen), sizeof(size_t));
		std::vector<node_t> cw;
		cw.reserve(cwlen);
		for (size_t i = 0; i < cwlen; ++i)
		{
			node_t cwbuf;
			is.read(reinterpret_cast<char*>(&cwbuf), sizeof(node_t));
			cw.push_back(cwbuf);
		}
		cw.shrink_to_fit();
		
		finalizer_t finalizer;
		is.read(reinterpret_cast<char*>(&finalizer), sizeof(finalizer_t));

		return std::forward<dpf_key>(dpf_key(nitems, std::move(root), std::move(cw), std::move(finalizer), prgkey));
	}

	inline std::ostream & serialize(std::ostream & os) const
	{
		os.write(reinterpret_cast<const char*>(&nitems), sizeof(size_t));
		os.write(reinterpret_cast<const char*>(&root), sizeof(node_t));
		size_t cwlen = cw.size();
		os.write(reinterpret_cast<char*>(&cwlen), sizeof(size_t));
		for (size_t i = 0; i < cw.size(); ++i)
		{
			os.write(reinterpret_cast<const char*>(&cw[i]), sizeof(node_t));
		}
		os.write(reinterpret_cast<const char*>(&finalizer), sizeof(finalizer_t));

		return os;
	}

	static auto default_make_finalizer(const prgkey_t & prgkey, const size_t target, const leaf_t & val, const node_t s[2], const uint8_t t[2])
	{
		finalizer_t finalizer;

		finalizer_t stretched[2];

		AES_KEY aeskey;

		stretch_leaf(prgkey, s[L], stretched[L]);
		stretch_leaf(prgkey, s[R], stretched[R]);

		// stretch_leaf(prgkey, s[L], stretched[L]);
		// stretch_leaf(prgkey, s[R], stretched[R]);

		if constexpr(dpf_key::is_packed)
		{
			auto finalizer0 = reinterpret_cast<node_t *>(&finalizer[0]);
			if constexpr(std::numeric_limits<leaf_t>::is_integer)
			{
				if constexpr(std::is_same<leaf_t, bool>::value)
				{
					*finalizer0 = (node_t)init_val<node_t>(val ? 1 : 0);
					//*finalizer0 = init_val<node_t>(val ? 1 : 0);
				}
				else
				{
					typedef typename std::make_unsigned_t<leaf_t> unsigned_leaf_t;
					*finalizer0 = init_val<node_t>(static_cast<unsigned_leaf_t>(val));
				}
				auto tmp = reinterpret_cast<std::bitset<8*sizeof(node_t)> *>(finalizer0);
				*tmp <<= bits_per_leaf * (target % leaves_per_node);
			}
			else
			{
				*finalizer0 = val;
			}
		}
		else
		{
			std::memcpy(&finalizer[0], &val, sizeof(finalizer_t));
		}
		for (size_t j = 0; j < nodes_per_leaf; ++j)
		{
			finalizer[j] ^= stretched[L][j] ^ stretched[R][j];
		}
		return std::make_pair(finalizer, finalizer);
	} // dpf_key::default_make_finalizer
	static auto make_shared_finalizer(const prgkey_t & prgkey, const size_t target, const leaf_t & val, const node_t s[2], const uint8_t t[2])
	{
		finalizer_t tmp[3];
		stretch_leaf(prgkey, s[L], tmp[0]);
		stretch_leaf(prgkey, s[R], tmp[1]);
		arc4random_buf(&tmp[2], sizeof(finalizer_t));

		auto tmp2 = reinterpret_cast<leaf_t *>(tmp);

		return std::make_pair(tmp2[2], t[L] ? (tmp2[1]-tmp2[0])-tmp2[2] : (tmp2[0]-tmp2[1])-tmp2[2]);
	} // dpf_key::make_shared_finalizer

	static auto gen(const prgkey_t & prgkey, size_t nitems, size_t target, const leaf_t & val = 1, const finalizer_callback make_finalizer = default_make_finalizer)
	{
		if (nitems <= target)
		{
			throw std::runtime_error("target point out of range");
		}

		node_t root[2];
		arc4random_buf(root, sizeof(root));
		uint8_t t[2] = { get_lsb(root[0]), !t[0] };
		root[1] = set_lsb(root[1], t[1]);
		node_t s[2] = { root[0], root[1] };

		const size_t depth = dpf_key::depth(nitems);
		std::vector<node_t> cw;
		cw.reserve(depth);

		node_t s0[2], s1[2];
		uint8_t t0[2], t1[2];
		const size_t nbits = input_bits(nitems);
		for (size_t layer = 0; layer < depth; ++layer)
		{
			const uint8_t bit = (target >> (nbits - layer - 1)) & 1U;

			 expand(prgkey, s[0], s0, t0);
			 expand(prgkey, s[1], s1, t1);

			const uint8_t keep = (bit == 0) ? L : R, lose = 1 - keep;
			bool cwt[2] = {
			    cwt[L] = t0[L] ^ t1[L] ^ bit ^ 1,
			    cwt[R] = t0[R] ^ t1[R] ^ bit
			};
			auto nextcw = s0[lose] ^ s1[lose];

			s[L] = xor_if(s0[keep], nextcw, !t[L]);
			t[L] = t0[keep] ^ (t[L] & cwt[keep]);

			s[R] = xor_if(s1[keep], nextcw, !t[R]);
			t[R] = t1[keep] ^ (t[R] & cwt[keep]);

			cw.emplace_back(set_lsbs(nextcw, cwt));
		}
		cw.shrink_to_fit();

		auto [finalizer0, finalizer1] = make_finalizer(prgkey, target, val, s, t);
		return std::make_pair(
		    std::forward<dpf_key>(dpf_key(nitems, root[0], cw, finalizer0, prgkey)),
		    std::forward<dpf_key>(dpf_key(nitems, root[1], cw, finalizer1, prgkey)));
	} // dpf_key::gen

	inline leaf_t eval(const size_t input) const { return std::forward<leaf_t>(dpf::eval(*this, input)); }
	inline void evalinterval(const size_t from, const size_t to, leaf_t * output, uint8_t * t = NULL) const { dpf::evalinterval(*this, from, to, output, t); }
	inline void evalfull(leaf_t * output, uint8_t * t = NULL) const { dpf::evalfull(*this, output, t); }
	template<class iterator>
	inline std::vector<leaf_t> evallist(iterator begin, iterator end, size_t size_hint = 0) const { return std::forward<std::vector<leaf_t>>(dpf::evallist(*this, std::forward<iterator>(begin), std::forward<iterator>(end), size_hint)); }

struct interator final
{
	inline explicit interator(const size_t v) : value(v) { }
	inline operator size_t() const { return value; }
	inline size_t operator*() const { return value; }
	inline interator & operator++() { ++value; return *this; }
  private:
	size_t value;
};

template<class Iterator>
struct filterator final
{
  public:
	inline filterator(const dpf_key & dpfkey_, Iterator && it1_, Iterator && it2_)
	  : dpfkey(dpfkey_),
	    it1(std::move(it1_)),
	    it2(std::move(it2_)) { }
	inline auto begin() const { return std::forward<const_iterator<Iterator>>(const_iterator<Iterator>(dpfkey, it1)); }
	inline auto end() const { return std::forward<const_iterator<Iterator>>(const_iterator<Iterator>(dpfkey, it2)); }
  private:
	const dpf_key & dpfkey;
	const Iterator it1;
	const Iterator it2;
};
	template<class Iterator = interator>
	struct const_iterator final
	{
	  public:
		typedef dpf_key::const_iterator<Iterator> self_type;
		typedef std::pair<leaf_t, size_t> value_type;
		typedef const value_type & reference;
		typedef void pointer;
		typedef std::bidirectional_iterator_tag iterator_category;
		typedef ssize_t difference_type;

		inline explicit const_iterator(const dpf_key & dpfkey_, Iterator curr_)
		  : dpfkey(dpfkey_),
		    S(dpfkey.depth()+1),
		    T(dpfkey.depth()+1),
		    curr(curr_),
		    prev(curr_)
		{
			S[0] = dpfkey.root;
			T[0] = get_lsb(dpfkey.root, 0b01);
			val = dpf::__reeval(dpfkey, curr_, S.data(), final, T.data(), 0);
		}
		inline const_iterator(const_iterator &&) = default;
		inline const_iterator & operator=(const_iterator &&) = default;
		inline const_iterator(const const_iterator &) = default;
		inline const_iterator & operator=(const const_iterator &) = default;
		inline ~const_iterator() = default;

		inline self_type & operator++() { ++curr; return *this; }
		inline self_type operator++(const int) { auto copy(*this); ++curr; return std::move(copy); }
		inline self_type & operator--() { --curr; return *this; }
		inline self_type operator--(const int) { auto copy(*this); --curr; return std::move(copy); }

		inline bool operator==(const self_type & rhs) const { return dpfkey == rhs.dpfkey && curr == rhs.curr; }
		inline bool operator!=(const self_type & rhs) const { return !(*this == rhs); }

		inline auto operator*()
		{
			auto curr_ = *curr;
			if (curr_ != prev)
			{
				int from_bit = __builtin_clzll(curr_ ^ prev) - 64 + dpfkey.input_bits();
				val = dpf::__reeval(dpfkey, curr_, S.data(), final, T.data(), from_bit);
				prev = curr_;
			}
			return std::forward<value_type>(std::make_pair(val, curr_));
		}
	  private:
		const dpf_key & dpfkey;
		std::vector<node_t> S;
		std::vector<uint8_t> T;
		finalizer_t final;
		Iterator curr;
		size_t prev;
		leaf_t val;
	};

	inline auto begin() const { return std::forward<const_iterator<interator>>(const_iterator<interator>(*this, interator(0))); }
	inline auto cbegin() const { return std::forward<const_iterator<interator>>(const_iterator<interator>(*this, interator(0))); }
	inline auto end() const { return std::forward<const_iterator<interator>>(const_iterator<interator>(*this, interator(nitems))); }
	inline auto cend() const { return std::forward<const_iterator<interator>>(const_iterator<interator>(*this, interator(nitems))); }

	inline auto rbegin() const { return std::reverse_iterator<const_iterator<interator>>(end()); }
	inline auto crbegin() const { return std::reverse_iterator<const_iterator<interator>>(end()); }
	inline auto rend() const { return std::reverse_iterator<const_iterator<interator>>(begin()); }
	inline auto crend() const { return std::reverse_iterator<const_iterator<interator>>(begin()); }

	inline auto filtered_by(size_t begin, size_t end) { return filterator<interator>(*this, interator(begin), interator(end)); }
	template<class Iterator>
	inline auto filtered_by(Iterator && begin, Iterator && end) { return filterator<Iterator>(*this, std::move(begin), std::move(end)); }
	template<class Container>
	inline auto filtered_by(const Container & c) { return filterator<typename Container::iterator_type>(*this, std::cbegin(c), std::cend(c)); }

	inline auto refinalize(const finalizer_t & new_finalizer) const
	{
		return std::forward<dpf_key>(nitems, root, cw, new_finalizer, prgkey);
	}

	const size_t nitems;
	const node_t root;
	const std::vector<node_t> cw;
	const finalizer_t finalizer;
	const prgkey_t prgkey;

  private:
	dpf_key(size_t nitems_, const node_t & root_, const std::vector<node_t> cw_,
		const finalizer_t & finalizer_, const prgkey_t & prgkey_)
	  : nitems(nitems_),
	    root(root_),
	    cw(cw_),
	    finalizer(finalizer_),
	    prgkey(prgkey_) { }
}; // struct dpf::dpf_key

template<typename leaf_t, typename node_t, typename prgkey_t>
inline std::ostream & operator<<(std::ostream & os, const dpf_key<leaf_t, node_t, prgkey_t> & dpfkey)
{
	return dpfkey.serialize(os);
}

template<typename leaf_t, typename node_t>
inline leaf_t getword(const node_t & S, const size_t input)
{
	auto S_ = reinterpret_cast<const leaf_t *>(&S);
	if constexpr(sizeof(leaf_t) >= sizeof(node_t)) return *S_;

	return S_[input];
} // dpf::getword

template<>
inline bool getword(const __m128i & S, const size_t input)
{
	const __m128i mask = bool128_mask[input / 64];
	__m128i vcmp = _mm_xor_si128(_mm_and_si128(S >> (input % 64), mask), mask);

	return static_cast<bool>(_mm_testz_si128(vcmp, vcmp));
} // dpf::getword<__m128i,bool>

template<>
inline bool getword(const __m256i & S, const size_t input)
{
	const __m256i mask = bool256_mask[input / 64];
	__m256i vcmp = _mm256_xor_si256(_mm256_and_si256(S >> (input % 64), mask), mask);

	return static_cast<bool>(_mm256_testz_si256(vcmp, vcmp));
} // dpf::getword<__m256i,bool>

template<typename leaf_t, typename node_t, typename prgkey_t>
inline void finalize(const prgkey_t & prgkey, std::array<node_t, dpf_key<leaf_t, node_t, prgkey_t>::nodes_per_leaf> finalizer, leaf_t * output, node_t * s, size_t nnodes, uint8_t * t)
{
	auto output_ = reinterpret_cast<std::array<node_t, dpf_key<leaf_t, node_t, prgkey_t>::nodes_per_leaf> *>(output);

	for (size_t i = 0; i < nnodes; ++i)
	{
		stretch_leaf(prgkey, s[i], output_[i]);
		for (size_t j = 0; j < dpf_key<leaf_t, node_t, prgkey_t>::nodes_per_leaf; ++j)
		{
			output_[i][j] = xor_if(output_[i][j], finalizer[j], t[i]);
		}
	}
} // dpf::finalize



template<typename leaf_t, typename node_t, typename prgkey_t>
inline void __evalinterval(const dpf_key<leaf_t, node_t, prgkey_t> & dpfkey, const size_t from, const size_t to, leaf_t * output, uint8_t * _t)
{
	auto nodes_per_leaf = dpfkey.nodes_per_leaf;
	auto depth = dpfkey.depth();
	auto nbits = dpfkey.input_bits();
	auto nodes_in_interval = dpfkey.nodes_in_interval(from, to);
	auto root = dpfkey.root;
	auto prgkey = dpfkey.prgkey;

	const size_t from_node = std::floor(static_cast<double>(from) / nodes_per_leaf);

	node_t * s[2] = {
	    reinterpret_cast<node_t *>(output) + nodes_in_interval * (nodes_per_leaf - 1),
	    s[0] + nodes_in_interval / 2
	};
	uint8_t * t[2] = { _t, _t + nodes_in_interval / 2};

	int curlayer = depth % 2;

	s[curlayer][0] = root;
	t[curlayer][0] = get_lsb(root, 0b01);

	//printf("depth = %u\n", depth);

	for (size_t layer = 0; layer < depth; ++layer)
	{
		auto & cw = dpfkey.cw[layer];
		uint8_t cw_t[2] = { get_lsb(cw, 0b01), get_lsb(cw, 0b10) };
		curlayer = 1-curlayer;

		size_t i=0, j=0;
		auto nextbit = (from_node >> (nbits-layer-1)) & 1;
		size_t nodes_in_prev_layer = std::ceil(static_cast<double>(nodes_in_interval) / (1ULL << (depth-layer)));
		size_t nodes_in_cur_layer = std::ceil(static_cast<double>(nodes_in_interval) / (1ULL << (depth-layer-1)));

		//printf("nextbit = %u\n",  (from_node >> (nbits-layer-1)));

		if (nextbit == 1) traverse(prgkey, s[1-curlayer][0], R, cw_t[R], cw, t[1-curlayer][j], s[curlayer][0], t[curlayer][0]); // these will not be called in evalfull
		for (i = nextbit, j = nextbit; j < nodes_in_prev_layer-1; ++j, i+=2)
		{
			//printf("j = %u\n", j );
			traverse2(prgkey, s[1-curlayer][j], cw_t, cw, t[1-curlayer][j], &s[curlayer][i], &t[curlayer][i]);
		}
		if (nodes_in_prev_layer > j)
		{
			//printf("jj' = %u\n", j );
			if (i < nodes_in_cur_layer - 1) 
			{
				traverse2(prgkey, s[1-curlayer][j], cw_t, cw, t[1-curlayer][j], &s[curlayer][i], &t[curlayer][i]);
				//printf("If\n");
			}
			else
			{
				traverse(prgkey, s[1-curlayer][j], L, cw_t[L], cw, t[1-curlayer][j], s[curlayer][i], t[curlayer][i]); // will not be called in evalfull
			//	printf("else\n");
			} 
		}
	}


	// AES_KEY aeskey;
	// finalize(aeskey, dpfkey.finalizer, output, s[0], nodes_in_interval, t[0]);
	finalize(prgkey, dpfkey.finalizer, output, s[0], nodes_in_interval, t[0]);
} // dpf::__evalinterval

template<typename leaf_t, typename node_t, typename prgkey_t>
inline void evalinterval(const dpf_key<leaf_t, node_t, prgkey_t> & dpfkey, const size_t from, const size_t to, leaf_t * output, uint8_t * t)
{
	uint8_t * tt = t ? t : reinterpret_cast<uint8_t *>(malloc(dpfkey.nodes_in_interval(from, to) * sizeof(uint8_t)));
	__evalinterval(dpfkey, from, to, output, tt);
	if (!t) free(tt);
} // dpf::evalinterval

template<typename leaf_t, typename node_t, typename prgkey_t>
inline void evalfull(const dpf_key<leaf_t, node_t, prgkey_t> & dpfkey, leaf_t * output, uint8_t * t)
{
	uint8_t * tt = t ? t : reinterpret_cast<uint8_t *>(malloc(dpfkey.nodes_at_leaf_layer() * sizeof(uint8_t)));
	__evalinterval(dpfkey, 0, dpfkey.nitems-1, output, tt);
	if (!t) free(tt);
} // dpf::evalfull

template<typename leaf_t, typename node_t, typename prgkey_t>
inline leaf_t eval(const dpf_key<leaf_t, node_t, prgkey_t> & dpfkey, const size_t input)
{
	auto prgkey = dpfkey.prgkey;
	auto root = dpfkey.root;
	auto depth = dpfkey.depth();
	auto nbits = dpfkey.input_bits();

	node_t S = root;
	uint8_t T = get_lsb(root, 0b01);

	for (size_t layer = 0; layer < depth; ++layer)
	{
		auto & cw = dpfkey.cw[layer];
		const uint8_t nextbit = (input >> (nbits-layer-1)) & 1;
		traverse(prgkey, S, nextbit, get_lsb(cw, nextbit ? 0b10 : 0b01), cw, T, S, T); 
	}
	std::array<node_t, dpf_key<leaf_t, node_t, prgkey_t>::nodes_per_leaf> final;
	finalize(prgkey, dpfkey.finalizer, &final, &S, 1, &T);

	if constexpr(dpfkey.is_packed)
	{
		auto S_ = reinterpret_cast<node_t *>(&final);
		return std::forward<leaf_t>(getword<leaf_t>(*S_, input % dpfkey.leaves_per_node));
	}
	else
	{
		auto ret = reinterpret_cast<leaf_t *>(&final);
		return *ret;
	}
} // dpf::eval

template<typename leaf_t, typename node_t, typename prgkey_t>
inline leaf_t __reeval(const dpf_key<leaf_t, node_t, prgkey_t> & dpfkey, const size_t input,
	node_t * S, std::array<node_t, dpf_key<leaf_t, node_t, prgkey_t>::nodes_per_leaf> & final, uint8_t * T, const size_t from_bit)
{
	auto prgkey = dpfkey.prgkey;
	auto depth = dpfkey.depth();
	auto nbits = dpfkey.input_bits();

	for (auto layer = from_bit; layer < depth; ++layer)
	{
		auto & cw = dpfkey.cw[layer];
		const uint8_t nextbit = (input >> (nbits-layer-1)) & 1;
		traverse(prgkey, S[layer], nextbit, get_lsb(cw, nextbit ? 0b10 : 0b01), cw, T[layer], S[layer+1], T[layer+1]);
	}
	if (from_bit != depth) finalize(prgkey, dpfkey.finalizer, &final, &S[depth], 1, &T[depth]);

	if constexpr(dpfkey.is_packed)
	{
		auto S_ = reinterpret_cast<node_t *>(&final);
		return std::forward<leaf_t>(getword<leaf_t>(*S_, input % dpfkey.leaves_per_node));
	}
	else
	{
		auto ret = reinterpret_cast<leaf_t *>(&final);
		return *ret;
	}
} // dpf::__reeval

template<class iterator, typename leaf_t, typename node_t, typename prgkey_t>
inline std::vector<leaf_t> evallist(const dpf_key<leaf_t, node_t, prgkey_t> & dpfkey, iterator begin, const iterator end, size_t size_hint)
{
	auto root = dpfkey.root;
	auto depth = dpfkey.depth();
	auto nbits = dpfkey.input_bits();

	std::vector<leaf_t> result;
	result.reserve(size_hint ? size_hint : std::distance(begin, end));
	node_t * S = (node_t *)std::aligned_alloc(sizeof(node_t), sizeof(node_t) * (depth+1));
	uint8_t * T = reinterpret_cast<uint8_t *>(malloc(sizeof(uint8_t) * (depth+1)));

	S[0] = root;
	T[0] = get_lsb(root, 0b01);
	std::array<node_t, dpfkey.nodes_per_leaf> final = { 0 };

	auto it = begin;
	result.emplace_back(std::forward<leaf_t>(__reeval(dpfkey, *it, S, final, T, 0)));
	auto prev = *it;
	while (++it != end)
	{
		size_t from_bit = __builtin_clzll(*it ^ prev) - 64 + nbits;
		result.emplace_back(std::forward<leaf_t>(__reeval(dpfkey, *it, S, final, T, from_bit)));
		prev = *it;
	}

	free(S);
	free(T);
	result.shrink_to_fit();
	return std::move(result);
} // dpf::evallist

} // namespace dpf

#endif // DPFPP_DPF_H
