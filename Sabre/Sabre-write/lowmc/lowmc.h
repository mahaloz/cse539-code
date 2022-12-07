/** Sabre, an anonymous bulletin board with speedier ripostes
 *  Copyright (C) 2020  Sabre authors
 *
 *  @file    lowmc.h
 *  @brief   Header-only library implementing fixed-key LowMC encryption
 *           suitable for constructing pseudorandom generators (PRGs).
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

// TODO: add more efficient methods for encrypting multiple blocks at once

#ifndef LOWMC_LOWMC_H__
#define LOWMC_LOWMC_H__

#include <type_traits>          // std::conditional
#include <cstring>              // std::memset
#include <bitset>               // std::bitset
#include <array>                // std::array
#include <cstddef>              // std::size_t
#include <thread>               // std::thread
#include <future>               // std::async

#include "../block.h"
#include "randomness.h"
#include "streams.h"

namespace lowmc
{

const size_t nitems = 1000000;// 1ULL << 20; 
/// the default block length in bytes (must be 128 or 256)
constexpr size_t default_block_len = 128;

/// the default number of rounds
constexpr size_t default_rounds    = 19;

/// the default number of s-boxes per round (must be between 1 and block_len/3)
constexpr size_t default_sboxes    = 32;

/// default number of slices in the bitsliced implementation
constexpr size_t default_slices    = 128;

/// mask used in the evaluation of s-boxes
static const std::string sbox_mask = "0100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100";

template <size_t block_len = default_block_len,
          size_t rounds    = default_rounds,
          size_t sboxes    = default_sboxes>
class lowmc
{
  public:
	// perform some basic sanity checks to ensure the template parameters
	// are not horribly out of whack.
	//
	// N.B.: These asserts are *not* sufficient to ensure that the combination
	//       of parameters yields a secure LowMC instantiation!!
	static_assert(block_len == 128 || block_len == 256,
		"block_len must be 128 or 256");
	static_assert(rounds > 0,
		"rounds must be positive");
	static_assert(sboxes > 0,
		"sboxes must be positive");
	static_assert(sboxes < block_len/3,
		"sboxes must be less than 3*block_len");
	static_assert(rounds > 0,
		"rounds must be positive");

	/// number of bits in a block (Contraints: @ref block_size = 128 or @ref block_size = 256)
	static constexpr auto block_size = block_len;

	/// number of rounds (Constraints: 0 < @ref num_rounds)
	static constexpr auto num_rounds = rounds;

	/// number of s-boxes per round (Contraints: 0 < @ref sboxes_per_round ≤ @ref block_size/3)
	static constexpr auto sboxes_per_round = sboxes;

	/// number of bits per block unaffected by the s-boxes in each round
	static constexpr auto identity_len = block_len - 3 * sboxes;

	/// total number of s-boxes across all rounds
	static constexpr auto sboxes_total = sboxes * rounds;

	/// type representing a single lowmc block
	using block_t = std::conditional_t<block_len == 128,
		block<__m128i>, block<__m256i>>;

	using instream = streams::input_stream<block_t>;
	using outstream = streams::output_stream<block_t, 1>;
	using rewindstream = streams::rewindable_stream<block_t, 1>;
	using basicstream = streams::basic_stream<block_t, 1>;

/** @defgroup group1 Regular encryption
 *  This is the first group
 *  @{
 */

	/// Plain-ol' ECB-mode encryption of a 1-block message
	inline auto encrypt(const block_t & msg) const
	{
		auto c = msg;
		for (size_t i = 0; i < rounds; ++i)
		{
		 	c = substitute(c);
			auto mat = reinterpret_cast<const block_t *>(matrices[i]);
			c = mul(mat, c , round_constants[i]);
		} 

		    // block_t c = msg ^ round_constants[0];
		    // for (unsigned r = 1; r <= rounds; ++r)
		    // {  
		    //    c =  substitute(c);
		     
		    //    //std::vector<block_t> lin = (lin_mat[r-1]);
		    //    const block_t * lin = reinterpret_cast<const block_t*>(matrices[r-1]);
		    //    c =  mul(lin, c, round_constants[r]);
		    // }
		return c;
	} // encrypt

/** @} */ // end of group1

/** @defgroup group2 3PC encryption
 *  This is the second group
 *  @{
 */

	inline auto encrypt2_p0p1(const block_t & share0, randomness & rand0,
		instream * p1in, instream * p2, outstream * p1out, bool p) const
	{
		auto c0 = share0;
		for (size_t i = 0; i < rounds; ++i)
		{
			block_t blinded_c1, blind0, gamma;
			rand0 >> blind0;           //< sample next blinding factor
			*p1out << (c0 ^ blind0);   //< blind own share; send to other party
			*p1in >> blinded_c1;       //< get blinded share from other party
			*p2 >> gamma;              //< get cancellation term from P2

			auto mat = reinterpret_cast<const block_t *>(matrices[i]);
			c0 = substitute2_p0p1(c0, blind0, blinded_c1, gamma);
			c0 = mul(mat, c0, p ? round_constants[i] : 0);
		}
		return c0;
	} // encrypt2_p0p1

	inline void encrypt2_p2(outstream * p0, outstream * p1, randomness & rand0,
		randomness & rand1, randomness & rand2) const
	{
		for (size_t i = 0; i < rounds; ++i)
		{
			auto [gamma0, gamma1] = substitute2_p2(rand0, rand1, rand2);
			*p0 << gamma0;             //< send next cancellation term to P0
			*p1 << gamma1;             //< send next cancellation term to P1
		}
	} // encrypt2_p2
	inline auto encrypt2_p2_(outstream * p0, outstream * p1, randomness && rand0,
		randomness && rand1, randomness & rand2) const
	{
		return encrypt2_p2(p0, p1, rand0, rand1, rand2);
	}

/** @} */ // end of group2

	inline auto encrypt3_proof(const block_t & share0, const block_t & share1,
		randomness & rand0, randomness & rand1, randomness & rand2,
		rewindstream * p01, rewindstream * p10, rewindstream * p20, rewindstream * p21) const
	{
		std::thread t2(&lowmc<block_len,rounds,sboxes>::encrypt2_p2_, this,
			p20, p21, rand0.clone(), rand1.clone(), std::ref(rand2));

		auto t0 = std::async(std::launch::async,
			&lowmc<block_len,rounds,sboxes>::encrypt2_p0p1, this,
			std::ref(share0), std::ref(rand0), p10, p20, p01, 0);

		auto t1 = std::async(std::launch::async,
			&lowmc<block_len,rounds,sboxes>::encrypt2_p0p1, this,
			std::ref(share1), std::ref(rand1), p01, p21, p10, 1);
		
		t2.join();
		return std::make_pair(t0.get(), t1.get());
	} // encrypt3_proof

	inline auto encrypt3_verify(const block_t & share0, const __m256i & hash,
		rewindstream * p10, rewindstream * p20, randomness & rand0, bool p) const
	{
		basicstream p01;
		p10->rewind();
		p20->rewind();
		(void)encrypt2_p0p1(share0, rand0, p10, p20, &p01, p);
		return block<__m256i>(p01.sha256_digest()) == block<__m256i>(hash);
	} // encrypt3_verify

  //private:
	/// mask for the highest-order bit in each s-box
	block_t mask = sbox_mask;
    block_t maska = mask;
 //    block_t maska = block_t(std::string(sbox_mask, 0, identity_len  - 1));
 	
	// /// mask for middle-order bit in each s-box
	   block_t maskb = maska >> 1;
	// /// mask for low-order bit in each s-box
	   block_t maskc = maska >> 2;
	// /// mask for the all-but-the-highest-order bit in each s-box
	   block_t maskbc = maskb | maskc;

	/// linear matrices -- these must be generated using gen_constants
	static const uint64_t matrices[rounds][(block_len/64) * block_len];
	/// round constants -- these must be generated using gen_constants
	static const block_t * round_constants;

	static const uint64_t matrices2[rounds][(block_len/64) * block_len / 4][16 * (block_len/64)];

	/// s-boxes
	inline auto & substitute(block_t & msg) const
	{

		auto srli1 = (msg >> 1) & maskbc;
		auto srli2 = (msg >> 2) & maskc;

		auto tmp = msg & srli1;
		auto bc = (tmp << 2) & maska;
		auto ac = (msg & srli2) << 1;
		auto ab = (tmp >> 1) & maskc;
		msg = (bc | ac | ab) ^ msg ^ srli1 ^ srli2;
 
		return msg;
	} // substitute

	inline auto & substitute2_p0p1(block_t & share0, const block_t & blind0,
		const block_t & blinded_share1, const block_t & gamma0) const
	{
		auto blinded_msg = share0 ^ blinded_share1;

		auto srli1 = (share0 >> 1) & maskbc;
		auto srli2 = (share0 >> 2) & maskc;

		auto tmp = (blinded_msg & srli1) ^ (blind0 & (blinded_share1 >> 1));

		auto bc = (tmp << 2) & maska;
		auto ac = (((blinded_msg & srli2) ^ (blind0 & (blinded_share1 >> 2))) << 1) & maskb;
		auto ab = (tmp >> 1) & maskc;

		share0 ^= (bc | ac | ab) ^ srli1 ^ srli2 ^ gamma0;
		return share0;
	} // substitute2_p0p1

	inline auto substitute2_p2(randomness & rand0, randomness & rand1,
		randomness & rand2) const
	{
		block_t blind0, blind1, blind2;
		rand0 >> blind0;
		rand1 >> blind1;
		rand2 >> blind2;

		auto tmp1 = ((blind0 >> 1) & blind1) ^ ((blind1 >> 1) & blind0);
		auto tmp2 = ((blind0 >> 2) & blind1) ^ ((blind1 >> 2) & blind0);

		auto bc = (tmp1 << 2) & maska;
		auto ac = (tmp2 << 1) & maskb;
		auto ab = (tmp1 >> 1) & maskc;

		auto gamma0 = (bc | ac | ab) ^ blind2;
		auto gamma1 = blind2;

		return std::make_pair(gamma0, gamma1);
	} // substitute2_p2

	inline auto mul(const block_t * matrix, const block_t & msg,
		const block_t & constant) const
	{
		  block_t temp =  constant;
		  uint64_t bitset ;
		 
		   for (size_t k = 0; k < sizeof(block_t)/8; ++k)
		   {

 	 
			    bitset = static_cast<typename block_t::value_type>(msg)[k];
			    while (bitset != 0)
			    {
			      uint64_t t = bitset & -bitset;
			      int j = k * 64 + __builtin_ctzl(bitset);
			      
			      temp =  temp ^ matrix[j];
			      bitset ^= t;
			    }
		 
		   }

		  return temp;
	} // mul
 


	inline auto mul2(const uint64_t * matrix, const block_t & msg, const block_t & constant) const
	{
		block_t result = constant;
		block_t msg_bytes[16][16] = {_mm_set1_epi8(0)};
		
		for (size_t j = 0; j < 16; ++j)
		{
			// printf("%d\n",  j);
		    auto tmp = matrix[j + sizeof(block_t)/sizeof(uint64_t)*j];
			
			for (size_t k = 0; k < 16; ++k)
			{
	 		   result ^= msg_bytes[k][tmp & 0x0f];
	 		   tmp >>= 8;
			}
		}

		 return result;
	}


 

}; // class lowmc

template <size_t block_len = default_block_len,
          size_t rounds    = default_rounds,
          size_t sboxes    = default_sboxes,
          size_t slices    = default_slices>
class bitsliced_lowmc
{
  public:
	static_assert(block_len == 128 || block_len == 256,
		"block_len must be 128 or 256");
	static_assert(sboxes > 0,
		"sboxes must be positive");
	static_assert(sboxes < 3*block_len,
		"sboxes must be less than 3*block_len");
	static_assert(rounds > 0,
		"rounds must be positive");
	static_assert(slices == 64 || slices == 128 || slices == 256,
		"slices must be 64 or 128");

	/// number of bits in a block
	static constexpr auto block_size = block_len;

	/// number of rounds
	static constexpr auto num_rounds = rounds;

	/// number of s-boxes per round
	static constexpr auto sboxes_per_round = sboxes;

	/// number of bits per block unaffected by the s-boxes in each round
	static constexpr auto identity_len = block_len - 3 * sboxes;

	/// total number of s-boxes across all rounds
	static constexpr auto sboxes_total = num_rounds * sboxes_per_round;

	/// type representing a single *non-bitsliced* lowmc block
	using block_t = std::conditional_t<block_len == 128,
		block<__m128i>, block<__m256i>>;

	/// type representing a row of bits in bitsliced lowmc
	//using slicerow_t = std::conditional_t<slices == 64, 
	//	uint64_t, block<__m128i>>; // TODO: THIS NEEDS TO BE UNCOMMENTED AND FIXED

	using slicerow_t = block<__m256i>;

	/// type representing a bitsliced batch of lowmc ciphertext
	using sliceblock_t = std::array<slicerow_t, block_len>; 

	/// type representing one bitsliced "s-box worth" of bits
	using sboxslice_t = std::array<slicerow_t, 3>;

	/// type representing non-identity part of a bitsliced block
	using sboxslices_t = std::array<slicerow_t, 3*sboxes>;

	using instream = streams::input_stream<sboxslices_t>;
	using outstream = streams::output_stream<sboxslices_t>;
	using rewindstream = streams::rewindable_stream<sboxslices_t>;
	using basicstream = streams::basic_stream<sboxslices_t>;



__m128i _mm_set1_epi8_xor(__m128i message, bool x)
{
  if(x) return message ^ _mm_set1_epi8(-1);
  else  return message ^ _mm_set1_epi8(0);
}
 

	/// Plain-ol' ECB-mode encryption of a bitsliced batch of 1-block message
	inline auto encrypt(const std::array<block<__m256i> , block_len> & msg) const
	{
		 auto c = msg;
		 auto c2 = msg;
		 for (size_t i = 0; i < rounds; ++i)
		 {

		  
		   
 

		   c2 = substitute(c2);
		   const uint8_t * mat = reinterpret_cast<const uint8_t *>(matrices[i]);
		   c2 = mmul2(i, mat,  c2, round_constants[i]);

		   c = substitute(c);
		   c = mmul(matrices[i], c, round_constants[i]);
		   for(size_t j = 0; j < 128; ++j)
		   { 
			/*
		   	assert(c2[j].mX[0] == c[j].mX[0]);
		   	assert(c2[j].mX[1] == c[j].mX[1]);
		   	assert(c2[j].mX[2] == c[j].mX[2]);
		   	assert(c2[j].mX[3] == c[j].mX[3]);
			*/
		   }

		 }

		    // for (int i = 0; i < 128; ++i) c[i] = _mm_set1_epi8_xor(msg[i].mX, round_constants[0].bits[i]);// (roundkeysXORconstants_[0].bits[i] ? -1 : 0);
    
		    // for (unsigned r = 1; r <= rounds; ++r)
		    // {  
		    //  // c = substitute(c);  
		    //   const uint64_t * M = matrices[r-1];// reinterpret_cast<const uint64_t *>(transposeLinMatrices[r-1].data());
		    //   c = mmul(M, substitute(c), round_constants[r]);
		       
		    // } 

		return c;
	} // encrypt


	/// Plain-ol' ECB-mode encryption of a bitsliced batch of 1-block message
    // inline void __encrypt(sliceblock_t & msg) const
    // {
    //     for (size_t i = 0; i < rounds; ++i)
    //     {
    //         msg = mmul(matrices[i], substitute(msg), round_constants[i]);
    //     }
    // } // __encrypt

    // /// Plain-ol' ECB-mode encryption of a bitsliced batch of 1-block message
    // inline auto encrypt(const sliceblock_t & msg) const
    // {
    //     auto c = msg;
    //     __encrypt(c);
    //     return c;
    // } // encrypt

	inline auto encrypt2_p0p1(const sliceblock_t & share0, randomness & rand0,
		instream * p1in, outstream * p2, outstream * p1out, bool p) const
	{
		auto c0 = share0;
		for (size_t i = 0; i < rounds; ++i)
		{
			sboxslices_t blinded_c1, blind0, gamma;
			rand0 >> blind0;
			*p1out << sliced_xor(c0, blind0);
			*p1in >> blinded_c1;
			*p2 >> gamma;
			c0 = substitute2_p0p1(c0, blind0, blinded_c1, gamma);
			c0 = mmul(matrices[i], c0, p ? round_constants[i] : 0);
		}
		return c0;
	} // encrypt2_p0p1

	inline auto encrypt2_p2(outstream * p0, outstream * p1, randomness & rand0,
		randomness & rand1, randomness & rand2) const
	{
		for (size_t i = 0; i < rounds; ++i)
		{
			auto [gamma0, gamma1] = substitute2_p2(rand0, rand1, rand2);
			p0 << gamma0;
			p1 << gamma1;
		}
	} // encrypt2_p2

	inline auto encrypt3_proof(const sliceblock_t & share0,
		const sliceblock_t & share1, randomness & rand0, randomness & rand1,
		randomness & rand2, rewindstream * p01, rewindstream * p10, rewindstream * p20,
		rewindstream * p21) const
	{
		std::thread t2(&bitsliced_lowmc<block_len,rounds,sboxes>::encrypt2_p2_, this,
			p20, p21, rand0.clone(), rand1.clone(), std::ref(rand2));

		auto t0 = std::async(std::launch::async, &bitsliced_lowmc<block_len,rounds,sboxes>::encrypt2_p0p1, this,
			std::ref(share0), std::ref(rand0), p10, p20, p01, 0);

		auto t1 = std::async(std::launch::async, &bitsliced_lowmc<block_len,rounds,sboxes>::encrypt2_p0p1, this,
			std::ref(share1), std::ref(rand1), p01, p21, p10, 1);

		t2.join();
		return std::make_tuple(t0.get(), t1.get());
	} // encrypt3_proof

	inline auto encrypt3_verify(const sliceblock_t & share0, const __m256i & hash,
		rewindstream * p10, rewindstream * p20, randomness & rand0, bool p) const
	{
		basicstream p01;
		p10->rewind();
		p20->rewind();
		(void)encrypt2_p0p1(share0, rand0, p10, p20, &p01, p);
		return block<__m256i>(p01.sha256_digest()) == block<__m256i>(hash);
	} // encrypt3_verify


template <int imm8 = 8>
inline static __m256i _mm256_gatherbytes_epi8(const __m256i * base_addr)
{
    return _mm256_setr_epi8(
        _mm256_extract_epi8(base_addr[ 0], imm8),
        _mm256_extract_epi8(base_addr[ 1], imm8),
        _mm256_extract_epi8(base_addr[ 2], imm8),
        _mm256_extract_epi8(base_addr[ 3], imm8),
        _mm256_extract_epi8(base_addr[ 4], imm8),
        _mm256_extract_epi8(base_addr[ 5], imm8),
        _mm256_extract_epi8(base_addr[ 6], imm8),
        _mm256_extract_epi8(base_addr[ 7], imm8),
        _mm256_extract_epi8(base_addr[ 8], imm8),
        _mm256_extract_epi8(base_addr[ 9], imm8),
        _mm256_extract_epi8(base_addr[10], imm8),
        _mm256_extract_epi8(base_addr[11], imm8),
        _mm256_extract_epi8(base_addr[12], imm8),
        _mm256_extract_epi8(base_addr[13], imm8),
        _mm256_extract_epi8(base_addr[14], imm8),
        _mm256_extract_epi8(base_addr[15], imm8),
        _mm256_extract_epi8(base_addr[16], imm8),
        _mm256_extract_epi8(base_addr[17], imm8),
        _mm256_extract_epi8(base_addr[18], imm8),
        _mm256_extract_epi8(base_addr[19], imm8),
        _mm256_extract_epi8(base_addr[20], imm8),
        _mm256_extract_epi8(base_addr[21], imm8),
        _mm256_extract_epi8(base_addr[22], imm8),
        _mm256_extract_epi8(base_addr[23], imm8),
        _mm256_extract_epi8(base_addr[24], imm8),
        _mm256_extract_epi8(base_addr[25], imm8),
        _mm256_extract_epi8(base_addr[26], imm8),
        _mm256_extract_epi8(base_addr[27], imm8),
        _mm256_extract_epi8(base_addr[28], imm8),
        _mm256_extract_epi8(base_addr[29], imm8),
        _mm256_extract_epi8(base_addr[30], imm8),
        _mm256_extract_epi8(base_addr[31], imm8)
    );
}


/// transpose a 32-by-8 matrix of bits
/// the result is an std::tuple consisting of eight 32-bit rows
inline static auto transpose32x8(const __m256i & x)
{
return std::make_tuple(_mm256_movemask_epi8(x),
_mm256_movemask_epi8(_mm256_slli_epi64(x, 1)),
_mm256_movemask_epi8(_mm256_slli_epi64(x, 2)),
_mm256_movemask_epi8(_mm256_slli_epi64(x, 3)),
_mm256_movemask_epi8(_mm256_slli_epi64(x, 4)),
_mm256_movemask_epi8(_mm256_slli_epi64(x, 5)),
_mm256_movemask_epi8(_mm256_slli_epi64(x, 6)),
_mm256_movemask_epi8(_mm256_slli_epi64(x, 7))
);
}



	void populate_lut_new(const size_t round, const size_t i, const sliceblock_t & matrix,  __m256i lut[256]) const
	{
	   		auto rows = &matrix[8 * i];
	    
		    lut[0b00000000] = _mm256_setzero_si256();
		    lut[0b00000001] =  rows[0];
		    lut[0b00000010] =  rows[1];
		    lut[0b00000100] =  rows[2];
		    lut[0b00001000] =  rows[3];
		    lut[0b00010000] =  rows[4];
		    lut[0b00100000] =  rows[5];
		    lut[0b01000000] =  rows[6];
		    lut[0b10000000] =  rows[7];

	 		size_t start = (i > 0) ? recipe_len[i-1] : 0, end = start + recipe_len[i];
		    
		    if(i == 0)
		    {
		    	start = 0;
		    	end = recipe_len[0]; 
		    }

		    if(i > 0)
		    {
		    	start = 0;

	 	    	for(size_t t = 0; t < i; ++t)
		    	{
		    		start += recipe_len[t];
		    	}

		    	end = start + recipe_len[i];
		    }

	 std::cout << "len = " << end - start << std::endl; 	 
		    for(size_t j = start; j < end; ++j)
		    {
		     	auto [dst, src1, src2] = lut_recipe_[j];
		        lut[dst] = lut[src1] ^ lut[src2];  
		    }	 
		 
	}
 
	inline auto mmul2(const size_t round, const uint8_t * matrix1, const sliceblock_t & matrix2,
		const block_t & constant) const
	{
		auto result = sliced_set(constant);
 
	 	for(size_t i = 0; i < 16; ++i)
		{
			__m256i lut_new[NDPFS];
			
			populate_lut_new(round, i, matrix2, lut_new);
			
			for (size_t j = 0; j < block_len; ++j)
			{			
				auto tmp = matrix1[i + 16 * j]; 	 
			 	result[j].mX ^= lut_new[tmp];		 	  
			}
		}	
 
 		 //printf("result[2] = %llu %llu %llu %llu \n\n\n",result[0].mX[0], result[0].mX[1], result[0].mX[2], result[0].mX[3]);
		return result;
	} // mmul2


	inline auto mmul(const uint64_t * matrix1, const sliceblock_t & matrix2,
		const block_t & constant) const
	{
		auto result = sliced_set(constant); 
		
		for (size_t i = 0; i < sizeof(slicerow_t)/16; ++i)
		{
			slicerow_t lut[8][256];
			
			populate_lut(i, matrix2, lut);
 
			for (size_t j = 0; j < block_len; ++j)
			{
				auto tmp = matrix1[i + sizeof(slicerow_t)/16*j];
 
				for (size_t k = 0; k < sizeof(uint64_t); ++k)
				{
					result[j] ^= lut[k][tmp & 0xff];					 
					tmp >>= 8;
				}
			}
		}
		
		// printf("->result[0] = %llu %llu %llu %llu \n\n\n",result[0].mX[0], result[0].mX[1], result[0].mX[2], result[0].mX[3]);
		
		return result;
	} // mmul

 // private:
  	static const std::tuple<int, int, int> lut_recipe_[]; 
  	static const size_t recipe_len[16];
	static const uint64_t matrices[rounds][(block_len/64) * block_len];
	static const block_t * round_constants;

	inline auto & substitute(sliceblock_t & msg) const
	{
		for (size_t i = 0, j = 0; i < sboxes; ++i, j+=3)
		{
			auto c = (msg[j+2] & msg[j+1]) ^ msg[j+1] ^ msg[j+2];
			auto b = (msg[j+0] & msg[j+2]) ^ msg[j+2];
			auto a = (msg[j+0] & msg[j+1]);

			msg[j+0] ^= c;
			msg[j+1] ^= b;
			msg[j+2] ^= a;
		}
		return msg;
	} // substitute

	inline auto & substitute2_p0p1(sliceblock_t & share0,
		const sliceblock_t & blind0, const sliceblock_t & blinded_share1,
		const sliceblock_t & gamma0) const
	{
		for (size_t i = 0, j = 0; i < sboxes; ++i, j+=3)
		{
			auto c = ((share0[j+2] ^ blinded_share1[j+2]) & share0[j+1])
			    ^ (blind0[j+2] & blinded_share1[j+1]) ^ share0[j+1] ^ share0[j+2];
			auto b = ((share0[j+0] ^ blinded_share1[j+0]) & share0[j+2])
			    ^ (blind0[j+0] & blinded_share1[j+2]) ^ share0[j+2];
			auto a = ((share0[j+1] ^ blinded_share1[j+1]) & share0[j+0])
			    ^ (blind0[j+1] & blinded_share1[j+0]);

			share0[j+0] ^= c ^ gamma0[j+0];
			share0[j+1] ^= b ^ gamma0[j+1];
			share0[j+2] ^= a ^ gamma0[j+2];
		}
		return share0;
	} // substitute2_p0p1

	inline auto & substitute2_p2(randomness & rand0, randomness & rand1,
		randomness & rand2) const
	{
		sboxslices_t gamma0, gamma1;
		for (size_t i = 0, j = 0; i < sboxes; ++i, j+=3)
		{
			std::array<slicerow_t, 3> blind0, blind1, blind2;
			rand0 >> blind0;
			rand1 >> blind1;
			rand2 >> blind2;

			gamma0[j+0] = (blind0[1] & blind1[2]) ^ blind2[0];
			gamma1[j+0] = (blind0[2] & blind1[1]) ^ blind2[0];

			gamma0[j+1] = (blind0[2] & blind1[0]) ^ blind2[1];
			gamma1[j+1] = (blind0[0] & blind1[2]) ^ blind2[1];

			gamma0[j+2] = (blind0[0] & blind1[1]) ^ blind2[2];
			gamma1[j+2] = (blind0[1] & blind1[0]) ^ blind2[2];
		}
		return std::make_pair(gamma0, gamma1);
	} // substitute2_p2
 


 
 


	void populate_lut(const size_t i, const sliceblock_t & matrix,
		slicerow_t lut[8][256]) const
	{
		for (size_t k = 0; k < sizeof(uint64_t); ++k)
		{
			std::memset(&lut[k][0b00000000], 0, sizeof(slicerow_t));      //0x00
			lut[k][0b00000001] = matrix[64*i+8*k+0];                      //0x01
			lut[k][0b00000010] = matrix[64*i+8*k+1];                      //0x02
			lut[k][0b00000011] = lut[k][0b00000010] ^ lut[k][0b00000001]; //0x03
			lut[k][0b00000100] = matrix[64*i+8*k+2];                      //0x04
			lut[k][0b00000101] = lut[k][0b00000100] ^ lut[k][0b00000001]; //0x05
			lut[k][0b00000110] = lut[k][0b00000100] ^ lut[k][0b00000010]; //0x06
			lut[k][0b00000111] = lut[k][0b00000100] ^ lut[k][0b00000011]; //0x07
			lut[k][0b00001000] = matrix[64*i+8*k+3];                      //0x08
			lut[k][0b00001001] = lut[k][0b00001000] ^ lut[k][0b00000001]; //0x09
			lut[k][0b00001010] = lut[k][0b00001000] ^ lut[k][0b00000010]; //0x0a
			lut[k][0b00001011] = lut[k][0b00001000] ^ lut[k][0b00000011]; //0x0b
			lut[k][0b00001100] = lut[k][0b00001000] ^ lut[k][0b00000100]; //0x0c
			lut[k][0b00001101] = lut[k][0b00001000] ^ lut[k][0b00000101]; //0x0d
			lut[k][0b00001110] = lut[k][0b00001000] ^ lut[k][0b00000110]; //0x0e
			lut[k][0b00001111] = lut[k][0b00001000] ^ lut[k][0b00000111]; //0x0f
			lut[k][0b00010000] = matrix[64*i+8*k+4];                      //0x10
			lut[k][0b00010001] = lut[k][0b00010000] ^ lut[k][0b00000001]; //0x11
			lut[k][0b00010010] = lut[k][0b00010000] ^ lut[k][0b00000010]; //0x12
			lut[k][0b00010011] = lut[k][0b00010000] ^ lut[k][0b00000011]; //0x13
			lut[k][0b00010100] = lut[k][0b00010000] ^ lut[k][0b00000100]; //0x14
			lut[k][0b00010101] = lut[k][0b00010000] ^ lut[k][0b00000101]; //0x15
			lut[k][0b00010110] = lut[k][0b00010000] ^ lut[k][0b00000110]; //0x16
			lut[k][0b00010111] = lut[k][0b00010000] ^ lut[k][0b00000111]; //0x17
			lut[k][0b00011000] = lut[k][0b00010000] ^ lut[k][0b00001000]; //0x18
			lut[k][0b00011001] = lut[k][0b00010000] ^ lut[k][0b00001001]; //0x19
			lut[k][0b00011010] = lut[k][0b00010000] ^ lut[k][0b00001010]; //0x1a
			lut[k][0b00011011] = lut[k][0b00010000] ^ lut[k][0b00001011]; //0x1b
			lut[k][0b00011100] = lut[k][0b00010000] ^ lut[k][0b00001100]; //0x1c
			lut[k][0b00011101] = lut[k][0b00010000] ^ lut[k][0b00001101]; //0x1d
			lut[k][0b00011110] = lut[k][0b00010000] ^ lut[k][0b00001110]; //0x1e
			lut[k][0b00011111] = lut[k][0b00010000] ^ lut[k][0b00001111]; //0x1f
			lut[k][0b00100000] = matrix[64*i+8*k+5];                      //0x20
			lut[k][0b00100001] = lut[k][0b00100000] ^ lut[k][0b00000001]; //0x21
			lut[k][0b00100010] = lut[k][0b00100000] ^ lut[k][0b00000010]; //0x22
			lut[k][0b00100011] = lut[k][0b00100000] ^ lut[k][0b00000011]; //0x23
			lut[k][0b00100100] = lut[k][0b00100000] ^ lut[k][0b00000100]; //0x24
			lut[k][0b00100101] = lut[k][0b00100000] ^ lut[k][0b00000101]; //0x25
			lut[k][0b00100110] = lut[k][0b00100000] ^ lut[k][0b00000110]; //0x26
			lut[k][0b00100111] = lut[k][0b00100000] ^ lut[k][0b00000111]; //0x27
			lut[k][0b00101000] = lut[k][0b00100000] ^ lut[k][0b00001000]; //0x28
			lut[k][0b00101001] = lut[k][0b00100000] ^ lut[k][0b00001001]; //0x29
			lut[k][0b00101010] = lut[k][0b00100000] ^ lut[k][0b00001010]; //0x2a
			lut[k][0b00101011] = lut[k][0b00100000] ^ lut[k][0b00001011]; //0x2b
			lut[k][0b00101100] = lut[k][0b00100000] ^ lut[k][0b00001100]; //0x2c
			lut[k][0b00101101] = lut[k][0b00100000] ^ lut[k][0b00001101]; //0x2d
			lut[k][0b00101110] = lut[k][0b00100000] ^ lut[k][0b00001110]; //0x2e
			lut[k][0b00101111] = lut[k][0b00100000] ^ lut[k][0b00001111]; //0x2f
			lut[k][0b00110000] = lut[k][0b00100000] ^ lut[k][0b00010000]; //0x30
			lut[k][0b00110001] = lut[k][0b00100000] ^ lut[k][0b00010001]; //0x31
			lut[k][0b00110010] = lut[k][0b00100000] ^ lut[k][0b00010010]; //0x32
			lut[k][0b00110011] = lut[k][0b00100000] ^ lut[k][0b00010011]; //0x33
			lut[k][0b00110100] = lut[k][0b00100000] ^ lut[k][0b00010100]; //0x34
			lut[k][0b00110101] = lut[k][0b00100000] ^ lut[k][0b00010101]; //0x35
			lut[k][0b00110110] = lut[k][0b00100000] ^ lut[k][0b00010110]; //0x36
			lut[k][0b00110111] = lut[k][0b00100000] ^ lut[k][0b00010111]; //0x37
			lut[k][0b00111000] = lut[k][0b00100000] ^ lut[k][0b00011000]; //0x38
			lut[k][0b00111001] = lut[k][0b00100000] ^ lut[k][0b00011001]; //0x39
			lut[k][0b00111010] = lut[k][0b00100000] ^ lut[k][0b00011010]; //0x3a
			lut[k][0b00111011] = lut[k][0b00100000] ^ lut[k][0b00011011]; //0x3b
			lut[k][0b00111100] = lut[k][0b00100000] ^ lut[k][0b00011100]; //0x3c
			lut[k][0b00111101] = lut[k][0b00100000] ^ lut[k][0b00011101]; //0x3d
			lut[k][0b00111110] = lut[k][0b00100000] ^ lut[k][0b00011110]; //0x3e
			lut[k][0b00111111] = lut[k][0b00100000] ^ lut[k][0b00011111]; //0x3f
			lut[k][0b01000000] = matrix[64*i+8*k+6];                      //0x40
			lut[k][0b01000001] = lut[k][0b01000000] ^ lut[k][0b00000001]; //0x41
			lut[k][0b01000010] = lut[k][0b01000000] ^ lut[k][0b00000010]; //0x42
			lut[k][0b01000011] = lut[k][0b01000000] ^ lut[k][0b00000011]; //0x43
			lut[k][0b01000100] = lut[k][0b01000000] ^ lut[k][0b00000100]; //0x44
			lut[k][0b01000101] = lut[k][0b01000000] ^ lut[k][0b00000101]; //0x45
			lut[k][0b01000110] = lut[k][0b01000000] ^ lut[k][0b00000110]; //0x46
			lut[k][0b01000111] = lut[k][0b01000000] ^ lut[k][0b00000111]; //0x47
			lut[k][0b01001000] = lut[k][0b01000000] ^ lut[k][0b00001000]; //0x48
			lut[k][0b01001001] = lut[k][0b01000000] ^ lut[k][0b00001001]; //0x49
			lut[k][0b01001010] = lut[k][0b01000000] ^ lut[k][0b00001010]; //0x4a
			lut[k][0b01001011] = lut[k][0b01000000] ^ lut[k][0b00001011]; //0x4b
			lut[k][0b01001100] = lut[k][0b01000000] ^ lut[k][0b00001100]; //0x4c
			lut[k][0b01001101] = lut[k][0b01000000] ^ lut[k][0b00001101]; //0x4d
			lut[k][0b01001110] = lut[k][0b01000000] ^ lut[k][0b00001110]; //0x4e
			lut[k][0b01001111] = lut[k][0b01000000] ^ lut[k][0b00001111]; //0x4f
			lut[k][0b01010000] = lut[k][0b01000000] ^ lut[k][0b00010000]; //0x50
			lut[k][0b01010001] = lut[k][0b01000000] ^ lut[k][0b00010001]; //0x51
			lut[k][0b01010010] = lut[k][0b01000000] ^ lut[k][0b00010010]; //0x52
			lut[k][0b01010011] = lut[k][0b01000000] ^ lut[k][0b00010011]; //0x53
			lut[k][0b01010100] = lut[k][0b01000000] ^ lut[k][0b00010100]; //0x54
			lut[k][0b01010101] = lut[k][0b01000000] ^ lut[k][0b00010101]; //0x55
			lut[k][0b01010110] = lut[k][0b01000000] ^ lut[k][0b00010110]; //0x56
			lut[k][0b01010111] = lut[k][0b01000000] ^ lut[k][0b00010111]; //0x57
			lut[k][0b01011000] = lut[k][0b01000000] ^ lut[k][0b00011000]; //0x58
			lut[k][0b01011001] = lut[k][0b01000000] ^ lut[k][0b00011001]; //0x59
			lut[k][0b01011010] = lut[k][0b01000000] ^ lut[k][0b00011010]; //0x5a
			lut[k][0b01011011] = lut[k][0b01000000] ^ lut[k][0b00011011]; //0x5b
			lut[k][0b01011100] = lut[k][0b01000000] ^ lut[k][0b00011100]; //0x5c
			lut[k][0b01011101] = lut[k][0b01000000] ^ lut[k][0b00011101]; //0x5d
			lut[k][0b01011110] = lut[k][0b01000000] ^ lut[k][0b00011110]; //0x5e
			lut[k][0b01011111] = lut[k][0b01000000] ^ lut[k][0b00011111]; //0x5f
			lut[k][0b01100000] = lut[k][0b01000000] ^ lut[k][0b00100000]; //0x60
			lut[k][0b01100001] = lut[k][0b01000000] ^ lut[k][0b00100001]; //0x61
			lut[k][0b01100010] = lut[k][0b01000000] ^ lut[k][0b00100010]; //0x62
			lut[k][0b01100011] = lut[k][0b01000000] ^ lut[k][0b00100011]; //0x63
			lut[k][0b01100100] = lut[k][0b01000000] ^ lut[k][0b00100100]; //0x64
			lut[k][0b01100101] = lut[k][0b01000000] ^ lut[k][0b00100101]; //0x65
			lut[k][0b01100110] = lut[k][0b01000000] ^ lut[k][0b00100110]; //0x66
			lut[k][0b01100111] = lut[k][0b01000000] ^ lut[k][0b00100111]; //0x67
			lut[k][0b01101000] = lut[k][0b01000000] ^ lut[k][0b00101000]; //0x68
			lut[k][0b01101001] = lut[k][0b01000000] ^ lut[k][0b00101001]; //0x69
			lut[k][0b01101010] = lut[k][0b01000000] ^ lut[k][0b00101010]; //0x6a
			lut[k][0b01101011] = lut[k][0b01000000] ^ lut[k][0b00101011]; //0x6b
			lut[k][0b01101100] = lut[k][0b01000000] ^ lut[k][0b00101100]; //0x6c
			lut[k][0b01101101] = lut[k][0b01000000] ^ lut[k][0b00101101]; //0x6d
			lut[k][0b01101110] = lut[k][0b01000000] ^ lut[k][0b00101110]; //0x6e
			lut[k][0b01101111] = lut[k][0b01000000] ^ lut[k][0b00101111]; //0x6f
			lut[k][0b01110000] = lut[k][0b01000000] ^ lut[k][0b00110000]; //0x70
			lut[k][0b01110001] = lut[k][0b01000000] ^ lut[k][0b00110001]; //0x71
			lut[k][0b01110010] = lut[k][0b01000000] ^ lut[k][0b00110010]; //0x72
			lut[k][0b01110011] = lut[k][0b01000000] ^ lut[k][0b00110011]; //0x73
			lut[k][0b01110100] = lut[k][0b01000000] ^ lut[k][0b00110100]; //0x74
			lut[k][0b01110101] = lut[k][0b01000000] ^ lut[k][0b00110101]; //0x75
			lut[k][0b01110110] = lut[k][0b01000000] ^ lut[k][0b00110110]; //0x76
			lut[k][0b01110111] = lut[k][0b01000000] ^ lut[k][0b00110111]; //0x77
			lut[k][0b01111000] = lut[k][0b01000000] ^ lut[k][0b00111000]; //0x78
			lut[k][0b01111001] = lut[k][0b01000000] ^ lut[k][0b00111001]; //0x79
			lut[k][0b01111010] = lut[k][0b01000000] ^ lut[k][0b00111010]; //0x7a
			lut[k][0b01111011] = lut[k][0b01000000] ^ lut[k][0b00111011]; //0x7b
			lut[k][0b01111100] = lut[k][0b01000000] ^ lut[k][0b00111100]; //0x7c
			lut[k][0b01111101] = lut[k][0b01000000] ^ lut[k][0b00111101]; //0x7d
			lut[k][0b01111110] = lut[k][0b01000000] ^ lut[k][0b00111110]; //0x7e
			lut[k][0b01111111] = lut[k][0b01000000] ^ lut[k][0b00111111]; //0x7f
			lut[k][0b10000000] = matrix[64*i+8*k+7];                      //0x80
			lut[k][0b10000001] = lut[k][0b10000000] ^ lut[k][0b00000001]; //0x81
			lut[k][0b10000010] = lut[k][0b10000000] ^ lut[k][0b00000010]; //0x82
			lut[k][0b10000011] = lut[k][0b10000000] ^ lut[k][0b00000011]; //0x83
			lut[k][0b10000100] = lut[k][0b10000000] ^ lut[k][0b00000100]; //0x84
			lut[k][0b10000101] = lut[k][0b10000000] ^ lut[k][0b00000101]; //0x85
			lut[k][0b10000110] = lut[k][0b10000000] ^ lut[k][0b00000110]; //0x86
			lut[k][0b10000111] = lut[k][0b10000000] ^ lut[k][0b00000111]; //0x87
			lut[k][0b10001000] = lut[k][0b10000000] ^ lut[k][0b00001000]; //0x88
			lut[k][0b10001001] = lut[k][0b10000000] ^ lut[k][0b00001001]; //0x89
			lut[k][0b10001010] = lut[k][0b10000000] ^ lut[k][0b00001010]; //0x8a
			lut[k][0b10001011] = lut[k][0b10000000] ^ lut[k][0b00001011]; //0x8b
			lut[k][0b10001100] = lut[k][0b10000000] ^ lut[k][0b00001100]; //0x8c
			lut[k][0b10001101] = lut[k][0b10000000] ^ lut[k][0b00001101]; //0x8d
			lut[k][0b10001110] = lut[k][0b10000000] ^ lut[k][0b00001110]; //0x8e
			lut[k][0b10001111] = lut[k][0b10000000] ^ lut[k][0b00001111]; //0x8f
			lut[k][0b10010000] = lut[k][0b10000000] ^ lut[k][0b00010000]; //0x90
			lut[k][0b10010001] = lut[k][0b10000000] ^ lut[k][0b00010001]; //0x91
			lut[k][0b10010010] = lut[k][0b10000000] ^ lut[k][0b00010010]; //0x92
			lut[k][0b10010011] = lut[k][0b10000000] ^ lut[k][0b00010011]; //0x93
			lut[k][0b10010100] = lut[k][0b10000000] ^ lut[k][0b00010100]; //0x94
			lut[k][0b10010101] = lut[k][0b10000000] ^ lut[k][0b00010101]; //0x95
			lut[k][0b10010110] = lut[k][0b10000000] ^ lut[k][0b00010110]; //0x96
			lut[k][0b10010111] = lut[k][0b10000000] ^ lut[k][0b00010111]; //0x97
			lut[k][0b10011000] = lut[k][0b10000000] ^ lut[k][0b00011000]; //0x98
			lut[k][0b10011001] = lut[k][0b10000000] ^ lut[k][0b00011001]; //0x99
			lut[k][0b10011010] = lut[k][0b10000000] ^ lut[k][0b00011010]; //0x9a
			lut[k][0b10011011] = lut[k][0b10000000] ^ lut[k][0b00011011]; //0x9b
			lut[k][0b10011100] = lut[k][0b10000000] ^ lut[k][0b00011100]; //0x9c
			lut[k][0b10011101] = lut[k][0b10000000] ^ lut[k][0b00011101]; //0x9d
			lut[k][0b10011110] = lut[k][0b10000000] ^ lut[k][0b00011110]; //0x9e
			lut[k][0b10011111] = lut[k][0b10000000] ^ lut[k][0b00011111]; //0x9f
			lut[k][0b10100000] = lut[k][0b10000000] ^ lut[k][0b00100000]; //0xa0
			lut[k][0b10100001] = lut[k][0b10000000] ^ lut[k][0b00100001]; //0xa1
			lut[k][0b10100010] = lut[k][0b10000000] ^ lut[k][0b00100010]; //0xa2
			lut[k][0b10100011] = lut[k][0b10000000] ^ lut[k][0b00100011]; //0xa3
			lut[k][0b10100100] = lut[k][0b10000000] ^ lut[k][0b00100100]; //0xa4
			lut[k][0b10100101] = lut[k][0b10000000] ^ lut[k][0b00100101]; //0xa5
			lut[k][0b10100110] = lut[k][0b10000000] ^ lut[k][0b00100110]; //0xa6
			lut[k][0b10100111] = lut[k][0b10000000] ^ lut[k][0b00100111]; //0xa7
			lut[k][0b10101000] = lut[k][0b10000000] ^ lut[k][0b00101000]; //0xa8
			lut[k][0b10101001] = lut[k][0b10000000] ^ lut[k][0b00101001]; //0xa9
			lut[k][0b10101010] = lut[k][0b10000000] ^ lut[k][0b00101010]; //0xaa
			lut[k][0b10101011] = lut[k][0b10000000] ^ lut[k][0b00101011]; //0xab
			lut[k][0b10101100] = lut[k][0b10000000] ^ lut[k][0b00101100]; //0xac
			lut[k][0b10101101] = lut[k][0b10000000] ^ lut[k][0b00101101]; //0xad
			lut[k][0b10101110] = lut[k][0b10000000] ^ lut[k][0b00101110]; //0xae
			lut[k][0b10101111] = lut[k][0b10000000] ^ lut[k][0b00101111]; //0xaf
			lut[k][0b10110000] = lut[k][0b10000000] ^ lut[k][0b00110000]; //0xb0
			lut[k][0b10110001] = lut[k][0b10000000] ^ lut[k][0b00110001]; //0xb1
			lut[k][0b10110010] = lut[k][0b10000000] ^ lut[k][0b00110010]; //0xb2
			lut[k][0b10110011] = lut[k][0b10000000] ^ lut[k][0b00110011]; //0xb3
			lut[k][0b10110100] = lut[k][0b10000000] ^ lut[k][0b00110100]; //0xb4
			lut[k][0b10110101] = lut[k][0b10000000] ^ lut[k][0b00110101]; //0xb5
			lut[k][0b10110110] = lut[k][0b10000000] ^ lut[k][0b00110110]; //0xb6
			lut[k][0b10110111] = lut[k][0b10000000] ^ lut[k][0b00110111]; //0xb7
			lut[k][0b10111000] = lut[k][0b10000000] ^ lut[k][0b00111000]; //0xb8
			lut[k][0b10111001] = lut[k][0b10000000] ^ lut[k][0b00111001]; //0xb9
			lut[k][0b10111010] = lut[k][0b10000000] ^ lut[k][0b00111010]; //0xba
			lut[k][0b10111011] = lut[k][0b10000000] ^ lut[k][0b00111011]; //0xbb
			lut[k][0b10111100] = lut[k][0b10000000] ^ lut[k][0b00111100]; //0xbc
			lut[k][0b10111101] = lut[k][0b10000000] ^ lut[k][0b00111101]; //0xbd
			lut[k][0b10111110] = lut[k][0b10000000] ^ lut[k][0b00111110]; //0xbe
			lut[k][0b10111111] = lut[k][0b10000000] ^ lut[k][0b00111111]; //0xbf
			lut[k][0b11000000] = lut[k][0b10000000] ^ lut[k][0b01000000]; //0xc0
			lut[k][0b11000001] = lut[k][0b10000000] ^ lut[k][0b01000001]; //0xc1
			lut[k][0b11000010] = lut[k][0b10000000] ^ lut[k][0b01000010]; //0xc2
			lut[k][0b11000011] = lut[k][0b10000000] ^ lut[k][0b01000011]; //0xc3
			lut[k][0b11000100] = lut[k][0b10000000] ^ lut[k][0b01000100]; //0xc4
			lut[k][0b11000101] = lut[k][0b10000000] ^ lut[k][0b01000101]; //0xc5
			lut[k][0b11000110] = lut[k][0b10000000] ^ lut[k][0b01000110]; //0xc6
			lut[k][0b11000111] = lut[k][0b10000000] ^ lut[k][0b01000111]; //0xc7
			lut[k][0b11001000] = lut[k][0b10000000] ^ lut[k][0b01001000]; //0xc8
			lut[k][0b11001001] = lut[k][0b10000000] ^ lut[k][0b01001001]; //0xc9
			lut[k][0b11001010] = lut[k][0b10000000] ^ lut[k][0b01001010]; //0xca
			lut[k][0b11001011] = lut[k][0b10000000] ^ lut[k][0b01001011]; //0xcb
			lut[k][0b11001100] = lut[k][0b10000000] ^ lut[k][0b01001100]; //0xcc
			lut[k][0b11001101] = lut[k][0b10000000] ^ lut[k][0b01001101]; //0xcd
			lut[k][0b11001110] = lut[k][0b10000000] ^ lut[k][0b01001110]; //0xce
			lut[k][0b11001111] = lut[k][0b10000000] ^ lut[k][0b01001111]; //0xcf
			lut[k][0b11010000] = lut[k][0b10000000] ^ lut[k][0b01010000]; //0xd0
			lut[k][0b11010001] = lut[k][0b10000000] ^ lut[k][0b01010001]; //0xd1
			lut[k][0b11010010] = lut[k][0b10000000] ^ lut[k][0b01010010]; //0xd2
			lut[k][0b11010011] = lut[k][0b10000000] ^ lut[k][0b01010011]; //0xd3
			lut[k][0b11010100] = lut[k][0b10000000] ^ lut[k][0b01010100]; //0xd4
			lut[k][0b11010101] = lut[k][0b10000000] ^ lut[k][0b01010101]; //0xd5
			lut[k][0b11010110] = lut[k][0b10000000] ^ lut[k][0b01010110]; //0xd6
			lut[k][0b11010111] = lut[k][0b10000000] ^ lut[k][0b01010111]; //0xd7
			lut[k][0b11011000] = lut[k][0b10000000] ^ lut[k][0b01011000]; //0xd8
			lut[k][0b11011001] = lut[k][0b10000000] ^ lut[k][0b01011001]; //0xd9
			lut[k][0b11011010] = lut[k][0b10000000] ^ lut[k][0b01011010]; //0xda
			lut[k][0b11011011] = lut[k][0b10000000] ^ lut[k][0b01011011]; //0xdb
			lut[k][0b11011100] = lut[k][0b10000000] ^ lut[k][0b01011100]; //0xdc
			lut[k][0b11011101] = lut[k][0b10000000] ^ lut[k][0b01011101]; //0xdd
			lut[k][0b11011110] = lut[k][0b10000000] ^ lut[k][0b01011110]; //0xde
			lut[k][0b11011111] = lut[k][0b10000000] ^ lut[k][0b01011111]; //0xdf
			lut[k][0b11100000] = lut[k][0b10000000] ^ lut[k][0b01100000]; //0xe0
			lut[k][0b11100001] = lut[k][0b10000000] ^ lut[k][0b01100001]; //0xe1
			lut[k][0b11100010] = lut[k][0b10000000] ^ lut[k][0b01100010]; //0xe2
			lut[k][0b11100011] = lut[k][0b10000000] ^ lut[k][0b01100011]; //0xe3
			lut[k][0b11100100] = lut[k][0b10000000] ^ lut[k][0b01100100]; //0xe4
			lut[k][0b11100101] = lut[k][0b10000000] ^ lut[k][0b01100101]; //0xe5
			lut[k][0b11100110] = lut[k][0b10000000] ^ lut[k][0b01100110]; //0xe6
			lut[k][0b11100111] = lut[k][0b10000000] ^ lut[k][0b01100111]; //0xe7
			lut[k][0b11101000] = lut[k][0b10000000] ^ lut[k][0b01101000]; //0xe8
			lut[k][0b11101001] = lut[k][0b10000000] ^ lut[k][0b01101001]; //0xe9
			lut[k][0b11101010] = lut[k][0b10000000] ^ lut[k][0b01101010]; //0xea
			lut[k][0b11101011] = lut[k][0b10000000] ^ lut[k][0b01101011]; //0xeb
			lut[k][0b11101100] = lut[k][0b10000000] ^ lut[k][0b01101100]; //0xec
			lut[k][0b11101101] = lut[k][0b10000000] ^ lut[k][0b01101101]; //0xed
			lut[k][0b11101110] = lut[k][0b10000000] ^ lut[k][0b01101110]; //0xee
			lut[k][0b11101111] = lut[k][0b10000000] ^ lut[k][0b01101111]; //0xef
			lut[k][0b11110000] = lut[k][0b10000000] ^ lut[k][0b01110000]; //0xf0
			lut[k][0b11110001] = lut[k][0b10000000] ^ lut[k][0b01110001]; //0xf1
			lut[k][0b11110010] = lut[k][0b10000000] ^ lut[k][0b01110010]; //0xf2
			lut[k][0b11110011] = lut[k][0b10000000] ^ lut[k][0b01110011]; //0xf3
			lut[k][0b11110100] = lut[k][0b10000000] ^ lut[k][0b01110100]; //0xf4
			lut[k][0b11110101] = lut[k][0b10000000] ^ lut[k][0b01110101]; //0xf5
			lut[k][0b11110110] = lut[k][0b10000000] ^ lut[k][0b01110110]; //0xf6
			lut[k][0b11110111] = lut[k][0b10000000] ^ lut[k][0b01110111]; //0xf7
			lut[k][0b11111000] = lut[k][0b10000000] ^ lut[k][0b01111000]; //0xf8
			lut[k][0b11111001] = lut[k][0b10000000] ^ lut[k][0b01111001]; //0xf9
			lut[k][0b11111010] = lut[k][0b10000000] ^ lut[k][0b01111010]; //0xfa
			lut[k][0b11111011] = lut[k][0b10000000] ^ lut[k][0b01111011]; //0xfb
			lut[k][0b11111100] = lut[k][0b10000000] ^ lut[k][0b01111100]; //0xfc
			lut[k][0b11111101] = lut[k][0b10000000] ^ lut[k][0b01111101]; //0xfd
			lut[k][0b11111110] = lut[k][0b10000000] ^ lut[k][0b01111110]; //0xfe
			lut[k][0b11111111] = lut[k][0b10000000] ^ lut[k][0b01111111]; //0xff
		} // for
	} // populate_lut
	 

	inline auto sliced_set(const block_t & y) const
	{
		sliceblock_t result;
		for (size_t i = 0; i < block_len; ++i)
		{
			if constexpr(slices == 64) 
			{
			 	result[i] = y[i] ? -1 : 0;
			}
			else if constexpr(slices == 128) 
			{
			 	result[i] = y[i] ? _mm_set1_epi8(-1) : _mm_setzero_si128();
			}
			else if constexpr(slices == 256) 
			{
				result[i] = y[i] ? _mm256_set1_epi8(-1) : _mm256_setzero_si256();
			}
			else
			{

			}
		}
		return result;
	} // sliced_set

	inline auto sliced_xor(const sliceblock_t & x, const sboxslices_t & y) const
	{
		sboxslices_t result;
		for (size_t i = 0; i < 3*sboxes; ++i)
		{
			result[i] = x[i] ^ y[i];
		}
		return std::move(result);
	}
};

} // namespace lowmc

#endif // LOWMC_LOWMC_H__
