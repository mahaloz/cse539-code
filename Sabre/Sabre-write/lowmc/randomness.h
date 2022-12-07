/** Sabre, an anonymous bulletin board with speedier ripostes
 *  Copyright (C) 2020  Sabre authors
 *
 *  @file    randomness.h
 *  @brief   
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

#ifndef LOWMC_RANDOMNESS_H__
#define LOWMC_RANDOMNESS_H__

#include <bsd/stdlib.h>   // arc4random

#include <cstdlib>        // std::aligned_alloc, free
#include <cassert>        // assert
#include <cstring>        // std::memcpy
#include <memory>         // std::shared_ptr

#include "../dpf++/prg.h"
#include "../dpf++/prg_aes_impl.h"

namespace lowmc
{

class randomness
{
  public:
	randomness(const __m128i & seed, size_t len, const AES_KEY & key = default_aes_key)
	  : buf(std::shared_ptr<__m128i[]>(new __m128i[len/sizeof(__m128i)],
	        std::default_delete<__m128i[]>())),
	    cur(reinterpret_cast<unsigned char *>(buf.get())),
	    end(cur + len + 1)
	{
		init(key, seed, len);
	}
	randomness(size_t len, const AES_KEY & key = default_aes_key)
	  : buf(std::shared_ptr<__m128i[]>(new __m128i[len/sizeof(__m128i)],
	        std::default_delete<__m128i[]>())),
	    cur(reinterpret_cast<unsigned char *>(buf.get())),
	    end(cur + len + 1)
	{
		__m128i seed;
		arc4random_buf(&seed, sizeof(seed));
		init(key, seed, len);
	}
	randomness(randomness &&) = default;
	randomness(const randomness &) = default;
	~randomness() = default;
	inline randomness & operator=(const randomness &) = default;
	inline randomness & operator=(randomness &&) = default;

	inline randomness clone() const { return randomness(*this); }

	template <typename T>
	inline randomness & operator>>(T & val)
	{
		std::memcpy(&val, cur, sizeof(T));
		cur += sizeof(T);
		assert(cur < end);
		return *this;
	}
  private:
	inline void init(const AES_KEY & key, const __m128i & seed, size_t len)
	{
		dpf::PRG(key, seed, buf.get(), len/sizeof(__m128i));
	}

	std::shared_ptr<__m128i[]> buf;
	unsigned char * cur;
	const unsigned char * end;
}; // class randomness

} // namespace lowmc

#endif // LOWMC_RANDOMNESS_H__