/** Sabre, an anonymous bulletin board with speedier ripostes
 *  Copyright (C) 2020  Sabre authors
 *
 *  @file    streams.h
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

#ifndef LOWMC_STREAMS_H__
#define LOWMC_STREAMS_H__

#include <type_traits>   // std::conditional
#include <array>         // std::array
#include <queue>         // std::queue
#include <mutex>         // std::mutex
#include <vector>        // std::vector

#include "openssl/sha.h" // OpenSSL's SHA256 implementation

#include "transposition.h"

namespace lowmc
{

namespace streams
{

template <typename block_t>
class input_stream
{
  public:
	input_stream() = default;
	input_stream(const input_stream &) = delete;
	~input_stream() = default;

	input_stream & operator=(const input_stream &) = delete;
	input_stream & operator=(input_stream &&) = default;

	virtual input_stream & operator>>(block_t & val) = 0;
}; // class lowmc::input_stream

template <typename block_t, size_t slices = 1>
class output_stream
{
  public:
	output_stream()
	{
		for (size_t i = 0; i < slices; ++i)
		{
			if (!SHA256_Init(&contexts[i])) { /*gah!*/ }
		}
	}
	output_stream(const output_stream &) = delete;
	~output_stream() = default;

	output_stream & operator=(const output_stream &) = delete;
	output_stream & operator=(output_stream &&) = default;

	output_stream & operator<<(const block_t & val)
	{
		auto transposed = transpose(val);
		for (size_t i = 0; i < slices; ++i)
		{
			if (!SHA256_Update(&contexts[i], &transposed[i],
				sizeof(transposed[i]))) { /*gah!*/ }
		}
		handle_read(val);
		return *this;
	}

	inline __m256i sha256_digest(size_t i = 0)
	{
		__m256i hash;
		// TODO: check return value; "invalidate" this stream
		SHA256_Final(reinterpret_cast<unsigned char*>(&hash), &contexts[i]);
		return hash;
	}

  protected:
	virtual void handle_read(const block_t & val) {  }

  private:
	SHA256_CTX contexts[slices];
}; // class lowmc::output_stream

template <typename block_t, size_t slices = 1>
class bidirectional_stream : public input_stream<block_t>, public output_stream<block_t, slices>
{
  public:
	bidirectional_stream() = default;
	bidirectional_stream(const bidirectional_stream &) = delete;
	~bidirectional_stream() = default;

	bidirectional_stream & operator=(const bidirectional_stream &) = delete;
	bidirectional_stream & operator=(bidirectional_stream &&) = default;
}; // class lowmc::bidirectional_stream

template <typename block_t, size_t slices = 1>
class basic_stream : public bidirectional_stream<block_t, slices>
{
  public:
	basic_stream() = default;
	basic_stream(const basic_stream &) = delete;
	basic_stream(basic_stream &&) = default;
	~basic_stream() = default;

	inline basic_stream & operator=(const basic_stream &) = delete;
	inline basic_stream & operator=(basic_stream &&) = default;

	inline basic_stream & operator>>(block_t & val) override
	{
		while (buffer.empty()) std::this_thread::yield();
		const std::lock_guard<std::mutex> lock(mutex);
		val = buffer.front();
		buffer.pop();
		return *this;
	}

  protected:
	inline void handle_read(const block_t & val) override
	{
		const std::lock_guard<std::mutex> lock(mutex);
		buffer.push(val);
	}

  private:
	std::queue<block_t> buffer;
	std::mutex mutex;
}; // class lowmc::basic_stream

template <typename block_t, size_t slices = 1>
class rewindable_stream : public bidirectional_stream<block_t, slices>
{
  public:
	rewindable_stream() : cur(0) { }
	rewindable_stream(const rewindable_stream &) = delete;
	rewindable_stream(rewindable_stream &&) = default;
	~rewindable_stream() = default;

	inline rewindable_stream & operator=(const rewindable_stream &) = delete;
	inline rewindable_stream & operator=(rewindable_stream &&) = default;

	inline rewindable_stream & rewind(size_t to = 0) { cur = to; return *this; }
	inline rewindable_stream & operator>>(block_t & val) override
	{
		while (cur >= buffer.size()) std::this_thread::yield();
		const std::lock_guard<std::mutex> lock(mutex);
		val = buffer[cur++];
		return *this;
	}

  protected:
	inline void handle_read(const block_t & val) override
	{
		const std::lock_guard<std::mutex> lock(mutex);
		buffer.push_back(val);
	}

  private:
	std::vector<block_t> buffer;
	std::mutex mutex;
	size_t cur;
}; // class lowmc::rewindable_stream

} // namespace lowmc::streams

} // namespace lowmc

#endif // LOWMC_STREAMS_H__
