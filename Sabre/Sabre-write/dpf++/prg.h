/* Copyright (C) 2019  Anonymous
 *
 * This is a pre-release version of the DPF++ library distributed anonymously
 * for peer review. A public release of the software will be published under the
 * LPGL v2.1 license in the near future. Please do not redistribute this version
 * of the software.
 */

#ifndef DPFPP_PRG_H__
#define DPFPP_PRG_H__
 
namespace dpf
{

template<typename node_t, typename lowmc>
inline void PRG(const lowmc & prgkey, const node_t & seed, void * outbuf, const uint32_t len, const uint32_t from = 0);
// template<typename row_t = __m256i, typename prgkey_t>
// inline void PRG_bit_sliced(const prgkey_t & prgkey, const std::array<row_t, 128>& seed, void * outbuf, const uint32_t len);
// const lowmc & prgkey, const __m128i & seed, void * outbuf, const uint32_t len, const uint32_t from

// inline void PRG(const lowmc & prgkey, const node_t & seed, void * outbuf, const uint32_t len, const uint32_t from = 0)
// {
// 	using block_t = typename lowmc::block_t;

// 	block_t * outbuf128 = reinterpret_cast<block_t*>(outbuf);
// 	for (size_t i = 0; i < len; ++i) outbuf128[i] = seed ^ block_t(from+i);
// 	prgkey.encrypt(outbuf128, len);
// 	for (size_t i = 0; i < len; ++i) outbuf128[i] ^= (seed ^ block_t(from+i));
// }


} // namespace dpf
#endif // DPFPP_PRG_H
