/* Copyright (C) 2019  Anonymous
 *
 * This is a pre-release version of the DPF++ library distributed anonymously
 * for peer review. A public release of the software will be published under the
 * LPGL v2.1 license in the near future. Please do not redistribute this version
 * of the software.
 */

#ifndef DPFPP_PRG_LOWMC_IMPL_H__
#define DPFPP_PRG_LOWMC_IMPL_H__

#include "prg.h"
#include "../lowmc.h"

using namespace lowmc;
using block_t = lowmc<>::block_t;

namespace dpf
{

template <typename lowmc>
inline void PRG(const lowmc & prgkey, const __m128i & seed, void * outbuf, const uint32_t len, const uint32_t from)
{
	block_t * outbuf128 = reinterpret_cast<block_t*>(outbuf);
	for (size_t i = 0; i < len; ++i) outbuf128[i] = seed ^ block_t(from+i);
	prgkey.encrypt(outbuf128, len);
	for (size_t i = 0; i < len; ++i) outbuf128[i] ^= (seed ^ block_t(from+i));
} // PRG<lowmc, __m128i>

template<typename lowmc>
inline std::ostream & operator<<(std::ostream & os, const lowmc & prgkey)
{
	auto zero = _mm_setzero_si128();
	return os.write(reinterpret_cast<const char *>(&zero), sizeof(__m128i));
}

} // namespace dpf

#endif // DPFPP_PRG_LOWMC_IMPL_H