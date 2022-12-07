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

template<typename node_t, typename prgkey_t>
inline void PRG(const prgkey_t & prgkey, const node_t & seed, void * outbuf, const uint32_t len, const uint32_t from = 0);

} // namespace dpf
#endif // DPFPP_PRG_H
