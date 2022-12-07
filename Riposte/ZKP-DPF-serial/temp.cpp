#include <cstdint>
#include <cmath>
#include <x86intrin.h>
#include <bsd/stdlib.h>
#include <vector>
#include <bits/stdc++.h> 
#include<memory.h>


struct bits
{
	
};

template <typename node_type = __m128i, typename leaf_type = bool>
struct dpf_key
{
  public:
	static constexpr size_t bits_per_leaf = std::is_same<leaf_type, bool>::value ? 1 : sizeof(leaf_type) * CHAR_BIT;
	static constexpr size_t leaves_per_mX = B ? sizeof(node_type) * CHAR_BIT / bits_per_leaf : 1;

	dpf_key(const node_type & root_, const bool root_bit_, const dpf_key<node_type, leaf_type>::cws & cw_)
	  : root(root_),
	    root_bit(root_bit_),
		cw(cw_) { }

	const node_type root;
	const bool root_bit;
	const cws cw;

	static std::pair<dpf_key<node_type, leaf_type> , dpf_key<node_type, leaf_type>>  gen(const size_t target, const leaf_type & val, const size_t nitems)
	{
		node_type roots[2];
		arc4random_buf(roots, sizeof(roots));
		auto cw = init(roots, target, val, nitems);

		return std::make_pair(dpf_key(roots[0], root_bit, cw), dpf_key(roots[1], !root_bit, cw));
	}

	struct cws
	{
	  public:
		const size_t nitems;
		const size_t depth;
		const std::vector<node_type> cws;
		const std::vector<bits> bits;
		const leaf_type final_cw;

	  private:
		cws init(node_type roots[2], bool root_bit, const size_t target, const leaf_type & val, const size_t nitems_)
		{
		  std::vector<node_type> cws_(depth); // init this
		  std::vector<bits> bits_(depth); // init this
		  leaf_type final_cw_; // init this

		  return cws(target, val, nitems_, cws_, bits_, final_cw_);
		}

		cws(const size_t target, const leaf_type & val, const size_t nitems_, std::vector<node_type> & cws_, std::vector<bits> & bits_, leaf_type & final_cw_)
		  : nitems(nitems_),
			depth(std::ceil(std::log2(std::ceil(static_cast<double>(nitems) / dpf_key<node_type, leaf_type>::leaves_per_mX)))),
			cws(cws_),
			bits(bits_),
			final_cw(final_cw_)
		{ }

		friend struct dpf_key<node_type, leaf_type>;
	};

  private:
    static constexpr bool B = (sizeof(leaf_type) <= sizeof(node_type));
    static_assert(!B || ((sizeof(node_type) * CHAR_BIT) % bits_per_leaf == 0));
};