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

	for (size_t layer = 0; layer < depth; ++layer)
	{
		auto & cw = dpfkey.cw[layer];
		uint8_t cw_t[2] = { get_lsb(cw, 0b01), get_lsb(cw, 0b10) };
		curlayer = 1-curlayer;

		size_t i=0, j=0;
		auto nextbit = (from_node >> (nbits-layer-1)) & 1;
		size_t nodes_in_prev_layer = std::ceil(static_cast<double>(nodes_in_interval) / (1ULL << (depth-layer)));
		size_t nodes_in_cur_layer = std::ceil(static_cast<double>(nodes_in_interval) / (1ULL << (depth-layer-1)));

		if (nextbit == 1) traverse(prgkey, s[1-curlayer][0], R, cw_t[R], cw, t[1-curlayer][j], s[curlayer][0], t[curlayer][0]);\
		for (i = nextbit, j = nextbit; j < nodes_in_prev_layer-1; ++j, i+=2)
		{
			traverse2(prgkey, s[1-curlayer][j], cw_t, cw, t[1-curlayer][j], &s[curlayer][i], &t[curlayer][i]);
		}
		if (nodes_in_prev_layer > j)
		{
			if (i < nodes_in_cur_layer - 1) traverse2(prgkey, s[1-curlayer][j], cw_t, cw, t[1-curlayer][j], &s[curlayer][i], &t[curlayer][i]);
			else traverse(prgkey, s[1-curlayer][j], L, cw_t[L], cw, t[1-curlayer][j], s[curlayer][i], t[curlayer][i]);
		}
	}
	finalize(prgkey, dpfkey.finalizer, output, s[0], nodes_in_interval, t[0]);
} // dpf::__evalinterval


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
static inline void traverse(const prgkey_t & prgkey, const block<node_t> & seed, const bool direction,
	const uint8_t cw_t, const block<node_t> & cw, const uint8_t prev_t,
	block<node_t> & s, uint8_t & t)
{
	dpf::PRG(prgkey, clear_lsb(seed, 0b11), &s, 1, direction);
	t = get_lsb(s) ^ (cw_t & prev_t);
	s = clear_lsb(xor_if(s, cw, !prev_t), 0b11);
} // dpf::traverse



template<typename finalizer_t, typename prgkey_t>
static inline void stretch_leaf(const prgkey_t & prgkey, const typename finalizer_t::value_type & seed, finalizer_t & s)
{
	dpf::PRG(prgkey, clear_lsb(seed, 0b11), &s, s.size());
} // dpf::stretch_leaf
template<typename finalizer_t, typename prgkey_t>
static inline void stretch_leaf(const prgkey_t & prgkey, const typename finalizer_t::value_type & seed, finalizer_t & s)
{
	dpf::PRG(prgkey, clear_lsb(seed, 0b11), &s, s.size());
} // dpf::stretch_leaf

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