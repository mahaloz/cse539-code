#include <chrono>
#include "dpf++/dpf.h"

inline size_t pad_to_multiple(size_t x, size_t n) { return x + n - 1 - (x - 1) % n; }

static inline uint64_t f64(uint64_t x, uint64_t y) { return y * (2 - y * x); }
static uint64_t findInverse64(uint64_t x)
{
	uint64_t y = (3 * x) ^ 2;
	y = f64(x, y);
	y = f64(x, y);
	y = f64(x, y);
	y = f64(x, y);
	return y;
}

static inline __m256i __mm256_mullo_epi64( const __m256i & a, const  __m256i&  b)
{
	__m256i bswap = _mm256_shuffle_epi32(b,0xB1); // swap H<->L
	__m256i prodlh = _mm256_mullo_epi32(a,bswap); // 32 bit L*H products
	__m256i zero = _mm256_setzero_si256(); // 0
	__m256i prodlh2 = _mm256_hadd_epi32(prodlh,zero); // a0Lb0H+a0Hb0L,a1Lb1H+a1Hb1L,0,0
	__m256i prodlh3 = _mm256_shuffle_epi32(prodlh2,0x73); // 0, a0Lb0H+a0Hb0L, 0, a1Lb1H+a1Hb1L
	__m256i prodll = _mm256_mul_epu32(a,b); // a0Lb0L,a1Lb1L, 64 bit unsigned products
	__m256i prod = _mm256_add_epi64(prodll,prodlh3); // a0Lb0L+(a0Lb0H+a0Hb0L)<<32, a1Lb1L+(a1Lb1H+a1Hb1L)<<32
	return prod;
}

static const __m256i masks[16] = {
	_mm256_set_epi64x( 0, 0, 0, 0), _mm256_set_epi64x( 0, 0, 0,-1),
	_mm256_set_epi64x( 0, 0,-1, 0), _mm256_set_epi64x( 0, 0,-1,-1),
	_mm256_set_epi64x( 0,-1, 0, 0), _mm256_set_epi64x( 0,-1, 0,-1),
	_mm256_set_epi64x( 0,-1,-1, 0), _mm256_set_epi64x( 0,-1,-1,-1),
	_mm256_set_epi64x(-1, 0, 0, 0), _mm256_set_epi64x(-1, 0, 0,-1),
	_mm256_set_epi64x(-1, 0,-1, 0), _mm256_set_epi64x(-1, 0,-1,-1),
	_mm256_set_epi64x(-1,-1, 0, 0), _mm256_set_epi64x(-1,-1, 0,-1),
	_mm256_set_epi64x(-1,-1,-1, 0), _mm256_set_epi64x(-1,-1,-1,-1)
};

auto rot(const std::vector<__m256i> & rnd, int by = 1)
{
// assume 0 < by < 4
	const uint64_t * orig = reinterpret_cast<const uint64_t*>(rnd.data());
	std::vector<__m256i> out(rnd.size());
	auto new_ = reinterpret_cast<uint64_t*>(out.data());
	std::memcpy(new_, &(orig[by]), (rnd.size()*4  - by)*sizeof(uint64_t));
	for (int i=0; i<by; ++i) out[rnd.size()-1][4-by+i] = orig[i];
	//out[rnd.size()-1][3] = orig[0];
	return out;
}

inline auto gen_rands(const AES_KEY & prgkey, const __m128i seed[2], size_t nitems)
{
	size_t len0 = pad_to_multiple(std::ceil(std::sqrt(nitems)), sizeof(__m256i)/sizeof(uint64_t));
	std::vector<__m256i> rnd0(len0);
	dpf::PRG(prgkey, seed[0], rnd0.data(), 2*len0);

	size_t len1 = pad_to_multiple(std::ceil(double(nitems) / len0), sizeof(__m256i)/sizeof(uint64_t));
	std::vector<__m256i> rnd1(len1);
	dpf::PRG(prgkey, seed[1], rnd1.data(), 2*len1);
	for (auto & x : rnd1) x = _mm256_or_si256(x, _mm256_set1_epi64x(1));

	return std::make_pair(std::move(rnd0), std::move(rnd1));
}


inline auto inverse(const std::vector<__m256i> & rnd1)
{
	size_t len1 = rnd1.size() * sizeof(__m256i) / sizeof(uint64_t);
	std::vector<uint64_t> inv1(len1);
	inv1.reserve(len1);
	const uint64_t * tmp = reinterpret_cast<const uint64_t*>(rnd1.data());
	for (size_t i = 0; i < len1; ++i) inv1.push_back(findInverse64(tmp[i]));

	return std::move(inv1);
}

inline auto sort(const std::vector<__m256i> & rnd0)
{
	size_t len0 = rnd0.size() * sizeof(__m256i) / sizeof(uint64_t);
	std::vector<uint64_t> srt0(2*len0);
	std::memcpy(srt0.data(), rnd0.data(), len0 * sizeof(uint64_t));
	for (size_t i = 0; i < len0; ++i) srt0[len0+i] = -srt0[i];
	std::sort(std::begin(srt0), std::end(srt0));

	return std::move(srt0);
}











inline uint64_t dot_prod(const std::vector<__m256i> & rnd0, const std::vector<__m256i> & rnd1, const uint8_t * buf)
{
	__m256i outer = _mm256_setzero_si256();
	for (size_t i = 0, k = 0; i < rnd1.size()/4; ++i)
	{
		__m256i inner[4] = { _mm256_setzero_si256(), _mm256_setzero_si256(), _mm256_setzero_si256(), _mm256_setzero_si256() };
		for (size_t j = 0; j < rnd0.size(); j+=4, k+=2)
		{
			inner[0] = _mm256_add_epi64(inner[0], _mm256_and_si256(rnd0[j+0], masks[buf[k+0] & 0x0f]));
			inner[1] = _mm256_add_epi64(inner[1], _mm256_and_si256(rnd0[j+1], masks[(buf[k+0] & 0xf0)>>4]));
			inner[2] = _mm256_add_epi64(inner[2], _mm256_and_si256(rnd0[j+2], masks[buf[k+1] & 0x0f]));
			inner[3] = _mm256_add_epi64(inner[3], _mm256_and_si256(rnd0[j+3], masks[(buf[k+1] & 0xf0)>>4]));
		}

		inner[0] = _mm256_add_epi64(inner[0], _mm256_bsrli_epi128(inner[0], sizeof(uint64_t))); // X * Y *
		inner[0] = _mm256_permute4x64_epi64(inner[0], _MM_SHUFFLE(0,2,0,0)); // X Y * *
		inner[0] = _mm256_and_si256(_mm256_add_epi64(inner[0], _mm256_bslli_epi128(inner[0], sizeof(uint64_t))), masks[8]); // X+Y * 

		inner[1] = _mm256_add_epi64(inner[1], _mm256_bslli_epi128(inner[1], sizeof(uint64_t))); // * X * Y
		inner[1] = _mm256_permute4x64_epi64(inner[1], _MM_SHUFFLE(3,1,0,0)); // Y X * *
		inner[1] = _mm256_and_si256(_mm256_add_epi64(inner[1], _mm256_bsrli_epi128(inner[1], sizeof(uint64_t))), masks[4]); // * X+Y * *

		inner[2] = _mm256_add_epi64(inner[2], _mm256_bsrli_epi128(inner[2], sizeof(uint64_t))); // X * Y *
		inner[2] = _mm256_permute4x64_epi64(inner[2], _MM_SHUFFLE(0,0,2,0)); // * * Y X
		inner[2] = _mm256_and_si256(_mm256_add_epi64(inner[2], _mm256_bslli_epi128(inner[2], sizeof(uint64_t))), masks[2]); // * * Y+X *

		inner[3] = _mm256_add_epi64(inner[3], _mm256_bslli_epi128(inner[3], sizeof(uint64_t))); // * X * Y
		inner[3] = _mm256_permute4x64_epi64(inner[3], _MM_SHUFFLE(0,0,1,3)); // * * X Y
		inner[3] = _mm256_and_si256(_mm256_add_epi64(inner[3], _mm256_bsrli_epi128(inner[3], sizeof(uint64_t))), masks[1]); // * * * Y+X

		__m256i in = _mm256_or_si256(inner[0], inner[1]);
		in = _mm256_or_si256(in, inner[2]);
		in = _mm256_or_si256(in, inner[3]);

		outer = _mm256_add_epi64(outer, __mm256_mullo_epi64(in, rnd1[i]));
	}

	return outer[0] + outer[1] + outer[2] + outer[3];
}

inline bool verify(uint64_t dp0, uint64_t dp1, const std::vector<uint64_t> & srt0, const std::vector<uint64_t> & inv1)
{
	auto dp = dp0-dp1;
	for (auto inv : inv1)
	{
		if (std::binary_search(std::begin(srt0), std::end(srt0), dp*inv)) return true;
//		if (std::binary_search(std::begin(srt0), std::end(srt0), -dp*inv)) return true;
	}
	return false;
}

//...
// size_t shift0 = random_between(0, sizeof(rnd0.size());
// size_t shift1 = random_between(0, sizeof(rnd1.size());
// dot_prod(rnd0_[shift0%4], rnd1_[shift1%4], q0);
 inline uint64_t dot_prod(const std::vector<__m256i> rnd0_[4], size_t shift0, const std::vector<__m256i> rnd1_[4], size_t shift1, const uint8_t * buf)
{
	auto rnd0 = rnd0_[shift0 % 4];
	shift0 -= shift0 % 4;
	auto rnd1 = rnd1_[shift1 % 4];
	shift1 -= shift1 % 4;

	__m256i outer = _mm256_setzero_si256();
	for (size_t i = 0, k = 0; i < rnd1.size()/4; ++i)
	{
		__m256i inner[4] = { _mm256_setzero_si256(), _mm256_setzero_si256(), _mm256_setzero_si256(), _mm256_setzero_si256() };
		for (size_t j = 0; j < rnd0.size(); j+=4, k+=2)
		{
			inner[0] = _mm256_add_epi64(inner[0], _mm256_and_si256(rnd0[(shift0+j+0) % rnd0.size()], masks[buf[k+0] & 0x0f]));
			inner[1] = _mm256_add_epi64(inner[1], _mm256_and_si256(rnd0[(shift0+j+1) % rnd0.size()], masks[(buf[k+0] & 0xf0)>>4]));
			inner[2] = _mm256_add_epi64(inner[2], _mm256_and_si256(rnd0[(shift0+j+2) % rnd0.size()], masks[buf[k+1] & 0x0f]));
			inner[3] = _mm256_add_epi64(inner[3], _mm256_and_si256(rnd0[(shift0+j+3) % rnd0.size()], masks[(buf[k+1] & 0xf0)>>4]));
		}

		inner[0] = _mm256_add_epi64(inner[0], _mm256_bsrli_epi128(inner[0], sizeof(uint64_t)));
		inner[0] = _mm256_permute4x64_epi64(inner[0], _MM_SHUFFLE(2,0,0,0));
		inner[1] = _mm256_add_epi64(inner[1], _mm256_bsrli_epi128(inner[1], sizeof(uint64_t)));
		inner[1] = _mm256_permute4x64_epi64(inner[1], _MM_SHUFFLE(0,0,2,0));

		inner[0] = _mm256_blendv_epi8(inner[0], inner[1], masks[3]);
		inner[0] = _mm256_add_epi64(inner[0], _mm256_bsrli_epi128(inner[0], sizeof(uint64_t)));

		inner[2] = _mm256_add_epi64(inner[2], _mm256_bsrli_epi128(inner[2], sizeof(uint64_t)));
		inner[2] = _mm256_permute4x64_epi64(inner[2], _MM_SHUFFLE(2,0,0,0));
		inner[3] = _mm256_add_epi64(inner[3], _mm256_bsrli_epi128(inner[3], sizeof(uint64_t)));
		inner[3] = _mm256_permute4x64_epi64(inner[3], _MM_SHUFFLE(0,0,2,0));

		inner[2] = _mm256_blendv_epi8(inner[2], inner[3], masks[3]);
		inner[2] = _mm256_add_epi64(inner[2], _mm256_bslli_epi128(inner[2], sizeof(uint64_t)));

		__m256i in = _mm256_blendv_epi8(inner[0], inner[2], masks[0b1010]);
		outer = _mm256_add_epi64(outer, __mm256_mullo_epi64(in, rnd1[(shift1+i) % rnd1.size()]));
	}

	return outer[0] + outer[1] + outer[2] + outer[3];
}

int main(int argc, char * argv[])
{
 

	using namespace dpf;
	using namespace std::chrono;

	constexpr size_t nitems = 1ULL << 10;

	AES_KEY prgkey;
	__m128i seeds[2];
	arc4random_buf(seeds, sizeof(seeds));

	auto [rnd0, rnd1] = gen_rands(prgkey, seeds, nitems);
	auto srt0 = sort(rnd0);
	auto inv1 = inverse(rnd1);

	uint8_t * q0 = reinterpret_cast<uint8_t*>(std::aligned_alloc(alignof(__m128i), nitems/8));
	uint8_t * q1 = reinterpret_cast<uint8_t*>(std::aligned_alloc(alignof(__m128i), nitems/8));
	uint8_t * t  = reinterpret_cast<uint8_t*>(std::aligned_alloc(alignof(__m128i), nitems));

	int verified = 0;
	duration<double> dp_time = duration<double>::zero();
	duration<double> ver_time = duration<double>::zero();

	std::vector<__m256i> rnd0_[4] = {rnd0, rot(rnd0,1), rot(rnd0,2), rot(rnd0,3)};
	std::vector<__m256i> rnd1_[4] = {rnd1, rot(rnd1,1), rot(rnd1,2), rot(rnd1,3)};

	for (int i = 0; i < 1000; ++i)
	{
		size_t shift0, shift1; 
		arc4random_buf(&shift0, sizeof(size_t));
		arc4random_buf(&shift1, sizeof(size_t));
	 
		shift0 = shift0 % rnd0.size();
		shift1 = shift1 % rnd1.size();

		size_t target = arc4random_uniform(nitems);
		auto [dpfkey0, dpfkey1] = dpf_key<bool >::gen(prgkey, nitems, target);

	 
		high_resolution_clock::time_point t1 = high_resolution_clock::now();
		dpfkey0.evalfull(reinterpret_cast<bool*>(q0), t);
		uint64_t dp0 = dot_prod(rnd0_, shift0, rnd1_, shift1, q0);;
		high_resolution_clock::time_point t2 = high_resolution_clock::now();
		dp_time += duration_cast<duration<double>>(t2 - t1);

		
		dpfkey1.evalfull(reinterpret_cast<bool*>(q1), t);
		uint64_t dp1 = dot_prod(rnd0_, shift0, rnd1_, shift1, q1);

		high_resolution_clock::time_point t3 = high_resolution_clock::now();
		auto v = verify(dp0, dp1, srt0, inv1);
		high_resolution_clock::time_point t4 = high_resolution_clock::now();
		ver_time += duration_cast<duration<double>>(t4 - t3);
 
		verified += v ? 1 : 0;
	}

	std::cout << "verified = " << verified << std::endl;
	std::cout << "dp_time = " << dp_time.count() << std::endl;
	std::cout << "ver_time = " << ver_time.count() << std::endl;
 

	free(q0);
	free(q1);
	free(t);

	return 0;
}