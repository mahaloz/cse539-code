#include <type_traits>
#include <set>
#include <vector>
#include <chrono> 
using namespace std::chrono; 
 
#define blocklen 128

#include "dpf.h"

#include <iostream>
using namespace dpf;

typedef bool leaf_t;
typedef __m128i node_t;
typedef __m256i node256_t;

typedef LowMC<node_t> prgkey_t;
typedef LowMC<node256_t> prgkey256_t;
#include "common.h"
int main(int argc, char * argv[])
{



prgkey_t prgkey;
prgkey256_t prgkey256;
block<node_t> s[2];


auto [dpfkey0, dpfkey1] = dpf_key<leaf_t, node_t, prgkey_t>::gen(prgkey, nitems, target, true);
auto start_evalfull = std::chrono::high_resolution_clock::now();

  leaf_t * output0 = (leaf_t *)std::aligned_alloc(sizeof(node_t), dpfkey0.full_bytes());
  dpfkey0.evalfull(output0);
 
   
  auto finish_evalfull = std::chrono::high_resolution_clock::now();
   // auto finish_sim = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double, std::milli> elapsed_evalfull = finish_evalfull - start_evalfull;

std::cout << "elapsed_evalfull = " << elapsed_evalfull.count() << std::endl;


auto start_128 = std::chrono::high_resolution_clock::now();
	 __m128i seed;
	 arc4random_buf(&seed, sizeof(__m128i));

	for(size_t j = 0; j < 100; ++j)
	{
	 PRG(prgkey, seed, s, 2);
	}

auto finish_128 = std::chrono::high_resolution_clock::now();
std::chrono::duration<double, std::milli> elapsed_128 = finish_128 - start_128;

auto start_256 = std::chrono::high_resolution_clock::now();

	 __m256i seed2;
	  arc4random_buf(&seed2, sizeof(__m256i));
	for (size_t j = 0; j < 100; ++j)
	{
	  PRG(prgkey256, seed2, s, 1);	
	}

auto finish_256 = std::chrono::high_resolution_clock::now();
std::chrono::duration<double, std::milli> elapsed_256 = finish_256 - start_256;

std::cout << "elapsed_128 = " << elapsed_128.count() << std::endl;
std::cout << "elapsed_256 = " << elapsed_256.count() << std::endl;
	// const size_t nitems = 1ULL << 10;
	// const size_t target = atoi(argv[1]);
	// const leaf_t val = 1;//_mm_set1_epi8(0x12);

	// auto [dpfkey0, dpfkey1] = dpf_key<leaf_t, node_t, prgkey_t>::gen(prgkey, nitems, target, val);
    
 //    //auto [dpfkey0, dpfkey1] = dpf_key<leaf_t, node_t, prgkey_t>::gen(prgkey, nitems, target, val, &dpf_key<leaf_t, node_t, prgkey_t>::make_shared_finalizer);
	
	// leaf_t * output0 = (leaf_t *)std::aligned_alloc(sizeof(node_t), dpfkey0.full_bytes());
	// leaf_t * output1 = (leaf_t *)std::aligned_alloc(sizeof(node_t), dpfkey1.full_bytes());

	// printf("%lu\n", dpfkey0.full_bytes() / sizeof(leaf_t));

	// dpfkey0.evalfull(output0);
	// dpfkey1.evalfull(output1);

	// for(size_t j = 0; j < nitems; ++j)
	// {	
	//     uint8_t xor_vals = 	output0[j] ^ output1[j];
	// 	if( xor_vals != 0) 
	// 	{
	// 		std::cout << j << ": " << (int)output0[j] << " ^ " << (int)output1[j] << " = " << (int) xor_vals << std::endl;
	// 	}
	// }
	// std::set<size_t> s;
	// s.insert(5);
	// s.insert(10);
	// s.insert(31337);
	// s.insert(10000);

	// auto v0 = dpfkey0.evallist(std::cbegin(s), std::cend(s));
	// auto v1 = dpfkey1.evallist(std::cbegin(s), std::cend(s));
 

	// free(output0);
	// free(output1);

	return 0;
}
