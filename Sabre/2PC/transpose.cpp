#include <type_traits>
#include <set>
#include <vector>
 
#define blocklen 128
const size_t len_ = 800;  
#include <openssl/sha.h>
#include "dpf.h"
#include <iostream>
#include <assert.h>
 
#include "unrank.h"
#include <chrono> 
#include <fstream>
using namespace std::chrono; 
  
using namespace dpf;

typedef unsigned char byte_t;
typedef bool leaf_t;
typedef __m128i node_t;
typedef LowMC<node_t> prgkey_t;
typedef block<node_t> block_t;
typedef std::array<__m128i, blocklen> blockT;

typedef std::array<uint64_t, blocklen> block64_T;

 

 
  
const prgkey_t prgkey;
   
 

 
 
 
  
 
 
 

typedef __m128i node_t;
typedef LowMC<node_t> prgkey_t;

prgkey_t lowmckey;

int main(int argc, char * argv[])
{



  std::array<__m256i, 128> x_rand;
 

  AES_KEY aeskey;

const uint32_t len = 800;

auto start_aes = std::chrono::high_resolution_clock::now();
 

for(size_t r = 0; r < len; ++r)
{
		  for(size_t j = 0; j < 128; ++j)
		  {
		    __m128i seed;
		    arc4random_buf(&seed, sizeof(__m128i));
		    PRG(aeskey, seed, &x_rand[j], 2);
		  }

		  std::array<__m128i, 256> x_rand_T;
 

		 for(size_t i = 0; i < 256; ++i)
		 {
		  for(size_t j = 0; j < 128; ++j)
		  {
		  	block<__m128i>(x_rand_T[i]).bits[j] = block<__m256i>(x_rand[j]).bits[i];
		  }
		 }
}

auto finish_aes = std::chrono::high_resolution_clock::now();
std::chrono::duration<double, std::milli> elapsed_aes = finish_aes - start_aes;
std::cout << "elapsed_aes = " << elapsed_aes.count() << std::endl;



auto start_lowmc = std::chrono::high_resolution_clock::now();

blockT seeds_lowmc;

arc4random_buf(&seeds_lowmc, sizeof(blockT));
unsigned char * buf = ((unsigned char *)malloc(len * sizeof(blockT)));

PRG_parallel(lowmckey, seeds_lowmc, (__m128i *)buf, len, 0); 

auto finish_lowmc = std::chrono::high_resolution_clock::now();

std::chrono::duration<double, std::milli> elapsed_lowmc = finish_lowmc - start_lowmc;
std::cout << "elapsed_lowmc = " << elapsed_lowmc.count() << std::endl; 
 
 return 0;
}
