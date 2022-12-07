


#include "dpf++/dpf.h"
#include "lowmc/lowmc.h"
#include <thread>
#include <iostream>
#include <deque>

#if(BLOCK_LEN == 128)
	#include "lowmc/constants_b128_r19_s32.h"
	#include "lowmc/recipe_b128_r19_s32.h"
#endif

#if(BLOCK_LEN == 256)
	#include "lowmc/constants_b256_r19_s32.h"
	#include "lowmc/recipe_b256_r19_s32.h"
#endif





#include "lowmc/streams.h"
#include "block.h"
#include <type_traits>  
#include <chrono>
using namespace std::chrono;



typedef unsigned char byte_t;


typedef std::conditional<BLOCK_LEN == 128,
                         __m128i,
                         __m256i>::type node_t;

//typedef __m128i node_t;

//typedef __m256i node_t;
 
constexpr size_t leaf_size = 2;
typedef std::array<node_t, leaf_size> leaf_t;

typedef std::conditional<NDPFS == 128,
                         __m128i,
                         __m256i>::type row_t;

typedef lowmc::lowmc<blocklen,rounds, sboxes> prgkey_t;
 

 
typedef lowmc::bitsliced_lowmc<blocklen,rounds, sboxes, ndpfs> bitsliced_prgkey_t;
 
const size_t target = 2;
leaf_t val;// =  _mm_set1_epi64x(-1);

using namespace dpf;
using LowMC = lowmc::lowmc<blocklen,rounds, sboxes>;
using bitsliced_LowMC = lowmc::bitsliced_lowmc<blocklen,rounds, sboxes, ndpfs>;
using block_t = LowMC::block_t;

using instream     = LowMC::instream;
using outstream    = LowMC::outstream;
using rewindstream =  LowMC::rewindstream;
using basicstream  = LowMC::basicstream;
 

void print_first_col(block<__m256i> * inp, size_t col = 0)
{
  for(size_t i = 0; i < nitems; ++i)
  {
  	bool x = (inp[i]).bits[col];
  	printf("%d",x);
     //std::cout << (inp[i]).bits[col];
  }
 
 	printf("\n");
   //std::cout << std::endl;
}


void print_mX(block<__m128i> inp)
{
	for(size_t i = 0; i < 128; ++i)
  {
  	bool x = inp.bits[i];
  	printf("%d",x);
     //std::cout << (inp[i]).bits[col];
  }
 
 	printf("\n");
}
void print_mX(block<__m256i> inp)
{
	for(size_t i = 0; i < 256; ++i)
  {
  	bool x = inp.bits[i];
  	printf("%d",x);
     //std::cout << (inp[i]).bits[col];
  }
 
 	printf("\n");
}

void print_first_col(std::array<block<__m256i> , 128> inp, size_t col = 0)
{
  for(size_t i = 0; i < 128; ++i)
  {
  	bool x = (inp[i]).bits[col];
  	printf("%d",x);
     //std::cout << (inp[i]).bits[col];
  }
 
 	printf("\n");
   //std::cout << std::endl;
}
 

  

int main(int argc, char * argv[])
{

   	AES_KEY aeskey;	
 	prgkey_t x;
 
 

	x.maska.shiftr(x.identity_len  - 1);
	x.maskb = x.maska >> 1;      /// mask for low-order bit in each s-box
	x.maskc = x.maska >> 2; 	/// mask for the all-but-the-highest-order bit in each s-box
	x.maskbc = x.maskb | x.maskc;
 

    bitsliced_prgkey_t bitsliced_prgkey;
	
	bitsliced_dpf_key<leaf_t, node_t, bitsliced_prgkey_t> dpf_array0;
	bitsliced_dpf_key<leaf_t, node_t, bitsliced_prgkey_t> dpf_array1;
	
	dpf_array0.nitems = nitems;
	dpf_array1.nitems = nitems;
 	

 	  auto start_gen = high_resolution_clock::now();

	  for(size_t j = 0; j < ndpfs; ++j)
   	  { 
   	    for(size_t j = 0; j < leaf_size; ++j) arc4random_buf(&val[j], sizeof(val[j]));
   	     
     	auto [dpfkey0, dpfkey1] = dpf_key<leaf_t, node_t, prgkey_t>::gen(x, nitems, target, val);
 
 	    dpf_array0.root[j] = dpfkey0.root;  	    

	     dpf_array0.cw.reserve(dpfkey0.depth());

	    for(size_t d = 0; d < dpfkey0.depth(); ++d)
	    {
	      dpf_array0.cw[d][j] = dpfkey0.cw[d];
	    }

   	     dpf_array0.finalizer[j] = dpfkey0.finalizer;
	 
	     dpf_array1.root[j] = dpfkey1.root;
   	    
   	     dpf_array1.cw.reserve(dpfkey1.depth());

   	     for(size_t d = 0; d < dpfkey1.depth(); ++d)
   	     {
   	       dpf_array1.cw[d][j] = dpfkey1.cw[d];
   	     }

	     dpf_array1.finalizer[j] = dpfkey1.finalizer;	
      }

   	auto stop_gen = high_resolution_clock::now(); 
	   	
  	size_t duration_gen = duration_cast<milliseconds>(stop_gen - start_gen).count();

 	printf("gentime =  %zu\n", duration_gen);


	size_t interval_len = nitems; 
 
 	leaf_t         * bitsliced_output0 = (leaf_t *) std::aligned_alloc(sizeof(__m256i),  nitems * sizeof(leaf_t));
	block<row_t> * flags0 = (block<row_t> *) std::aligned_alloc(sizeof(row_t), nitems * sizeof(block<row_t>));


 	// std::vector<std::thread> evaluater(ncores); 
  //  	auto start_eval_threads = high_resolution_clock::now(); 

		// for(size_t j = 0; j < ncores; ++j)
		// {		
		//   evaluater[j] = std::thread(__evalinterval_bitsliced<leaf_t, node_t, bitsliced_prgkey_t, row_t>, std::ref(aeskey), std::ref(bitsliced_prgkey),
		// 								     std::ref(dpf_array0), flags0, 0, interval_len-1, bitsliced_output0, j);
		// }

	 //    for(size_t j = 0; j < ncores; ++j)
	 //    {
	 //      evaluater[j].join();
	 //  	}

  // 	auto stop_eval_threads = high_resolution_clock::now(); 	  	
  // 	size_t duration_eval_threads = duration_cast<milliseconds>(stop_eval_threads - start_eval_threads).count();
 	// printf("evaltime_threads =  %zu\n", duration_eval_threads);



	 for(size_t j = 0; j < nitems; ++j)
	 {
	   flags0[j] = _mm256_setzero_si256(); 
	 }

	 auto start_eval = high_resolution_clock::now();
	 
	 __evalinterval_bitsliced(aeskey, bitsliced_prgkey, dpf_array0,  flags0, 0, interval_len-1, bitsliced_output0, 0);

  	 auto stop_eval = high_resolution_clock::now(); 	  	
  	 size_t duration_eval = duration_cast<milliseconds>(stop_eval - start_eval).count();
 	 printf("evaltime =  %zu\n", duration_eval);
 
 	
	// printf("\n\n\n-----------------------------------------------------\n\n\n");
	

	leaf_t  * bitsliced_output1 = (leaf_t *) std::aligned_alloc(sizeof(__m256i),  nitems * sizeof(leaf_t));
	block<row_t> * flags1 = (block<row_t> *) std::aligned_alloc(sizeof(row_t), nitems * sizeof(block<row_t>))  ;
		for(size_t j = 0; j < nitems; ++j)
	{
	  flags1[j] = _mm256_setzero_si256();
	}
	__evalinterval_bitsliced(aeskey, bitsliced_prgkey, dpf_array1, flags1, 0, interval_len-1, bitsliced_output1, 0);
  
 	for(size_t j = 0; j < 10; ++j)
 	{
 		print_mX(bitsliced_output0[j][0]);
 		printf("\n");
 		print_mX(bitsliced_output1[j][0]);
 		printf("\n\n");
 	}
 
 	

 	/*
			//This is for checking if the bitsliced encrypt is working ...
			
			std::array<block<__m256i> , 128> root_array = ___transpose(dpf_array0.root);

			
			printf("input = \n");
			print_first_col(root_array, 0);
			auto out0 = bitsliced_prgkey.encrypt(root_array);
			printf("out0 = \n");
			print_first_col(out0, 0);
			printf("\n\n\n");

			printf("input_ = \n");
		 	print_m128(dpf_array0.root[0]);

			auto out_ = x.encrypt(dpf_array0.root[0]);	
			printf("out_ = \n");
			print_m128(out_);	
	*/
	
	return 0;
}
