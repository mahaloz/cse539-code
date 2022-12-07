

#include <type_traits>
#include <set>
#include <vector>
#include "dpf.h"
#include <iostream>
#include <assert.h>
#include "picosha2.h"

 
using namespace dpf;
typedef unsigned char byte_t;
typedef uint16_t leaf_t;
typedef __m256i node_t;
typedef LowMC<__m256i> prgkey_t;
typedef block<node_t> block_t;


  const prgkey_t prgkey;

  const block_t mask   = prgkey.mask;
  const block_t maska  = prgkey.maska;
  const block_t maskb  = prgkey.maskb;
  const block_t maskc  = prgkey.maskc;
  const block_t maskbc = prgkey.maskbc;

  const size_t round_ =  prgkey.rounds;
  const size_t rounds =  14;


inline size_t n_sided_die (size_t n) {return (rand() % n);}


inline bool xor_if(const bool & block1, const bool & block2, bool flag)
{
  if(flag) 
  {
    return (block1 ^ block2);
  }
  else
  {
    return block1;
  }  
}

const size_t n_simulations = 128;

#include "randomness.h"
#include "transcripts.h"
#include "simulator.h"
#include "proof.h"
#include "verifier.h"
#include "verifier2.h"

template<typename T>
auto hash(T val , byte_t hashed_val[])
{
   char * chared_val = reinterpret_cast<char* >(val); 
   
   picosha2::hash256(chared_val, chared_val + sizeof(val), hashed_val, hashed_val + picosha2::k_digest_size);
   
   return hashed_val;  
}

template<typename Trancript_TYPE> 
auto hash_transcript(Trancript_TYPE view, byte_t hashed_transcript[])
{
  byte_t hashed[3][picosha2::k_digest_size];
  hash(&view.root,  hashed[0]);
  hash(&view.leaf,  hashed[1]);   
  hash(view.middle, hashed[2]);

  hash(hashed, hashed_transcript); 
}



 
int main(int argc, char * argv[])
{  
  std::cout << "rounds = " << rounds << std::endl;

  bool party0 = false; bool party1 = true;
  


  const size_t nitems = 1ULL << 44;  
  const size_t target =  atoi(argv[1]);
  const leaf_t val =  40000; //_mm256_set1_epi8(0x01);

 
  auto [dpfkey0, dpfkey1] = dpf_key<leaf_t, node_t, prgkey_t>::gen(prgkey, nitems, target, val);
  const size_t depth = dpfkey1.depth(nitems);  
 

  PB_transcript  P0_view[n_simulations]; // = (PB_transcript *) malloc(sizeof(PB_transcript) * n_simulations);
  PB_transcript  P1_view[n_simulations]; //= (PB_transcript *) malloc(sizeof(PB_transcript) * n_simulations);
 
  PB_transcript PB_other_view0;// = (PB_transcript *) malloc(sizeof(PB_transcript) * n_simulations);
  PB_transcript PB_other_view1;// = (PB_transcript *) malloc(sizeof(PB_transcript) * n_simulations);
  
  P2_transcript  P2_P0_view[n_simulations];
  P2_transcript  P2_P1_view[n_simulations];


  P2_transcript  P2_P0_view_V[n_simulations];
  P2_transcript  P2_P1_view_V[n_simulations];
  

  PB_other_view0.middle = (from_PB_middle *) std::aligned_alloc(sizeof(__m256i), sizeof(from_PB_middle) * (depth -1));
  PB_other_view1.middle = (from_PB_middle *) std::aligned_alloc(sizeof(__m256i), sizeof(from_PB_middle) * (depth -1));
  
  for(size_t i = 0; i < n_simulations; ++i)
  {
    P2_P0_view[i].middle = (from_P2_middle *) std::aligned_alloc(sizeof(__m256i), sizeof(from_P2_middle) * (depth -1));
    P2_P1_view[i].middle = (from_P2_middle *) std::aligned_alloc(sizeof(__m256i), sizeof(from_P2_middle) * (depth -1));

    P2_P0_view_V[i].middle = (from_P2_middle *) std::aligned_alloc(sizeof(__m256i), sizeof(from_P2_middle) * (depth -1));
    P2_P1_view_V[i].middle = (from_P2_middle *) std::aligned_alloc(sizeof(__m256i), sizeof(from_P2_middle) * (depth -1));

    P0_view[i].middle = (from_PB_middle *) std::aligned_alloc(sizeof(__m256i), sizeof(from_PB_middle) * (depth -1));
    P1_view[i].middle = (from_PB_middle *) std::aligned_alloc(sizeof(__m256i), sizeof(from_PB_middle) * (depth -1));
  }


  
 

  std::cout << "depth = " << depth << std::endl;
  
  std::bitset<depth> directions = ceil(target/dpfkey0.leaves_per_node);
  
  for(std::size_t i = 0; i < depth/2; ++i) 
  {
    bool t = directions[i];
    directions[i] = directions[depth-i-1];
    directions[depth-i-1] = t;
  } 
  
  std::bitset<depth>  P0direction = rand();
  std::bitset<depth>  P1direction =  P0direction ^ directions;

  std::cout << "directions = " << directions << std::endl;
   
  AES_KEY aeskey;


 

  size_t len = 100000;
  
  __m128i seed0[n_simulations], seed1[n_simulations], seed2[n_simulations];
  arc4random_buf(seed0, n_simulations * sizeof(__m128i));
  arc4random_buf(seed1, n_simulations * sizeof(__m128i));
  arc4random_buf(seed2, n_simulations * sizeof(__m128i));
 
byte_t hashed_P2_P0[n_simulations][picosha2::k_digest_size];

size_t die_roll = 5;// n_sided_die(n_simulations);

for(size_t j = 0; j < n_simulations; ++j)
{  

  Simulator sim(aeskey, seed0[j], seed1[j], seed2[j], len, depth);  
 
  for(size_t i = 0; i < depth; ++i)
  {
    sim.P0direction[i] = P0direction[i];
    sim.P1direction[i] = P1direction[i];
  }

  sim.root_layer(P0_view[j], P1_view[j], P2_P0_view[j], P2_P1_view[j], prgkey, dpfkey0, dpfkey1);
  
  for(size_t index = 1; index < depth; ++index)
  {
   sim.middle_layers(P0_view[j], P1_view[j], P2_P0_view[j], P2_P1_view[j], prgkey, dpfkey0, dpfkey1, index);
  }  

  hash_transcript(P2_P0_view[j], hashed_P2_P0[j]);
 
}




 
struct Proof
{
  PB_transcript PB_view;
 
  byte_t hash[picosha2::k_digest_size];
};
    

Proof Proof_for_V0;
 

hash_transcript(P1_view[die_roll], Proof_for_V0.hash);

FILE * outfile; 
// open file for writing 
outfile = fopen ("proof_for_V0.dat", "w"); 

fwrite (&Proof_for_V0, sizeof(struct Proof), 1, outfile); 

fclose(outfile);

std::cout << std::endl << std::endl << " --------end of simulation----------------- " << std::endl;
 


byte_t hashed_P2_V[picosha2::k_digest_size];

for(size_t j = 0; j < n_simulations; ++j)
{  

  Verifier2 ver_P2(aeskey, seed0[j], seed1[j], seed2[j], len, depth);  
 
  ver_P2.root_layer(prgkey, P2_P0_view_V[j], P2_P1_view_V[j]);
  
  for(size_t index = 1; index < depth; ++index)
  {
   ver_P2.middle_layers(prgkey, P2_P0_view_V[j], P2_P1_view_V[j], index);
  }  
 
  hash_transcript(P2_P0_view_V[j], hashed_P2_V);
 
  for(size_t d = 0; d < depth-1; ++d)
  {
    for(size_t mul = 0; mul < 4; ++mul)
     {
      assert(P2_P0_view[j].middle[d].c_bit[mul] == P2_P0_view_V[j].middle[d].c_bit[mul]);
      assert(P2_P0_view[j].middle[d].c[mul] == P2_P0_view_V[j].middle[d].c[mul]);
     }

     for(size_t r = 0; r < rounds; ++r)
     {
      assert(P2_P0_view[j].middle[d].gamma0[r] == P2_P0_view_V[j].middle[d].gamma0[r]);
      assert(P2_P0_view[j].middle[d].gamma1[r] == P2_P0_view_V[j].middle[d].gamma1[r]);
     }
  }
  assert(memcmp(hashed_P2_V , hashed_P2_P0[j] , picosha2::k_digest_size ) == 0);
}

 

 Verifier  ver0(aeskey, seed0[die_roll], len, depth);
 Verifier  ver1(aeskey, seed1[die_roll], len, depth);

 for(size_t i = 0; i < depth; ++i) ver0.Pdirection[i] = P0direction[i];
  
 ver0.root_layer(P1_view[die_roll], PB_other_view0, P2_P0_view[die_roll],   prgkey, dpfkey0, party0);
     
 for(size_t index = 1; index < depth; ++index)
 { 
  ver0.middle_layers(P2_P0_view[die_roll] , P1_view[die_roll], PB_other_view0, prgkey,   dpfkey0, index, party0);
 }


 for(size_t mul = 0; mul < 4; ++mul) 
{
  assert(P0_view[die_roll].root.L_shares_recv == PB_other_view0.root.L_shares_recv);
  assert(P0_view[die_roll].root.R_shares_recv == PB_other_view0.root.R_shares_recv);
  assert(P0_view[die_roll].root.bit_L_shares_recv == PB_other_view0.root.bit_L_shares_recv);
  assert(P0_view[die_roll].root.bit_R_shares_recv == PB_other_view0.root.bit_R_shares_recv);
  assert(P0_view[die_roll].root.blinds_recv[mul] == PB_other_view0.root.blinds_recv[mul]);
  assert(P0_view[die_roll].root.bit_blinds_recv[mul] == PB_other_view0.root.bit_blinds_recv[mul]);
  assert(P0_view[die_roll].root.next_bit_L_recv[mul] == PB_other_view0.root.next_bit_L_recv[mul]);
  assert(P0_view[die_roll].root.next_bit_R_recv[mul] == PB_other_view0.root.next_bit_R_recv[mul]);
}
// assert((memcmp(hashed0_ver, proof0.PB[j],picosha2::k_digest_size ) == 0));


for(size_t d = 0 ; d < depth-1; ++d)
{
      for(size_t r = 0; r <= rounds; ++r)
      {
       assert(P0_view[die_roll].middle[d].seed1L_encrypt[r] == PB_other_view0.middle[d].seed1L_encrypt[r]);  
       assert(P0_view[die_roll].middle[d].seed1R_encrypt[r] == PB_other_view0.middle[d].seed1R_encrypt[r]); 
       assert(P0_view[die_roll].middle[d].seed0L_encrypt[r] == PB_other_view0.middle[d].seed0L_encrypt[r]);  
       assert(P0_view[die_roll].middle[d].seed0R_encrypt[r] == PB_other_view0.middle[d].seed0R_encrypt[r]); 
      }
      
      for(size_t mul = 0; mul < 4; ++mul) 
      {
        assert(P0_view[die_roll].middle[d].blinds_recv[mul] == PB_other_view0.middle[d].blinds_recv[mul]);
        assert(P0_view[die_roll].middle[d].bit_blinds_recv[mul] == PB_other_view0.middle[d].bit_blinds_recv[mul]);
        assert(P0_view[die_roll].middle[d].next_bit_L_recv[mul] == PB_other_view0.middle[d].next_bit_L_recv[mul]);
        assert(P0_view[die_roll].middle[d].next_bit_R_recv[mul] == PB_other_view0.middle[d].next_bit_R_recv[mul]);
      }
 
 }

 assert(P0_view[die_roll].leaf.final_cw == PB_other_view0.leaf.final_cw);

 


 byte_t hashed_t0[picosha2::k_digest_size], hashed_t1[picosha2::k_digest_size];
 
 hash_transcript(P0_view[die_roll], hashed_t0);
 hash_transcript(PB_other_view0, hashed_t1);
 assert(memcmp(hashed_t0, hashed_t1, picosha2::k_digest_size ) == 0);

 std::cout << std::endl <<  "final verifier: " << std::endl;
 for (int i = 0; i < 32; i++)   printf("%x", hashed_t0[i]);
 std::cout << std::endl << "---" << std::endl;
 
 for (int i = 0; i < 32; i++)  printf("%x", hashed_t1[i]);
 std::cout << std::endl << "---" << std::endl;
 for(size_t i = 0; i < depth; ++i) ver1.Pdirection[i] = P1direction[i];


  ver1.root_layer(P0_view[die_roll], PB_other_view1, P2_P1_view[die_roll],     prgkey, dpfkey1, party1);

 
  for(size_t index = 1; index < depth; ++index)
  {  
    ver1.middle_layers(P2_P1_view[die_roll], P0_view[die_roll], PB_other_view1,   prgkey,  dpfkey1, index, party1);
  }

 hash_transcript(P1_view[die_roll], hashed_t0);
 hash_transcript(PB_other_view1, hashed_t1);
  
 assert(memcmp(hashed_t0, hashed_t1, picosha2::k_digest_size ) == 0);

 

 
 

 
 
  return 0;
}

 