

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
typedef LowMC<node_t> prgkey_t;
typedef block<node_t> block_t;



 
 
 


  const prgkey_t prgkey;

  const block_t mask   = prgkey.mask;
  const block_t maska  = prgkey.maska;
 
  const block_t maskb  = prgkey.maskb;
  const block_t maskc  = prgkey.maskc;
  const block_t maskbc = prgkey.maskbc;
  

  const block_t maska_  = prgkey.mask;
  const block_t maskb_  = maska_ >> 1;
  const block_t maskc_  = maska_ >> 2;
  const block_t maskbc_ = maskb_ | maskc_;
  
  const size_t rounds     =  prgkey.rounds;
  const size_t numofboxes =  prgkey.numofboxes;
  const size_t nboxbits = 3 * numofboxes;

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

template<typename Trancript_TYPE> 
auto hash_transcript(Trancript_TYPE view0, Trancript_TYPE view1, byte_t hashed_transcript[])
{
  byte_t hashed[6][picosha2::k_digest_size];
  hash(&view0.root,  hashed[0]);
  hash(&view0.leaf,  hashed[1]);   
  hash(view0.middle, hashed[2]);
  
  hash(&view1.root,  hashed[3]);
  hash(&view1.leaf,  hashed[4]);   
  hash(view1.middle, hashed[5]);

  hash(hashed, hashed_transcript); 
}

std::bitset<n_simulations> roll_the_dice(byte_t root[picosha2::k_digest_size])
{

  std::bitset<n_simulations> die_rolls;

  for(int i = 0; i < (n_simulations/CHAR_BIT); ++i)
  {
    unsigned char cur = root[i];
    
    int offset = i * CHAR_BIT;

    for(int bit = 0; bit < CHAR_BIT; ++bit)
    {
        die_rolls[offset] = cur & 1;
        ++offset;   // Move to next bit in b
        cur >>= 1;  // Move to next bit in array
    }
  }

  return die_rolls;

}
 
auto generate_proof(PB_transcript P0_view[], PB_transcript P1_view[], P2_transcript P2_P0_view[], P2_transcript P2_P1_view[], 
                    Proof_leaves_PB * proof_PB_0, Proof_leaves_PB * proof_PB_1,  Proof_leaves_P2 * proof_P2_0,  Proof_leaves_P2 * proof_P2_1)
{

}


int main(int argc, char * argv[])
{






  std::cout << "rounds = " << rounds << std::endl;

  bool party0 = false; bool party1 = true;
  
  std::cout << "prgkey_t " << prgkey.maska.bits << std::endl;

  const size_t nitems = 1ULL << 40;  
  const size_t target =  atoi(argv[1]);
  const leaf_t val =  40; //_mm256_set1_epi8(0x01);

 
  auto [dpfkey0, dpfkey1] = dpf_key<leaf_t, node_t, prgkey_t>::gen(prgkey, nitems, target, val);
  const size_t depth = dpfkey1.depth(nitems);  
    block<node_t> child[2];

  uint8_t t_old[2];
  __m128i t_new[2];

  expand(prgkey, dpfkey0.root, child, t_old);
  
  block<node_t> child2[2];

  expand(prgkey, dpfkey1.root, child2, t_old);
  
  std::cout << "PRG-old: ";
 // for(size_t j = 0; j < 256; ++j)
  {
   std::cout << (child[R] ^ child2[R]).bits;
  } 
  std::cout << std::endl << " ---- " << std::endl;
  //for(size_t j = 0; j < 256; ++j)
  {
   std::cout << (child[L] ^ child2[L]).bits;
  } 
  std::cout << std::endl << " ---- " << std::endl;
  std::cout << "cw: " << dpfkey0.cw[0].bits << std::endl;


  PB_transcript  P0_view[n_simulations];  
  PB_transcript  P1_view[n_simulations];  

  PB_transcript PB_other_view0; 
  PB_transcript PB_other_view1; 
  
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

  const size_t n_sub_bits = 3 * numofboxes * n_simulations * (rounds) * (depth-1) * 2;
  size_t n_256 =  std::ceil(static_cast<double>(n_sub_bits)/255) + 1;
  std::cout << "n_sub_bits = " << n_sub_bits << std::endl;
  std::cout << "n_256    = " << n_256 << std::endl;
  

  node_t * blinds0 =  (node_t *) std::aligned_alloc(sizeof(__m256i),sizeof(node_t) * n_256 ) ;
  node_t * blinds1 =  (node_t *) std::aligned_alloc(sizeof(__m256i),sizeof(node_t) * n_256) ;
  node_t * rand_ =  (node_t *) std::aligned_alloc(sizeof(__m256i),sizeof(node_t) * n_256) ;
  
  PRG(aeskey, seed0[0], (node_t *) blinds0, n_256);
  PRG(aeskey, seed1[0], (node_t *) blinds1, n_256);
  PRG(aeskey, seed2[0], (node_t *) rand_, n_256);
  
  block_t * gamma0 = (block_t *) std::aligned_alloc(sizeof(__m256i), sizeof(block_t) * n_256);
  block_t * gamma1 = (block_t *) std::aligned_alloc(sizeof(__m256i), sizeof(block_t) * n_256);
  block_t * blind0 = (block_t *) std::aligned_alloc(sizeof(__m256i), sizeof(block_t) * n_256);
  block_t * blind1 = (block_t *) std::aligned_alloc(sizeof(__m256i), sizeof(block_t) * n_256);
  block_t * rand   = (block_t *) std::aligned_alloc(sizeof(__m256i), sizeof(block_t) * n_256);

  


  for (unsigned r = 0; r <= n_256; ++r)
  {
    blind0[r] = blinds0[r];
    blind1[r] = blinds1[r];
    rand[r]   = rand_[r];

    const block_t tmp1 = ((blind0[r] >> 1) & blind1[r]) ^ ((blind1[r] >> 1) & blind0[r]);
    const block_t tmp2 = ((blind0[r] >> 2) & blind1[r]) ^ ((blind1[r] >> 2) & blind0[r]);

    const block_t bc = (tmp1 << 2) & maska_;
    const block_t ac = (tmp2 << 1) & maskb_;
    const block_t ab = (tmp1 >> 1) & maskc_;

    gamma0[r] = ((bc | ac | ab) ^ rand[r]) ;
    gamma1[r] = (rand[r] );
  }

 
 
block_t * gamma0_ = (block_t *) std::aligned_alloc(sizeof(__m256i), sizeof(block_t) * (85 * n_256)); // compressed
block_t * gamma1_ = (block_t *) std::aligned_alloc(sizeof(__m256i), sizeof(block_t) * (85 * n_256)); // compressed
block_t * blind0_ = (block_t *) std::aligned_alloc(sizeof(__m256i), sizeof(block_t) * (85 * n_256)); // compressed
block_t * blind1_ = (block_t *) std::aligned_alloc(sizeof(__m256i), sizeof(block_t) * (85 * n_256)); // compressed


decompress_transcript(gamma0_, gamma1_, blind0_, blind1_, gamma0, gamma1, blind0, blind1, n_256);



size_t t = 0;

  for(size_t i = 0; i < n_simulations; ++i)
  {
    for(size_t d = 0; d < depth-1; ++d)
    {
      for(size_t r = 0; r < rounds; ++r )
      {
        P2_P0_view[i].middle[d].blindL[r] = blind0_[t];
        P2_P1_view[i].middle[d].blindL[r] = blind1_[t];
        P2_P0_view[i].middle[d].gamma0[r] = gamma0_[t];
        P2_P1_view[i].middle[d].gamma0[r] = gamma1_[t];

        ++t;

        P2_P0_view[i].middle[d].blindR[r] = blind0_[t];
        P2_P1_view[i].middle[d].blindR[r] = blind1_[t];
        P2_P0_view[i].middle[d].gamma1[r] = gamma0_[t];
        P2_P1_view[i].middle[d].gamma1[r] = gamma1_[t];
        ++t;
      }
    }
  }


  byte_t hashed_P2[n_simulations][picosha2::k_digest_size];
  byte_t hashed_P0[n_simulations][picosha2::k_digest_size];
  byte_t hashed_P1[n_simulations][picosha2::k_digest_size];

 

byte_t hash_array[n_simulations][picosha2::k_digest_size];

for(size_t j = 0; j < n_simulations; ++j)
{  
  std::cout << "SIMULATION RUN: " << j << std::endl;
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
 
}
size_t die_roll =  n_sided_die(n_simulations);

 

byte_t PB_hashes[2][picosha2::k_digest_size];


byte_t P2_PB_hash[n_simulations][2][picosha2::k_digest_size];
for(size_t j = 0; j < n_simulations; ++j)
{
  
  hash_transcript(P2_P0_view[j], P2_P1_view[j], hashed_P2[j]);  
  hash_transcript(P0_view[j], hashed_P0[j]);
  hash_transcript(P1_view[j], hashed_P1[j]);

 

  hash_transcript(P2_P0_view[j], P2_P1_view[j], P2_PB_hash[j][0]);
  hash_transcript(P0_view[j], PB_hashes[0]);
  hash_transcript(P1_view[j], PB_hashes[1]);
  hash(PB_hashes, P2_PB_hash[j][1]);
  hash(P2_PB_hash[j], hash_array[j]);
}

Proof Proof_for_V0, Proof_for_V1;



hash(hash_array, Proof_for_V0.root);
hash(hash_array, Proof_for_V1.root);
 
std::bitset<16 * CHAR_BIT> die_rolls = roll_the_dice(Proof_for_V0.root);

 

size_t parity = die_rolls.count();

std::cout << "parity = " << parity << std::endl;
std::cout << "n_simulations - parity = " << n_simulations - parity << std::endl;

Proof_leaves_PB * proof_PB_0 = (Proof_leaves_PB *) std::aligned_alloc(sizeof(__m256i), parity * sizeof(Proof_leaves_PB));
Proof_leaves_P2 * proof_P2_0 = (Proof_leaves_P2 *) std::aligned_alloc(sizeof(__m256i), (n_simulations - parity) * sizeof(Proof_leaves_PB));
Proof_leaves_PB * proof_PB_1 = (Proof_leaves_PB *) std::aligned_alloc(sizeof(__m256i), parity * sizeof(Proof_leaves_PB));
Proof_leaves_P2 * proof_P2_1 = (Proof_leaves_P2 *) std::aligned_alloc(sizeof(__m256i), (n_simulations - parity) * sizeof(Proof_leaves_PB));

 
  

size_t nP2s = 0;
size_t nPBs = 0;

for(size_t j = 0; j < n_simulations; ++j)
{
  if(die_rolls[j])
  {
   
    for(size_t t = 0; t < picosha2::k_digest_size; ++t) proof_PB_0[nPBs].P2_hash[t] = P2_PB_hash[j][0][t];
     proof_PB_0[nPBs].PB_view = P1_view[j];
     proof_PB_0[nPBs].P2_view = P2_P0_view[j];
     proof_PB_1[nPBs].PB_view = P0_view[j];
     proof_PB_1[nPBs].P2_view = P2_P1_view[j];
     ++nPBs;

  }
  else
  {
    for(size_t t = 0; t < picosha2::k_digest_size; ++t) 
    {
      proof_P2_0[nP2s].PB_hash[t] = P2_PB_hash[j][1][t];
      proof_P2_1[nP2s].PB_hash[t] = P2_PB_hash[j][1][t];
    }
    ++nP2s; 
  }

}




 
std::cout << "size of one PB transcript: " << sizeof(from_PB_middle) + sizeof(from_PB_root) + sizeof(from_PB_leaf) << std::endl;
std::cout << "size of one P2 transcript: " << sizeof(from_P2_middle) + sizeof(from_P2_root) + sizeof(from_P2_leaf) << std::endl;
 
size_t PB_proof_size = (depth - 1) * (sizeof(from_PB_middle)) + sizeof(from_PB_root) + sizeof(from_PB_leaf);
size_t P2_proof_size = (depth - 1) * (sizeof(from_P2_middle)) + sizeof(from_P2_root) + sizeof(from_P2_leaf);
std::cout << "proof size: " << (sizeof(Proof_for_V0) + (PB_proof_size * nPBs) + (P2_proof_size * nP2s))/1000000 << " MB "  << std::endl;

 
std::cout << std::endl << std::endl << " --------end of simulation----------------- " << std::endl;
 

 
byte_t hashed_P2_V[n_simulations][picosha2::k_digest_size];

byte_t hash_array_V[n_simulations][picosha2::k_digest_size];
byte_t hash_array_V1[n_simulations][picosha2::k_digest_size]; 

nP2s = 0;
byte_t hashed_P2_PB[2][picosha2::k_digest_size];
for(size_t j = 0; j < n_simulations; ++j)
{  

  //if(die_rolls[j]) continue;


  Verifier2 ver_P2(aeskey, seed0[j], seed1[j], seed2[j], len, depth);  
 
  ver_P2.root_layer(prgkey, P2_P0_view_V[j], P2_P1_view_V[j]);
  
  for(size_t index = 1; index < depth; ++index)
  {
   ver_P2.middle_layers(prgkey, P2_P0_view_V[j], P2_P1_view_V[j], index);
  }  
  
 if(!die_rolls[j])
 {
  hash_transcript(P2_P0_view_V[j], P2_P1_view_V[j], hashed_P2_PB[0]);
  for(size_t t = 0; t < picosha2::k_digest_size; ++t) hashed_P2_PB[1][t] = proof_P2_0[nP2s].PB_hash[t];
  hash(hashed_P2_PB, hash_array_V[j]); 
  hash(hashed_P2_PB, hash_array_V1[j]);

  //assert(memcmp(proof_PB_0[nP2s].P2_hash, hashed_P2_V[j] , picosha2::k_digest_size ) == 0);
  //assert(memcmp(hashed_P2_V[j] , hashed_P2[j] , picosha2::k_digest_size ) == 0);
  ++nP2s;
 }
}
 

 nPBs = 0; 
for(size_t j = 0; j < n_simulations; ++j)
{
  if(!die_rolls[j]) continue;
  for(size_t mul = 0; mul < 4; ++mul)
  {
    assert(P2_P0_view_V[j].root.c[mul] == proof_PB_0[nPBs].P2_view.root.c[mul]);
    assert(P2_P1_view_V[j].root.c[mul] == proof_PB_1[nPBs].P2_view.root.c[mul]);
    assert(P2_P0_view_V[j].root.c_bit[mul] == proof_PB_0[nPBs].P2_view.root.c_bit[mul]);
    assert(P2_P1_view_V[j].root.c_bit[mul] == proof_PB_1[nPBs].P2_view.root.c_bit[mul]);
  }


  for(size_t d = 0; d < depth-1; ++d)
  {
    for(size_t mul = 0; mul < 4; ++mul)
    {
      assert(P2_P0_view_V[j].middle[d].c[mul] == proof_PB_0[nPBs].P2_view.middle[d].c[mul]);
      assert(P2_P1_view_V[j].middle[d].c[mul] == proof_PB_1[nPBs].P2_view.middle[d].c[mul]);
      assert(P2_P0_view_V[j].middle[d].c_bit[mul] == proof_PB_0[nPBs].P2_view.middle[d].c_bit[mul]);
      assert(P2_P1_view_V[j].middle[d].c_bit[mul] == proof_PB_1[nPBs].P2_view.middle[d].c_bit[mul]);
    }

    for(size_t r = 0; r < rounds; ++r)
    {
      assert(P2_P0_view_V[j].middle[d].gamma0[r] == proof_PB_0[nPBs].P2_view.middle[d].gamma0[r]);
      assert(P2_P1_view_V[j].middle[d].gamma0[r] == proof_PB_1[nPBs].P2_view.middle[d].gamma0[r]);
      assert(P2_P0_view_V[j].middle[d].gamma1[r] == proof_PB_0[nPBs].P2_view.middle[d].gamma1[r]);
      assert(P2_P1_view_V[j].middle[d].gamma1[r] == proof_PB_1[nPBs].P2_view.middle[d].gamma1[r]);
    }
  }
  ++nPBs;
}
 

  nPBs = 0;
 for(size_t j = 0; j < n_simulations; ++j)
 {

   if(!die_rolls[j]) continue;

   Verifier  ver0(aeskey, seed0[j], len, depth);
  
   for(size_t i = 0; i < depth; ++i) ver0.Pdirection[i] = P0direction[i];
   
   ver0.root_layer(proof_PB_0[nPBs].PB_view, PB_other_view0, proof_PB_0[nPBs].P2_view,   prgkey, dpfkey0, party0); 
   //ver0.root_layer(P1_view[j], PB_other_view0, P2_P0_view[j],   prgkey, dpfkey0, party0);
       
   for(size_t index = 1; index < depth; ++index)
   { 
    ver0.middle_layers(proof_PB_0[nPBs].P2_view, proof_PB_0[nPBs].PB_view, PB_other_view0, prgkey,   dpfkey0, index, party0);
    //ver0.middle_layers(P2_P0_view[j] , P1_view[j], PB_other_view0, prgkey,   dpfkey0, index, party0);
   }

   byte_t PB_hashes[2][picosha2::k_digest_size];
   hash_transcript(PB_other_view0, PB_hashes[0]);
   hash_transcript(proof_PB_0[nPBs].PB_view, PB_hashes[1]);
   hash(PB_hashes, hashed_P2_PB[1]);
   for(size_t t = 0; t < picosha2::k_digest_size; ++t)
   {
     hashed_P2_PB[0][t] = proof_PB_0[nPBs].P2_hash[t];
   }

   hash(hashed_P2_PB, hash_array_V[j]); 


      for(size_t mul = 0; mul < 4; ++mul) 
{
  assert(proof_PB_1[nPBs].PB_view.root.L_shares_recv == PB_other_view0.root.L_shares_recv);
  assert(proof_PB_1[nPBs].PB_view.root.R_shares_recv == PB_other_view0.root.R_shares_recv);
  assert(proof_PB_1[nPBs].PB_view.root.bit_L_shares_recv == PB_other_view0.root.bit_L_shares_recv);
  assert(proof_PB_1[nPBs].PB_view.root.bit_R_shares_recv == PB_other_view0.root.bit_R_shares_recv);
  assert(proof_PB_1[nPBs].PB_view.root.blinds_recv[mul] == PB_other_view0.root.blinds_recv[mul]);
  assert(proof_PB_1[nPBs].PB_view.root.bit_blinds_recv[mul] == PB_other_view0.root.bit_blinds_recv[mul]);
  assert(proof_PB_1[nPBs].PB_view.root.next_bit_L_recv[mul] == PB_other_view0.root.next_bit_L_recv[mul]);
  assert(proof_PB_1[nPBs].PB_view.root.next_bit_R_recv[mul] == PB_other_view0.root.next_bit_R_recv[mul]);
}

for(size_t d = 0 ; d < depth-1; ++d)
{
      for(size_t r = 0; r <= rounds; ++r)
      {
       assert(proof_PB_1[nPBs].PB_view.middle[d].seed1L_encrypt[r] == PB_other_view0.middle[d].seed1L_encrypt[r]);  
       assert(proof_PB_1[nPBs].PB_view.middle[d].seed1R_encrypt[r] == PB_other_view0.middle[d].seed1R_encrypt[r]); 
       assert(proof_PB_1[nPBs].PB_view.middle[d].seed0L_encrypt[r] == PB_other_view0.middle[d].seed0L_encrypt[r]);  
       assert(proof_PB_1[nPBs].PB_view.middle[d].seed0R_encrypt[r] == PB_other_view0.middle[d].seed0R_encrypt[r]); 
      }
      
      for(size_t mul = 0; mul < 4; ++mul) 
      {
        assert(proof_PB_1[nPBs].PB_view.middle[d].blinds_recv[mul] == PB_other_view0.middle[d].blinds_recv[mul]);
        assert(proof_PB_1[nPBs].PB_view.middle[d].bit_blinds_recv[mul] == PB_other_view0.middle[d].bit_blinds_recv[mul]);
        assert(proof_PB_1[nPBs].PB_view.middle[d].next_bit_L_recv[mul] == PB_other_view0.middle[d].next_bit_L_recv[mul]);
        assert(proof_PB_1[nPBs].PB_view.middle[d].next_bit_R_recv[mul] == PB_other_view0.middle[d].next_bit_R_recv[mul]);
      }
 
 }
 assert(proof_PB_1[nPBs].PB_view.leaf.final_cw == PB_other_view0.leaf.final_cw);
   ++nPBs;
 }

byte_t verifier0_root[picosha2::k_digest_size];

hash(hash_array_V, verifier0_root);
std::cout << std::endl <<  "FINAL HASH: " << std::endl;
for (int i = 0; i < 32; i++)   printf("%x", Proof_for_V0.root[i]);
std::cout << std::endl << "---" << std::endl;
std::cout << std::endl <<  "FINAL HASH: " << std::endl;
for (int i = 0; i < 32; i++)   printf("%x", verifier0_root[i]);
std::cout << std::endl << "---" << std::endl;


nPBs = 0;
for(size_t j = 0; j < n_simulations; ++j)
{
  if(!die_rolls[j]) continue;
  Verifier  ver1(aeskey, seed1[j], len, depth);
 
   for(size_t i = 0; i < depth; ++i) ver1.Pdirection[i] = P1direction[i];
  
   ver1.root_layer(proof_PB_1[nPBs].PB_view, PB_other_view1, proof_PB_1[nPBs].P2_view, prgkey, dpfkey1, party1);

  // ver1.root_layer(P0_view[die_roll], PB_other_view1, P2_P1_view[die_roll], prgkey, dpfkey1, party1);

   for(size_t index = 1; index < depth; ++index)
   { 
     ver1.middle_layers(proof_PB_1[nPBs].P2_view, proof_PB_1[nPBs].PB_view, PB_other_view1, prgkey, dpfkey1, index, party1); 
  //   ver1.middle_layers(P2_P1_view[die_roll], P0_view[die_roll], PB_other_view1, prgkey, dpfkey1, index, party1);
   }
   byte_t PB_hashes[2][picosha2::k_digest_size];
   hash_transcript(PB_other_view1, PB_hashes[1]);
   hash_transcript(proof_PB_1[nPBs].PB_view, PB_hashes[0]);
   hash(PB_hashes, hashed_P2_PB[1]);
   for(size_t t = 0; t < picosha2::k_digest_size; ++t)
   {
     hashed_P2_PB[0][t] = proof_PB_1[nPBs].P2_hash[t];
   }

   hash(hashed_P2_PB, hash_array_V1[j]); 


      for(size_t mul = 0; mul < 4; ++mul) 
{
  assert(proof_PB_0[nPBs].PB_view.root.L_shares_recv == PB_other_view1.root.L_shares_recv);
  assert(proof_PB_0[nPBs].PB_view.root.R_shares_recv == PB_other_view1.root.R_shares_recv);
  assert(proof_PB_0[nPBs].PB_view.root.bit_L_shares_recv == PB_other_view1.root.bit_L_shares_recv);
  assert(proof_PB_0[nPBs].PB_view.root.bit_R_shares_recv == PB_other_view1.root.bit_R_shares_recv);
  assert(proof_PB_0[nPBs].PB_view.root.blinds_recv[mul] == PB_other_view1.root.blinds_recv[mul]);
  assert(proof_PB_0[nPBs].PB_view.root.bit_blinds_recv[mul] == PB_other_view1.root.bit_blinds_recv[mul]);
  assert(proof_PB_0[nPBs].PB_view.root.next_bit_L_recv[mul] == PB_other_view1.root.next_bit_L_recv[mul]);
  assert(proof_PB_0[nPBs].PB_view.root.next_bit_R_recv[mul] == PB_other_view1.root.next_bit_R_recv[mul]);
}

for(size_t d = 0 ; d < depth-1; ++d)
{
      for(size_t r = 0; r <= rounds; ++r)
      {
       assert(proof_PB_0[nPBs].PB_view.middle[d].seed1L_encrypt[r] == PB_other_view1.middle[d].seed1L_encrypt[r]);  
       assert(proof_PB_0[nPBs].PB_view.middle[d].seed1R_encrypt[r] == PB_other_view1.middle[d].seed1R_encrypt[r]); 
       assert(proof_PB_0[nPBs].PB_view.middle[d].seed0L_encrypt[r] == PB_other_view1.middle[d].seed0L_encrypt[r]);  
       assert(proof_PB_0[nPBs].PB_view.middle[d].seed0R_encrypt[r] == PB_other_view1.middle[d].seed0R_encrypt[r]); 
      }
      
      for(size_t mul = 0; mul < 4; ++mul) 
      {
        assert(proof_PB_0[nPBs].PB_view.middle[d].blinds_recv[mul] == PB_other_view1.middle[d].blinds_recv[mul]);
        assert(proof_PB_0[nPBs].PB_view.middle[d].bit_blinds_recv[mul] == PB_other_view1.middle[d].bit_blinds_recv[mul]);
        assert(proof_PB_0[nPBs].PB_view.middle[d].next_bit_L_recv[mul] == PB_other_view1.middle[d].next_bit_L_recv[mul]);
        assert(proof_PB_0[nPBs].PB_view.middle[d].next_bit_R_recv[mul] == PB_other_view1.middle[d].next_bit_R_recv[mul]);
      }
 
 }
 assert(proof_PB_0[nPBs].PB_view.leaf.final_cw == PB_other_view1.leaf.final_cw);





   ++nPBs;
}



byte_t verifier1_root[picosha2::k_digest_size];

hash(hash_array_V1, verifier1_root);
std::cout << std::endl <<  "FINAL HASH: " << std::endl;
for (int i = 0; i < 32; i++)   printf("%x", Proof_for_V1.root[i]);
std::cout << std::endl << "---" << std::endl;
std::cout << std::endl <<  "FINAL HASH: " << std::endl;
for (int i = 0; i < 32; i++)   printf("%x", verifier1_root[i]);
std::cout << std::endl << "---" << std::endl;
 
 



 
 

 
 
  return 0;
}

 
