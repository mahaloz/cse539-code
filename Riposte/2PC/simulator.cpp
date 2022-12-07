#include <type_traits>
#include <set>
#include <vector>
 
#define blocklen 128
  
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

 

__m128i ones = _mm_set1_epi64x(-1);
  
const prgkey_t prgkey;
   
inline __m128i xor_if(const __m128i & block1, const __m128i & block2, __m128i flag)
{
 return _mm_xor_si128(block1, _mm_and_si128(block2, flag));
}
 
inline uint64_t xor_if(const uint64_t & block1, const uint64_t & block2, uint64_t flag)
{

 return (block1 ^ (block2 & flag)); // _mm_xor_si128(block1, _mm_and_si128(block2, flag));
}
 

const size_t numofboxes = prgkey.numofboxes;
const size_t rounds = prgkey.rounds;
 
typedef std::array<uint64_t, 3 * numofboxes> blind64_T;
typedef std::array<__m128i, 3 * numofboxes>  blindT;
 
inline auto transpose(const block_t & inp, const __m128i & challenge = _mm_set1_epi64x(-1))
{
  blockT out = { _mm_setzero_si128()};
 
  for (size_t k = 0; k < sizeof(block_t)/8; ++k)
  {
    uint64_t bitset = static_cast<node_t>(inp)[k];
 
    int j = k * 64;
    while (bitset != 0)
    {
      uint64_t t = bitset & -bitset;
      while (j < k * 64 + __builtin_ctzl(bitset))
        out[j++] = _mm_setzero_si128();
      out[j++] = challenge;
      bitset ^= t;
    }
  }
  return std::move(out);
}

inline auto transpose64(const block_t & inp)
{
  block64_T out = { 0 };
  
  for(size_t j = 0; j < 128; ++j)
  {
    if(inp.bits[j]) out[j] = -1;
  }
 
  return std::move(out);
}
 
void print_first_col(blockT inp, size_t col = 0)
{
  for(size_t i = 0; i < blocklen; ++i)
  {
    std::cout << (block<__m128i>(inp[i])).bits[col];
  }
 
  std::cout << std::endl;
}

void print_first_col(blindT inp, size_t col = 0)
{
  for(size_t i = 0; i < 3 * numofboxes; ++i)
  {
    std::cout << (block<__m128i>(inp[i])).bits[col];
  }
 
  std::cout << std::endl;
}

void print_first_col(block64_T inp, size_t col = 0)
{
  // for(size_t i = 0; i < blocklen; ++i)
  // {
  //   std::cout << (block<__m128i>(inp[i])).bits[col];
  // }
 
  // std::cout << std::endl;
}

void print_first_col(blind64_T inp, size_t col = 0)
{
  // for(size_t i = 0; i < 3 * numofboxes; ++i)
  // {
  //   std::cout << (block<__m128i>(inp[i])).bits[col];
  // }
 
  // std::cout << std::endl;
}

__m128i not_(__m128i& message)
{
    return message ^ ones;
}

uint64_t not_(uint64_t& message)
{
  return message ^ (-1);
}

const size_t nitems = 1ULL << 42;  
const size_t target =  133;//atoi(argv[1]);
const leaf_t val =  1; //_mm256_set1_epi8(0x01);
 
  
 
auto [dpfkey0, dpfkey1] = dpf_key<leaf_t, node_t, prgkey_t>::gen(prgkey, nitems, target, val);
 
constexpr size_t depth = dpfkey1.depth(nitems);  
constexpr size_t nodes_per_leaf = dpfkey0.nodes_per_leaf;

#include "transcripts.h"
 
 
PB_transcript  * P0_view_ = new PB_transcript;  
PB_transcript  * P1_view_ = new PB_transcript; 

PB_transcript_64  * P0_view_64 = new PB_transcript_64;  
PB_transcript_64  * P1_view_64 = new PB_transcript_64; 
  
 
P2_transcript * P2_P0_view = new P2_transcript;
P2_transcript * P2_P1_view = new P2_transcript;
 
P2_transcript_64 * P2_P0_view_64 = new P2_transcript_64;
P2_transcript_64 * P2_P1_view_64 = new P2_transcript_64;

P2_transcript_64 * P2_P0_view_V = new P2_transcript_64;
P2_transcript_64 * P2_P1_view_V = new P2_transcript_64;
 

PB_transcript  * PB_other_v0 = new PB_transcript; 
PB_transcript  * PB_other_v1 = new PB_transcript;

P2_transcript * P2_P0_v = new P2_transcript;
P2_transcript * P2_P1_v = new P2_transcript;
 

blockT * zero_share0 = (blockT *) std::aligned_alloc(sizeof(__m256i), sizeof(blockT) * depth);
blockT * zero_share1 = (blockT *) std::aligned_alloc(sizeof(__m256i), sizeof(blockT) * depth);
blockT * zero_share_v0 = (blockT *) std::aligned_alloc(sizeof(__m256i), sizeof(blockT) * depth);
blockT * zero_share_v1 = (blockT *) std::aligned_alloc(sizeof(__m256i), sizeof(blockT) * depth);
  
unsigned char hash0[128][SHA256_DIGEST_LENGTH];
unsigned char hash1[128][SHA256_DIGEST_LENGTH];
unsigned char hashP2_0[128][SHA256_DIGEST_LENGTH];
unsigned char hashP2_1[128][SHA256_DIGEST_LENGTH];
unsigned char final_hash[SHA256_DIGEST_LENGTH];


unsigned char hash0_v[128][SHA256_DIGEST_LENGTH];
unsigned char hash1_v[128][SHA256_DIGEST_LENGTH];
unsigned char hashP2_0_v[128][SHA256_DIGEST_LENGTH];
unsigned char hashP2_1_v[128][SHA256_DIGEST_LENGTH];
unsigned char final_hash_v[SHA256_DIGEST_LENGTH];
 
#include "proof.h"
#include "randomness.h"
#include "simulator.h"
#include "verifier.h"
#include "verifierP2.h"

int main(int argc, char * argv[])
{
     
  P0_view_->middle       = new from_PB_middle[depth-1];
  P1_view_->middle       = new from_PB_middle[depth-1];
  
  P0_view_64->middle     = new from_PB_middle_64[depth-1];
  P1_view_64->middle     = new from_PB_middle_64[depth-1];

  P2_P0_view->middle     = new from_P2_middle[depth-1];
  P2_P1_view->middle     = new from_P2_middle[depth-1];

  P2_P0_view_64->middle  = new from_P2_middle_64[depth-1];
  P2_P1_view_64->middle  = new from_P2_middle_64[depth-1];

  std::cout << "rounds = " << rounds << std::endl;
   
  bool party0 = false; bool party1 = true;

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
 
 
 
  blockT seed0_, seed1_, seed2_;
 
  
  arc4random_buf(&seed0_, sizeof(blockT));
  arc4random_buf(&seed1_, sizeof(blockT));
  arc4random_buf(&seed2_, sizeof(blockT));
 
  size_t len = 750;
 
  auto start_sim = std::chrono::high_resolution_clock::now();
 
  Simulator sim(depth, prgkey, seed0_, seed1_, seed2_, len);  
 
  for(size_t i = 0; i < depth; ++i) 
  { 
   if(P0direction[i])  
    {
      sim.P0direction_[i] = _mm_set1_epi64x(-1);
    }
    else
    {
      sim.P0direction_[i] = _mm_set1_epi64x(0);
    }
   if(P1direction[i])  
    {
      sim.P1direction_[i] = _mm_set1_epi64x(-1);
    }
    else
    {
      sim.P1direction_[i] = _mm_set1_epi64x(0);
    } 
  }
  
  sim.root_layer(prgkey, dpfkey0, dpfkey1);
    
  for(size_t cur_depth = 1; cur_depth < depth; ++cur_depth)
  {
   sim.middle_layers(prgkey,  dpfkey0,  dpfkey1, cur_depth);
  }
 
  sim.leaf_layer(dpfkey0, dpfkey1);
 
  auto finish_sim = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double, std::milli> elapsed_sim = finish_sim - start_sim;
 
  std::cout << "elapsed_sim = " << elapsed_sim.count() << std::endl;




  PB_transcriptT * view1T_128      = (PB_transcriptT *) std::aligned_alloc(sizeof(__m256i), 128 * sizeof(PB_transcriptT));
  
  PB_transcriptT * view0T_128      = (PB_transcriptT *) std::aligned_alloc(sizeof(__m256i), 128 * sizeof(PB_transcriptT));

  P2_transcriptT * P2_P0_viewT_128 = (P2_transcriptT *) std::aligned_alloc(sizeof(__m256i), 128 * sizeof(P2_transcriptT));
    
  P2_transcriptT * P2_P1_viewT_128 = (P2_transcriptT *) std::aligned_alloc(sizeof(__m256i), 128 * sizeof(P2_transcriptT));

 
  transpose_transcript(P0_view_, P1_view_, view0T_128, view1T_128);
  transpose_transcript(P2_P0_view, P2_P0_viewT_128, ones);
  transpose_transcript(P2_P1_view, P2_P1_viewT_128, ones);

  P2_transcriptT * P2_P0_viewT = (P2_transcriptT *) std::aligned_alloc(sizeof(__m256i), 64 * sizeof(P2_transcriptT)); 
  P2_transcriptT * P2_P1_viewT = (P2_transcriptT *) std::aligned_alloc(sizeof(__m256i), 64 * sizeof(P2_transcriptT));

 
 auto start_gen = std::chrono::high_resolution_clock::now();

 __m128i challenge = get_root_hash(final_hash, view0T_128, view1T_128, P2_P0_viewT_128, P2_P1_viewT_128);
  
  
  auto finish_gen = std::chrono::high_resolution_clock::now();
  
  std::chrono::duration<double, std::milli> elapsed_gen = finish_gen - start_gen;
 
  std::cout << "elapsed_gen = " << elapsed_gen.count() << std::endl;

  uint64_t challenge_[2] = {
    unrank(challenge[0] % _64_CHOOSE_32), // ignoring modulo bias; thus, we lose
    unrank(challenge[1] % _64_CHOOSE_32)  // (less than) 1-bit entropy per limb
   };
  

 
  challenge[0]  = challenge_[0];
  challenge[1]  = challenge_[1];

  uint64_t not_challenge[2];
 
   not_challenge[0] = (challenge_[0] ^ -1);
   not_challenge[1] = (challenge_[1] ^ -1);

  __m128i not_challenge_;
  not_challenge_[0] = not_challenge[0];
  not_challenge_[1] = not_challenge[1];
  
  compress_transcript(P0_view_, P0_view_64, challenge_);
  compress_transcript(P1_view_, P1_view_64, challenge_);
  compress_transcript(P2_P0_view, P2_P0_view_64, challenge_);
  compress_transcript(P2_P1_view, P2_P1_view_64, challenge_);

 

  PB_transcriptT * view0T_test = (PB_transcriptT *) std::aligned_alloc(sizeof(__m256i), 64 * sizeof(PB_transcriptT));
  
  transpose_transcript(P0_view_64, view0T_test);
  
 
  std::cout << "challenge:     ";
  for(size_t j = 0; j < 128; ++j) std::cout << (block<__m128i>(challenge)).bits[j];

  std::cout << std::endl << "not_challenge: ";
  for(size_t j = 0; j < 128; ++j) std::cout << (block<__m128i>(not_challenge_)).bits[j];
 

  generate_proofs(challenge_, not_challenge, seed0_, seed1_, seed2_, dpfkey0, dpfkey1, hash0, hash1, hashP2_0, hashP2_1, final_hash, P0direction, P1direction);

  proof_PB<leaf_t, node_t, prgkey_t, nodes_per_leaf> proof_recv_v0 = read_proof("proof_for_P0.dat");
  proof_PB<leaf_t, node_t, prgkey_t, nodes_per_leaf> proof_recv_v1 = read_proof("proof_for_P1.dat");

  __m128i challenge_v  = _mm_loadu_si128((__m128i*) proof_recv_v0.PB_root);

   uint64_t challengeV[2] = {
    unrank(challenge_v[0] % _64_CHOOSE_32), // ignoring modulo bias; thus, we lose
    unrank(challenge_v[1] % _64_CHOOSE_32)  // (less than) 1-bit entropy per limb
   };
  

 
  challenge_v[0]  = challengeV[0];
  challenge_v[1]  = challengeV[1];
  std::cout << "challenge: " << std::bitset<64>(challenge_v[0]) << std::endl;
  std::cout << "challenge: " << std::bitset<64>(challenge_v[1]) << std::endl;
  uint64_t not_challengeV[2];
 
   not_challengeV[0] = (challenge_v[0] ^ -1);
   not_challengeV[1] = (challenge_v[1] ^ -1);

  __m128i not_challenge_v;
  not_challenge_v[0] = not_challengeV[0];
  not_challenge_v[1] = not_challengeV[1];

  assert(not_challenge_v[0] == not_challenge_[0]);
 
 
  PB_transcript * gen_view0_ = new PB_transcript;
  gen_view0_->middle         = new from_PB_middle[depth-1];
  PB_transcript * gen_view1_ = new PB_transcript;
  gen_view1_->middle         = new from_PB_middle[depth-1];
  
  PB_transcript_64 * gen_view0_64 = new PB_transcript_64;
  gen_view0_64->middle            = new from_PB_middle_64[depth-1];
  
  PB_transcript_64 * gen_view1_64 = new PB_transcript_64;
  gen_view1_64->middle            = new from_PB_middle_64[depth-1];

  P2_P0_view_V->middle = new from_P2_middle_64[depth-1];
  P2_P1_view_V->middle = new from_P2_middle_64[depth-1];

  
  Verifier_P2 ver_P2(depth, prgkey, proof_recv_v0.seed, proof_recv_v0.seed_other, proof_recv_v0.seed2, len);  
 
  ver_P2.root_layer(not_challengeV);
    
  for(size_t cur_depth = 1; cur_depth < depth; ++cur_depth)
  {
   ver_P2.middle_layers(cur_depth, not_challengeV);
  }
  


  Verifier ver1(depth, prgkey, proof_recv_v1.seed, len); 
  
  for(size_t i = 0; i < depth; ++i) 
  { 
    if(proof_recv_v1.direction[i])  
    {
     ver1.Pdirection_[i] = -1;// _mm_set1_epi64x(-1);
    }
    else
    {
     ver1.Pdirection_[i] = 0;//_mm_set1_epi64x(0);
    }    
  }
   
  
 

  ver1.root_layer(prgkey, proof_recv_v1.dpfkey_, proof_recv_v1.PB_other , gen_view1_64,  proof_recv_v1.P2_view, party1, challengeV);
 

 
  for(size_t cur_depth = 1; cur_depth < depth; ++cur_depth)
  {
   ver1.middle_layers(proof_recv_v1.P2_view, proof_recv_v1.PB_other, gen_view1_64, prgkey, proof_recv_v1.dpfkey_, cur_depth, party1, challengeV);  
  }    

 
  ver1.leaf_layer(proof_recv_v1.PB_other, gen_view1_64 , proof_recv_v1.dpfkey_, challengeV);
 


 
  Verifier ver0(depth, prgkey, proof_recv_v0.seed, len); 

  for(size_t i = 0; i < depth; ++i) 
  { 
    if(proof_recv_v0.direction[i])  
    {
     ver0.Pdirection_[i] = -1;//_mm_set1_epi64x(-1);
    }
    else
    {
     ver0.Pdirection_[i] = 0;//_mm_set1_epi64x(0);
    }
  }
   
 
 
 
 ver0.root_layer(prgkey, proof_recv_v0.dpfkey_, proof_recv_v0.PB_other , gen_view0_64, proof_recv_v0.P2_view, party0, challengeV);
  

 for(size_t cur_depth = 1; cur_depth < depth; ++cur_depth)
 {
  ver0.middle_layers(proof_recv_v0.P2_view, proof_recv_v0.PB_other, gen_view0_64, prgkey, proof_recv_v0.dpfkey_, cur_depth, party0, challengeV);   
 }    
 


  
 ver0.leaf_layer(proof_recv_v0.PB_other, gen_view0_64, proof_recv_v0.dpfkey_ , challengeV);


 
  PB_transcriptT * gen_view1T    = (PB_transcriptT *) std::aligned_alloc(sizeof(__m256i), 64 * sizeof(PB_transcriptT));
  PB_transcriptT * gen_view0T    = (PB_transcriptT *) std::aligned_alloc(sizeof(__m256i), 64 * sizeof(PB_transcriptT));

  P2_transcriptT * P2_P0_view_VT = (P2_transcriptT *) std::aligned_alloc(sizeof(__m256i), 64 * sizeof(P2_transcriptT));   
  P2_transcriptT * P2_P1_view_VT = (P2_transcriptT *) std::aligned_alloc(sizeof(__m256i), 64 * sizeof(P2_transcriptT));

  PB_transcriptT * view1T = (PB_transcriptT *) std::aligned_alloc(sizeof(__m256i), 64 * sizeof(PB_transcriptT));
  PB_transcriptT * view0T = (PB_transcriptT *) std::aligned_alloc(sizeof(__m256i), 64 * sizeof(PB_transcriptT));


  transpose_transcript(gen_view0_64, gen_view0T);
  transpose_transcript(gen_view1_64, gen_view1T);

  transpose_transcript(P2_P0_view_V, P2_P0_view_VT);
  transpose_transcript(P2_P1_view_V, P2_P1_view_VT);

  unsigned char final_hash_v[SHA256_DIGEST_LENGTH];


  auto start_verify = std::chrono::high_resolution_clock::now();

  verify_root_hash(proof_recv_v0, final_hash_v, gen_view0T,  gen_view1T, P2_P0_view_VT, P2_P1_view_VT, challenge_v, not_challenge_v);

  auto finish_verify = std::chrono::high_resolution_clock::now();

  std::chrono::duration<double, std::milli> elapsed_verify = finish_verify - start_verify;
 
  std::cout << "elapsed_verify = " << elapsed_verify.count() << std::endl;

 //  get_swap_hashes(zero_share0, zero_share1, zero_share_v0, zero_share_v1, challenge);
 
  transpose_transcript(P0_view_64, view0T);
  transpose_transcript(P1_view_64 , view1T);
  


  size_t t = 0;
  size_t t2 = 0;
  for(size_t j = 0; j < 128; ++j)
  { 
    if((block<__m128i>(challenge)).bits[j])
    {
    
 
      assert(view0T_128[j].rootT.bit_L_shares_recv == gen_view0T[t].rootT.bit_L_shares_recv);
      assert(view0T_128[j].rootT.bit_R_shares_recv == gen_view0T[t].rootT.bit_R_shares_recv);
      assert(view0T_128[j].rootT.next_bit_bit_[0] == gen_view0T[t].rootT.next_bit_bit_[0]);
      assert(view0T_128[j].rootT.next_bit_bit_[1] == gen_view0T[t].rootT.next_bit_bit_[1]);

      for(size_t k = 0; k < blocklen; ++k) 
      {
        assert(view0T_128[j].rootT.R_shares_recv[k] == gen_view0T[t].rootT.R_shares_recv[k]);
        assert(view0T_128[j].rootT.L_shares_recv[k] == gen_view0T[t].rootT.L_shares_recv[k]);
        assert(view0T_128[j].leafT.final_cw[k] == gen_view0T[t].leafT.final_cw[k]);
        assert(view0T_128[j].rootT.swap_bit_[0][k] == gen_view0T[t].rootT.swap_bit_[0][k]);
        assert(view0T_128[j].rootT.swap_bit_[1][k] == gen_view0T[t].rootT.swap_bit_[1][k]);
        assert(view0T_128[j].rootT.swap_block[0][k] == gen_view0T[t].rootT.swap_block[0][k]);
        assert(view0T_128[j].rootT.swap_block[1][k] == gen_view0T[t].rootT.swap_block[1][k]);
      }


      assert(view1T_128[j].rootT.bit_L_shares_recv == gen_view1T[t].rootT.bit_L_shares_recv);
      assert(view1T_128[j].rootT.bit_R_shares_recv == gen_view1T[t].rootT.bit_R_shares_recv);
      assert(view1T_128[j].rootT.next_bit_bit_[0] == gen_view1T[t].rootT.next_bit_bit_[0]);
      assert(view1T_128[j].rootT.next_bit_bit_[1] == gen_view1T[t].rootT.next_bit_bit_[1]);

      for(size_t k = 0; k < blocklen; ++k) 
      {
        assert(view1T_128[j].rootT.R_shares_recv[k] == gen_view1T[t].rootT.R_shares_recv[k]);
        assert(view1T_128[j].rootT.L_shares_recv[k] == gen_view1T[t].rootT.L_shares_recv[k]);
        assert(view1T_128[j].leafT.final_cw[k] == gen_view1T[t].leafT.final_cw[k]);
        assert(view1T_128[j].rootT.swap_bit_[0][k] == gen_view1T[t].rootT.swap_bit_[0][k]);
        assert(view1T_128[j].rootT.swap_bit_[1][k] == gen_view1T[t].rootT.swap_bit_[1][k]);
        assert(view1T_128[j].rootT.swap_block[0][k] == gen_view1T[t].rootT.swap_block[0][k]);
        assert(view1T_128[j].rootT.swap_block[1][k] == gen_view1T[t].rootT.swap_block[1][k]);
      }

       ++t;
    }
    
    if(!(block<__m128i>(challenge)).bits[j])
    {
      assert(P2_P0_viewT_128[j].rootT.next_bit_gamma[0] == P2_P0_view_VT[t2].rootT.next_bit_gamma[0]);
      assert(P2_P0_viewT_128[j].rootT.next_bit_gamma[1] == P2_P0_view_VT[t2].rootT.next_bit_gamma[1]);
      for(size_t k = 0; k < blocklen; ++k)
      {
        assert(P2_P0_viewT_128[j].rootT.swap_gamma[0][k] == P2_P0_view_VT[t2].rootT.swap_gamma[0][k]);
        assert(P2_P0_viewT_128[j].rootT.swap_gamma[1][k] == P2_P0_view_VT[t2].rootT.swap_gamma[1][k]);
      }
      ++t2;
    }
  }
  

  assert(gen_view1_64->root.bit_L_shares_recv == P1_view_64->root.bit_L_shares_recv);
  assert(gen_view1_64->root.bit_R_shares_recv == P1_view_64->root.bit_R_shares_recv);
  assert(gen_view1_64->root.next_bit_block[0] == P1_view_64->root.next_bit_block[0]);
  assert(gen_view1_64->root.next_bit_bit_[0]  == P1_view_64->root.next_bit_bit_[0]);
  assert(gen_view1_64->root.next_bit_bit_[1]  == P1_view_64->root.next_bit_bit_[1]);
  assert(gen_view1_64->root.next_bit_block[1] == P1_view_64->root.next_bit_block[1]);
 
  for(size_t j = 0; j < blocklen; ++j)
  {
   assert(gen_view1_64->root.L_shares_recv[j] == P1_view_64->root.L_shares_recv[j]);
   assert(gen_view1_64->root.R_shares_recv[j] == P1_view_64->root.R_shares_recv[j]);
   assert(gen_view1_64->root.swap_block[0][j] == P1_view_64->root.swap_block[0][j]);
   assert(gen_view1_64->root.swap_block[1][j] == P1_view_64->root.swap_block[1][j]);
   assert(gen_view1_64->root.swap_bit_[0][j]  == P1_view_64->root.swap_bit_[0][j]);
   assert(gen_view1_64->root.swap_bit_[1][j]  == P1_view_64->root.swap_bit_[1][j]);
  }
 
 for(size_t j = 0; j < 3 * numofboxes; ++j)
  {
    for(size_t d = 0; d < depth-1; ++d)
    { 
      for(size_t r = 0; r < rounds; ++r)
      {
        assert(gen_view1_64->middle[d].seed0L_encrypt[r][j] == P1_view_64->middle[d].seed0L_encrypt[r][j]);
        assert(gen_view1_64->middle[d].seed1L_encrypt[r][j] == P1_view_64->middle[d].seed1L_encrypt[r][j]);
        assert(gen_view1_64->middle[d].seed0R_encrypt[r][j] == P1_view_64->middle[d].seed0R_encrypt[r][j]);
        assert(gen_view1_64->middle[d].seed1R_encrypt[r][j] == P1_view_64->middle[d].seed1R_encrypt[r][j]);
      }
    }
  }

   for(size_t j = 0; j < blocklen; ++j)
 {
  assert(gen_view0_64->root.L_shares_recv[j] == P0_view_64->root.L_shares_recv[j]);
  assert(gen_view0_64->root.R_shares_recv[j] == P0_view_64->root.R_shares_recv[j]);
 }

 for(size_t j = 0; j < 3 * numofboxes; ++j)
  {
    for(size_t d = 0; d < depth-1; ++d)
    {
      for(size_t r = 0; r < rounds; ++r)
      {
        assert(gen_view0_64->middle[d].seed0L_encrypt[r][j] == P0_view_64->middle[d].seed0L_encrypt[r][j]);
        assert(gen_view0_64->middle[d].seed1L_encrypt[r][j] == P0_view_64->middle[d].seed1L_encrypt[r][j]);

        assert(gen_view0_64->middle[d].seed0R_encrypt[r][j] == P0_view_64->middle[d].seed0R_encrypt[r][j]);
        assert(gen_view0_64->middle[d].seed1R_encrypt[r][j] == P0_view_64->middle[d].seed1R_encrypt[r][j]);
       }
    }
  }
  
   for(size_t i = 0; i < blocklen; ++i)
   {
     assert(gen_view0_64->leaf.final_cw[i] == P0_view_64->leaf.final_cw[i]);
   }


  assert_transcripts_match(view0T, view1T,  gen_view0T, gen_view1T); 
    
 
 return 0;
}