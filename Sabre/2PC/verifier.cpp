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
typedef LowMC2<node_t> randomness_prgkey_t;
typedef block<node_t> block_t; 
typedef std::array<__m128i, blocklen> blockT;

typedef std::array<uint64_t, blocklen> block64_T;

 

__m128i ones = _mm_set1_epi64x(-1);
  
const prgkey_t prgkey;
const randomness_prgkey_t randomness_prgkey;   

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

 

__m128i not_(__m128i& message)
{
    return message ^ ones;
}

uint64_t not_(uint64_t& message)
{
  return message ^ (-1);
}

#include "common.h"  
 
  
 
auto [dpfkey0, dpfkey1] = dpf_key<leaf_t, node_t, prgkey_t>::gen(prgkey, nitems, target, val);
 
constexpr size_t depth = dpfkey1.depth(nitems);  
constexpr size_t nodes_per_leaf = dpfkey0.nodes_per_leaf;

#include "transcripts.h"
 
 
PB_transcript  * P0_view_ = new PB_transcript;  
PB_transcript  * P1_view_ = new PB_transcript; 

PB_transcript_64  * P0_view_64 = new PB_transcript_64;  
PB_transcript_64  * P1_view_64 = new PB_transcript_64; 
  
 
 
 
P2_transcript_64 * P2_P0_view_64 = new P2_transcript_64;
P2_transcript_64 * P2_P1_view_64 = new P2_transcript_64;

P2_transcript_64 * P2_P0_view_V = new P2_transcript_64;
P2_transcript_64 * P2_P1_view_V = new P2_transcript_64;
 

 
 



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
//#include "simulator.h"
#include "verifier.h"
#include "verifierP2.h"
  proof_PB<leaf_t, node_t, prgkey_t, nodes_per_leaf> proof_recv_v0 = read_proof("proof_for_P0.dat");
  proof_PB<leaf_t, node_t, prgkey_t, nodes_per_leaf> proof_recv_v1 = read_proof("proof_for_P1.dat");


  blockT * zero_share0 = (blockT *) std::aligned_alloc(sizeof(__m256i), sizeof(blockT) * depth);
blockT * zero_share1 = (blockT *) std::aligned_alloc(sizeof(__m256i), sizeof(blockT) * depth);
blockT * zero_share_v0 = (blockT *) std::aligned_alloc(sizeof(__m256i), sizeof(blockT) * depth);
blockT * zero_share_v1 = (blockT *) std::aligned_alloc(sizeof(__m256i), sizeof(blockT) * depth);
int main(int argc, char * argv[])
{
    
    size_t len = 750; 
   bool party0 = false; bool party1 = true;

  // proof_PB<leaf_t, node_t, prgkey_t, nodes_per_leaf> proof_recv_v0 = read_proof("proof_for_P0.dat");
  // proof_PB<leaf_t, node_t, prgkey_t, nodes_per_leaf> proof_recv_v1 = read_proof("proof_for_P1.dat");
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

 // assert(not_challenge_v[0] == not_challenge_[0]);
 
 
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

 
  auto start_verify = std::chrono::high_resolution_clock::now();
 
  Verifier_P2 ver_P2(depth, randomness_prgkey,  proof_recv_v0.seed, proof_recv_v0.seed_other, proof_recv_v0.seed2, len);  
 
  ver_P2.root_layer(not_challengeV);
    
  for(size_t cur_depth = 1; cur_depth < depth; ++cur_depth)
  {
   ver_P2.middle_layers(cur_depth, not_challengeV);
  }
  


  Verifier ver1(depth, randomness_prgkey, prgkey, proof_recv_v1.seed, len); 
  
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
 


 
  Verifier ver0(depth, randomness_prgkey, prgkey, proof_recv_v0.seed, len); 

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




  verify_root_hash(proof_recv_v0, final_hash_v, gen_view0T,  gen_view1T, P2_P0_view_VT, P2_P1_view_VT, challenge_v, not_challenge_v);

  auto finish_verify = std::chrono::high_resolution_clock::now();

  std::chrono::duration<double, std::milli> elapsed_verify = finish_verify - start_verify;
 
  std::cout << "elapsed_verify = " << elapsed_verify.count() << std::endl;


 
 
 return 0;
}