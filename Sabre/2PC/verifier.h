class Verifier
{

  public:
  
  const size_t depth;

  std::vector<uint64_t> Pdirection_;
 
  block64_T seed0_prev, seed1_prev;

  uint64_t bit0_prev, bit1_prev;
 
   
  Verifier(const size_t depth_, const randomness_prgkey_t& randomness_prgkey, const prgkey_t& key, const blockT seed, const size_t len)
      : depth(depth_), PBrand(randomness_prgkey, seed, len) 
  {   
    Pdirection_.reserve(depth_+1);
  }

   


  // ///// Functions for dice role i = n
  
   

  void get_next_bits(const P2_transcript_64 * from_P2, const PB_transcript_64 * recv_view, PB_transcript_64* gen_view, const uint64_t L0_shares, const uint64_t R0_shares, 
                        const uint64_t L1_shares, const uint64_t R1_shares, const bool party, const size_t cur_depth, const uint64_t challenge[]);
    
  void Gen_Blinds(blind64_T blinds0[], const uint64_t challenge[2]);

   template<  typename prgkey_t>
   void expand_mpc_verify(const prgkey_t & key, const block64_T seed,  const PB_transcript_64 * recv_view, PB_transcript_64* gen_view, block64_T &s0_L, block64_T & s0_R, 
                                         uint64_t & t0_L, uint64_t & t0_R,  blind64_T* blind, blind64_T* gamma, const bool party, const size_t cur_depth, const bool LR);

  template<typename prgkey_t>
  auto prg_mpc_verify(const prgkey_t & key, const block64_T seed, const PB_transcript_64 * recv_view, PB_transcript_64* gen_view, 
                                 blind64_T* blind, blind64_T* gamma, const size_t cur_depth, const bool party, bool LR , size_t len);
  
  std::pair<uint64_t, uint64_t> multiply_mpc( const PB_transcript_64 * recv_view, const uint64_t val_mX, 
                           const uint64_t val_bool, const uint64_t other_mX, const uint64_t other_bool, const uint64_t c, const size_t cur_depth,  const bool party, uint64_t& result, const uint64_t challenge[]);
 
  void conditional_swap_and_next_seed(const PB_transcript_64 * recv_view, PB_transcript_64* gen_view, const P2_transcript_64 * P2_view, const block64_T L_share, 
                                       const block64_T R_share, const block64_T L1_share, const block64_T R1_share, const bool party, const size_t cur_depth, const uint64_t challenge[]);
 
  template<typename leaf_t, typename node_t, typename prgkey_t>
  void root_layer(const prgkey_t & key, const dpf_key<leaf_t, node_t, prgkey_t>& dpfkey, const PB_transcript_64 * recv_view,  PB_transcript_64* gen_view, const P2_transcript_64 * P2_view,  const bool party, const uint64_t challenge[2]);
 
  template<typename leaf_t, typename node_t, typename prgkey_t>
  void middle_layers(const P2_transcript_64 * from_P2, const PB_transcript_64 * recv_view, PB_transcript_64* gen_view, const prgkey_t & key, const dpf_key<leaf_t, node_t, prgkey_t>& dpfkey, const size_t cur_depth, const bool party, const uint64_t challenge[2]);
                    
  template<typename leaf_t, typename node_t, typename prgkey_t>
  void leaf_layer(const PB_transcript_64 * recv_view, PB_transcript_64* gen_view, const dpf_key<leaf_t, node_t, prgkey_t>& dpfkey, const uint64_t challenge[2]);

  ~ Verifier()
  {

  }

  private:
  MPCrandomness PBrand;
};

 
  ////////////////////////////////// The below functions for i == n //////////////////////////////////
 
 void Verifier::Gen_Blinds(blind64_T blinds0[], const uint64_t challenge[2])
  {
    for (unsigned r = 0; r < rounds; ++r)
     {
        blinds0[r] = PBrand.next_blind_64(challenge);  
     }
  }


template<typename leaf_t, typename node_t, typename prgkey_t>
void Verifier::root_layer(const prgkey_t & key,  const dpf_key<leaf_t, node_t, prgkey_t>& dpfkey, const PB_transcript_64 * recv_view, PB_transcript_64* gen_view, const P2_transcript_64 * P2_view, const bool party, const uint64_t challenge[2])
{

   block64_T seed_array = transpose64(dpfkey.root);
  
   const size_t cur_depth = 0;

   block64_T cw_array = transpose64(dpfkey.cw[cur_depth]);
 
   block64_T  s[2];

   uint64_t t[2];
   
 
   expand_parallel(key, seed_array, s, t);
   
   // bool root_t = _mm_testz_si128(seed_array[0], seed_array[0]);
    // for(size_t j = 0; j < blocklen; ++j)
    // {
    //   std::cout << std::bitset<64>(s[L][j]) << " -------> ^ \n";// << std::bitset<64>(cw_array[j]) << std::endl; 
    // }
    
   bool root_t = false;
   if(seed_array[0] == 0) root_t = true;
    
   for(size_t j = 2; j < blocklen; ++j)
   {
    if(root_t)
    {
      // if(j < 4)  std::cout << std::bitset<64>(s[L][j]) << " -------> ^ \n" << std::bitset<64>(cw_array[j]) << std::endl; 

      s[L][j] ^= cw_array[j]; 
      s[R][j] ^= cw_array[j];  
    }
   }
   
   clear_lsb_parallel(s[L], 0b11);
   clear_lsb_parallel(s[R], 0b11);
  
   block64_T s_L_myshare, s_L_othershare, s_R_myshare, s_R_othershare;
   block64_T L_shares[2];    

   L_shares[0] = PBrand.next_block_64(challenge); 
  

   for(size_t j = 0; j < blocklen; ++j) L_shares[1][j] = s[L][j] ^ L_shares[0][j];

   if(!party) s_L_myshare = L_shares[0];
   if(party ) s_L_myshare = L_shares[1];

   block64_T R_shares[2]; 
  
   R_shares[0] = PBrand.next_block_64(challenge);
    
 
   for(size_t j = 0; j < blocklen; ++j)  R_shares[1][j] = s[R][j] ^ R_shares[0][j];
  
   if(!party) s_R_myshare = R_shares[0];
   if(party ) s_R_myshare = R_shares[1];


   if(!party) for(size_t j = 0; j < blocklen; ++j)  
   {
    gen_view->root.L_shares_recv[j]  =  L_shares[1][j]; 
    // if(j < 5)
    // {
    //  std::cout << std::bitset<64>(s[L][j]) << " ^ \n" << std::bitset<64>(L_shares[0][j]) << std::endl;
    //  std::cout << std::bitset<64>(gen_view->root.L_shares_recv[j]) << " " << j << " -- \n" << std::endl; 
    // } 
   } 
   if(!party) for(size_t j = 0; j < blocklen; ++j)  gen_view->root.R_shares_recv[j]  =  R_shares[1][j];  

   if(party) for(size_t j = 0; j < blocklen; ++j)   gen_view->root.L_shares_recv[j]  =  L_shares[0][j];  
   if(party) for(size_t j = 0; j < blocklen; ++j)   gen_view->root.R_shares_recv[j]  =  R_shares[0][j];
 
   s_L_othershare = recv_view->root.L_shares_recv;    
   s_R_othershare = recv_view->root.R_shares_recv;   

 

   if(!party) conditional_swap_and_next_seed(recv_view, gen_view, P2_view, s_L_myshare, s_R_myshare, s_L_othershare, s_R_othershare, party, cur_depth, challenge); 
   if( party) conditional_swap_and_next_seed(recv_view, gen_view, P2_view, s_L_othershare, s_R_othershare, s_L_myshare, s_R_myshare, party, cur_depth, challenge);
   
   uint64_t bitL_shares[2];  
   uint64_t bitR_shares[2]; 
 
   uint64_t bit_L_myshare, bit_L_othershare, bit_R_myshare, bit_R_othershare;

   uint64_t bit_L0_share, bit_R0_share, bit_L1_share, bit_R1_share;  
  
   bitL_shares[0] = PBrand.next_node_blind_64(challenge);
   bitR_shares[0] = PBrand.next_node_blind_64(challenge);
 

   bitL_shares[1] = bitL_shares[0] ^ t[L] ^ (cw_array[0] & get_lsb_array(seed_array));
   bitR_shares[1] = bitR_shares[0] ^ t[R] ^ (cw_array[1] & get_lsb_array(seed_array));
   

   if(!party)
   {
    bit_L_myshare = bitL_shares[0];
    bit_R_myshare = bitR_shares[0];

    gen_view->root.bit_L_shares_recv = bitL_shares[1];
    gen_view->root.bit_R_shares_recv = bitR_shares[1];
   }

   if(party)
   {
    bit_L_myshare = bitL_shares[1];
    bit_R_myshare = bitR_shares[1];

    gen_view->root.bit_L_shares_recv = bitL_shares[0];
    gen_view->root.bit_R_shares_recv = bitR_shares[0];  
   }
 
    bit_L_othershare =  recv_view->root.bit_L_shares_recv;
    bit_R_othershare =  recv_view->root.bit_R_shares_recv; 
      
   if(!party) get_next_bits(P2_view, recv_view, gen_view, bit_L_myshare, bit_R_myshare, bit_L_othershare, bit_R_othershare, party, cur_depth, challenge);
   if( party) get_next_bits(P2_view, recv_view, gen_view, bit_L_othershare, bit_R_othershare, bit_L_myshare, bit_R_myshare, party, cur_depth, challenge);
}


void Verifier::get_next_bits(const P2_transcript_64 * from_P2, const PB_transcript_64 * recv_view, PB_transcript_64* gen_view, const uint64_t L0_shares, const uint64_t R0_shares, 
                             const  uint64_t L1_shares, const uint64_t R1_shares, const bool party, const size_t cur_depth, const uint64_t challenge[])
 {
    uint64_t L_xor_R0 = L0_shares ^ R0_shares;

    uint64_t X1[2], gamma[2];
     uint64_t Y1[2];
    uint64_t result0, result1;

    if(cur_depth == 0)
    {
      X1[0]    = recv_view->root.next_bit_block[0];
      Y1[0]    = recv_view->root.next_bit_bit_[0];
      gamma[0] = from_P2->root.next_bit_gamma[0];

      X1[1]    = recv_view->root.next_bit_block[1];
      Y1[1]    = recv_view->root.next_bit_bit_[1];
      gamma[1] = from_P2->root.next_bit_gamma[1];
    }
    else
    {
      X1[0]    = recv_view->middle[cur_depth-1].next_bit_block[0];
      Y1[0]    = recv_view->middle[cur_depth-1].next_bit_bit_[0];
      gamma[0] = from_P2->middle[cur_depth-1].next_bit_gamma[0]; 

      X1[1]    = recv_view->middle[cur_depth-1].next_bit_block[1];
      Y1[1]    = recv_view->middle[cur_depth-1].next_bit_bit_[1];
      gamma[1] = from_P2->middle[cur_depth-1].next_bit_gamma[1]; 
    }
  
   
   auto mul_out0 = multiply_mpc(recv_view, L_xor_R0, Pdirection_[cur_depth], X1[0], Y1[0], gamma[0],  cur_depth,  party,  result0, challenge);
   
 
    if(cur_depth == 0)
    {
     gen_view->root.next_bit_block[0] = mul_out0.first;
     gen_view->root.next_bit_bit_[0]   = mul_out0.second;
    }
    else
    {
     gen_view->middle[cur_depth-1].next_bit_block[0] = mul_out0.first;
     gen_view->middle[cur_depth-1].next_bit_bit_[0]   = mul_out0.second;
    }
 

   uint64_t L_xor_R1 = L1_shares ^ R1_shares;  

   auto mul_out1 = multiply_mpc(recv_view, L_xor_R1, Pdirection_[cur_depth], X1[1], Y1[1], gamma[1],  cur_depth,  party,  result1, challenge);

    if(cur_depth == 0)
    {
     gen_view->root.next_bit_block[1] = mul_out1.first;
 
     gen_view->root.next_bit_bit_[1] = mul_out1.second;
    }
    else
    {
     gen_view->middle[cur_depth-1].next_bit_block[1] = mul_out1.first;
     gen_view->middle[cur_depth-1].next_bit_bit_[1] = mul_out1.second;
    }
    
    bit0_prev = result0 ^ L0_shares;
    bit1_prev = result1 ^ L1_shares;

 }


 
 
std::pair<uint64_t, uint64_t> Verifier::multiply_mpc(const PB_transcript_64 * recv_view, const uint64_t val_mX, const uint64_t val_bool, const uint64_t other_mX, 
                                                    const uint64_t other_bool, const uint64_t c,  const size_t cur_depth,  const bool party, uint64_t& result, const uint64_t challenge[])
{   

   uint64_t D0 = PBrand.next_node_blind_64(challenge);   
   

   uint64_t X0 = val_mX ^ D0;   
 

   uint64_t d0 = PBrand.next_node_blind_64(challenge);

   uint64_t Y0 = val_bool ^ d0;   
 
   uint64_t  gamma = xor_if(c, other_mX, d0);

   result = xor_if(gamma, val_mX, (val_bool ^ other_bool));   

   return std::make_pair(X0, Y0);
}


 

 
void Verifier::conditional_swap_and_next_seed(const PB_transcript_64 * recv_view, PB_transcript_64* gen_view, const P2_transcript_64 * P2_view, 
                                              const block64_T s0_L, const block64_T s0_R, const block64_T s1_L, const block64_T s1_R,  const bool party, const size_t cur_depth, const uint64_t challenge[])
{


 
  for(size_t j = 0; j < blocklen; ++j)
  {
    uint64_t X1, gamma; 
    uint64_t Y1;
    
    if(cur_depth == 0)
    {
       X1    = recv_view->root.swap_block[0][j];
       Y1    = recv_view->root.swap_bit_[0][j];
       gamma = P2_view->root.swap_gamma[0][j];
    }
    else
    {       
       X1    = recv_view->middle[cur_depth-1].swap_block[0][j];
       Y1    = recv_view->middle[cur_depth-1].swap_bit_[0][j];
       gamma = P2_view->middle[cur_depth-1].swap_gamma[0][j];
    } 

    uint64_t result0, result1;   

    uint64_t L_xor_R0 = s0_L[j] ^ s0_R[j];


     auto mul_out0 = multiply_mpc(recv_view, L_xor_R0, Pdirection_[cur_depth], X1, Y1, gamma,  cur_depth,  party,  result0, challenge);
 
    if(cur_depth == 0)
    {
     gen_view->root.swap_block[0][j] = mul_out0.first;
     gen_view->root.swap_bit_[0][j] = mul_out0.second;
    } 
    else
    {
     gen_view->middle[cur_depth-1].swap_block[0][j] = mul_out0.first;
     gen_view->middle[cur_depth-1].swap_bit_[0][j] = mul_out0.second;
    }
 
    if(cur_depth == 0)
    {
      X1    = recv_view->root.swap_block[1][j];
      Y1    = recv_view->root.swap_bit_[1][j];
      gamma = P2_view->root.swap_gamma[1][j];
    }
    else
    {       
      X1    = recv_view->middle[cur_depth-1].swap_block[1][j];
      Y1    = recv_view->middle[cur_depth-1].swap_bit_[1][j];
      gamma = P2_view->middle[cur_depth-1].swap_gamma[1][j];
    } 
   
    uint64_t L_xor_R1 = s1_L[j] ^ s1_R[j];
 
    auto mul_out1 = multiply_mpc(recv_view, L_xor_R1, Pdirection_[cur_depth], X1, Y1, gamma,  cur_depth,  party,  result1, challenge);

    if(cur_depth == 0)
    {
     gen_view->root.swap_block[1][j] = mul_out1.first;
     gen_view->root.swap_bit_[1][j] = mul_out1.second;
    } 
    else
    {
     gen_view->middle[cur_depth-1].swap_block[1][j] = mul_out1.first;
     gen_view->middle[cur_depth-1].swap_bit_[1][j] = mul_out1.second;
    }
 
    seed0_prev[j] = result0 ^ s0_L[j]; 
    seed1_prev[j] = result1 ^ s1_L[j];
  }
    
}




  
 template<typename prgkey_t>
 inline auto Verifier::prg_mpc_verify(const prgkey_t & key, const block64_T seed, const PB_transcript_64 * recv_view, PB_transcript_64* gen_view, 
                                 blind64_T* blind, blind64_T* gamma, const size_t cur_depth, const bool party, bool LR , size_t len)
 {

   block64_T seed_ = seed;
   seed_ = clear_lsb_parallel(seed_, 0b11); 

 
   blind64_T * c2L = (blind64_T *) std::aligned_alloc(sizeof(__m256i), (rounds + 1) * sizeof(blind64_T));
   if(!LR) 
   {
    for(size_t r = 0; r <= rounds; ++r) c2L[r] = recv_view->middle[cur_depth-1].seed0L_encrypt[r];
   }   
   if(LR)
   {
    for(size_t r = 0; r <= rounds; ++r) c2L[r] = recv_view->middle[cur_depth-1].seed1L_encrypt[r];
   }    
  
    
   blind64_T * outL = (blind64_T *) std::aligned_alloc(sizeof(__m256i), (rounds + 1) * sizeof(blind64_T));//    [rounds+1];
   block64_T tmp = seed_;
  


   auto prg_out0 = key.encrypt_MPC_verify_(tmp, c2L, blind, gamma, party, outL);


   for(size_t j = 0; j < blocklen; ++j) prg_out0[j] ^= tmp[j];
 
  
   if(!LR) 
   {  
    for(size_t r = 0; r <= rounds; ++r)  gen_view->middle[cur_depth-1].seed0L_encrypt[r] = outL[r];
   }
 
   if(LR) 
   {
    for(size_t r = 0; r <= rounds; ++r)  gen_view->middle[cur_depth-1].seed1L_encrypt[r] = outL[r];
   } 
   
   //blind64_T c2R[rounds+1];
   blind64_T * c2R = (blind64_T *) std::aligned_alloc(sizeof(__m256i), (rounds + 1) * sizeof(blind64_T));
   if(!LR) 
   {
    for(size_t r = 0; r <= rounds; ++r) c2R[r] = recv_view->middle[cur_depth-1].seed0R_encrypt[r];  
   }

   if(LR) 
   {
    for(size_t r = 0; r <= rounds; ++r) c2R[r] =  recv_view->middle[cur_depth-1].seed1R_encrypt[r];  
   }

   if(!party)
   {
     tmp = seed_; 
     tmp[0] = _mm_set1_epi64x_xor(seed_[0]);// ^ _mm_set1_epi64x(-1);
   }
   
   if(party)  tmp = seed_;
   
    blind64_T * outR = (blind64_T *) std::aligned_alloc(sizeof(__m256i), (rounds + 1) * sizeof(blind64_T));// blind64_T outR[rounds+1]; 
   auto prg_out1 = key.encrypt_MPC_verify_(tmp, c2R, blind, gamma, party, outR);
   
   if(!LR)for(size_t r = 0; r <= rounds; ++r) gen_view->middle[cur_depth-1].seed0R_encrypt[r] = outR[r];
   if(LR) for(size_t r = 0; r <= rounds; ++r) gen_view->middle[cur_depth-1].seed1R_encrypt[r] = outR[r];


   for(size_t j = 0; j < blocklen; ++j) prg_out1[j] ^= tmp[j];

    free(c2R);
    free(c2L);
    free(outL);
    free(outR); 
   return std::make_pair(std::move(prg_out0), std::move(prg_out1));
 }
 


template<typename prgkey_t>
inline void Verifier::expand_mpc_verify(const prgkey_t & key, const block64_T seed, const PB_transcript_64 * recv_view, PB_transcript_64* gen_view, block64_T &s0_L, block64_T & s0_R, 
                                        uint64_t & t0_L, uint64_t & t0_R,  blind64_T* blind, blind64_T* gamma, const bool party, const size_t cur_depth, const bool LR)
{ 
   auto prg_out =  prg_mpc_verify(key, seed, recv_view, gen_view,  blind,  gamma,  cur_depth, party, LR, 2);

   auto outL = prg_out.first;
   auto outR = prg_out.second;

   s0_L = outL;
   s0_R = outR; 
     
   t0_L = get_lsb_array(s0_L); 
   t0_R = get_lsb_array(s0_R);

   s0_L = clear_lsb_parallel(s0_L, 0b11);   
   s0_R = clear_lsb_parallel(s0_R, 0b11);     
}



template<typename leaf_t, typename node_t, typename prgkey_t>
void Verifier::middle_layers(const P2_transcript_64 * from_P2, const PB_transcript_64 * recv_view, PB_transcript_64* gen_view, const prgkey_t & key, const dpf_key<leaf_t, node_t, prgkey_t>& dpfkey, const size_t cur_depth, const bool party, const uint64_t challenge[2])
{
  
  block64_T cw_array = transpose64(dpfkey.cw[cur_depth]);  
  
  const block64_T seedL = seed0_prev;
  const block64_T seedR = seed1_prev;
  
  blind64_T * Pblinds = (blind64_T *) std::aligned_alloc(sizeof(__m256i), (rounds + 1) * sizeof(blind64_T)); 
     
    
  blind64_T *Pgamma[2];
   
  Pgamma[0] = (blind64_T *) std::aligned_alloc(sizeof(__m256i), (rounds + 1) * sizeof(blind64_T));
  Pgamma[1] = (blind64_T *) std::aligned_alloc(sizeof(__m256i), (rounds + 1) * sizeof(blind64_T));

  Gen_Blinds(Pblinds, challenge);
  
  for(size_t j = 0; j < rounds; ++j)
  {
    Pgamma[0][j] = from_P2->middle[cur_depth-1].gamma0[j];  
    Pgamma[1][j] = from_P2->middle[cur_depth-1].gamma0[j];
  } 
  
  
  block64_T s0_L,  s0_R; 
  uint64_t  t0_L, t0_R;
  
  if(!party) expand_mpc_verify(key, seedL, recv_view, gen_view, s0_L, s0_R, t0_L, t0_R, Pblinds, Pgamma[0], party, cur_depth, false);  
  if(party ) expand_mpc_verify(key, seedL, recv_view, gen_view, s0_L, s0_R, t0_L, t0_R, Pblinds, Pgamma[1], party, cur_depth, false);
 


  block64_T L0_shares_2, R0_shares_2;
  
  if(!party)
  {
    for(size_t i = 0; i < blocklen; ++i)
    {
     L0_shares_2[i] = xor_if(s0_L[i], cw_array[i], bit0_prev);
     R0_shares_2[i] = xor_if(s0_R[i], cw_array[i], bit0_prev);
    }
  } 
  if(party)
  {
    for(size_t i = 0; i < blocklen; ++i)
    {
      L0_shares_2[i] = xor_if(s0_L[i], cw_array[i], ( not_(bit0_prev)));
      R0_shares_2[i] = xor_if(s0_R[i], cw_array[i], ( not_(bit0_prev)));
    }
  }
 

   clear_lsb_parallel(L0_shares_2, 0b11);
   clear_lsb_parallel(R0_shares_2, 0b11);

    block64_T s1_L,  s1_R; 
  
    uint64_t t1_L, t1_R;
 
    Gen_Blinds(Pblinds, challenge);

    for(size_t j = 0; j < rounds; ++j)
    {
     Pgamma[0][j] = from_P2->middle[cur_depth-1].gamma1[j];  
     Pgamma[1][j] = from_P2->middle[cur_depth-1].gamma1[j];  
    } 
  
    if(!party) expand_mpc_verify(key, seedR,  recv_view, gen_view, s1_L, s1_R, t1_L, t1_R,  Pblinds, Pgamma[0], party, cur_depth, true);
    

    if(party)  expand_mpc_verify(key, seedR,  recv_view, gen_view, s1_L, s1_R, t1_L, t1_R,  Pblinds, Pgamma[1], party, cur_depth, true); 
  
   
    block64_T L1_shares_2, R1_shares_2;

    if(!party)
    {
      for(size_t i = 2; i < blocklen; ++i)
      {
       L1_shares_2[i] = xor_if(s1_L[i], cw_array[i], bit1_prev);
       R1_shares_2[i] = xor_if(s1_R[i], cw_array[i], bit1_prev);
      }
    }
    if(party)
    {
     for(size_t i = 2; i < blocklen; ++i)
     {
      L1_shares_2[i] = xor_if(s1_L[i], cw_array[i], ( not_(bit1_prev)));
      R1_shares_2[i] = xor_if(s1_R[i], cw_array[i], ( not_(bit1_prev)));
     }
    }
   
   clear_lsb_parallel(L1_shares_2, 0b11);
   clear_lsb_parallel(R1_shares_2, 0b11);

   
   conditional_swap_and_next_seed(recv_view, gen_view, from_P2, L0_shares_2, R0_shares_2, L1_shares_2, R1_shares_2,   party, cur_depth, challenge); 
   
     
   uint64_t bit0_L, bit0_R, bit1_L, bit1_R;
   
   bit0_L = xor_if(t0_L, cw_array[L], bit0_prev);
   bit0_R = xor_if(t0_R, cw_array[R], bit0_prev); 
   bit1_L = xor_if(t1_L, cw_array[L], bit1_prev); 
   bit1_R = xor_if(t1_R, cw_array[R], bit1_prev);
 
   get_next_bits(from_P2, recv_view, gen_view , bit0_L, bit0_R, bit1_L, bit1_R,  party, cur_depth, challenge);
 
 }


  template<typename leaf_t, typename node_t, typename prgkey_t>
  void Verifier::leaf_layer(const PB_transcript_64 * recv_view, PB_transcript_64* gen_view, const dpf_key<leaf_t, node_t, prgkey_t>& dpfkey, const uint64_t challenge[2])
  {
      
     std::array<block64_T, dpfkey.nodes_per_leaf> final_array;
     
     for(size_t j = 0; j < dpfkey.nodes_per_leaf; ++j)
     {
      final_array[j] = transpose64(dpfkey.finalizer[j]);
     }
     
     
     for(size_t i = 0; i < blocklen; ++i)
     {
       for(size_t j = 0; j < dpfkey.nodes_per_leaf; ++j)
       {
 
          seed0_prev[i] = xor_if(seed0_prev[i], final_array[j][i], bit0_prev); 
          seed1_prev[i] = xor_if(seed1_prev[i], final_array[j][i], bit1_prev); 
          gen_view->leaf.final_cw[i] =  (seed0_prev[i]   ^ seed1_prev[i]);     
        }         
      }
  }