class  Simulator
{
 
  public:
 
  const size_t depth;

  std::vector<__m128i> P0direction_;
  std::vector<__m128i> P1direction_;
  
  blockT seed0_prev_L;
  blockT seed0_prev_R;
 
  blockT seed1_prev_L;
  blockT seed1_prev_R;  
 
  __m128i bit0_prev_L, bit0_prev_R, bit1_prev_L, bit1_prev_R;
    
  Simulator(const size_t depth_, const randomness_prgkey_t& randomness_prgkey, const prgkey_t& key, const blockT seed0_, const blockT seed1_, const blockT seed2_, const size_t len)
      : depth(depth_), P0rand( randomness_prgkey, seed0_, len), P1rand(randomness_prgkey, seed1_, len), P2rand(randomness_prgkey, seed2_, len)
  { 
     
    P0direction_.reserve(depth_+1);
    P1direction_.reserve(depth_+1);
  
  }
 
 
 
   
   void conditional_swap_and_next_seed(const blockT * s0_L, const blockT * s0_R, const blockT * s1_L, const blockT * s1_R, const size_t cur_depth);
 
   void Gen_Blinds(blindT* blind0, blindT*  blind1, blindT* gamma0, blindT* gamma1);
 
   void get_next_bits(const __m128i bit0_L[2], const __m128i bit0_R[2], const __m128i bit1_L[2], const __m128i bit1_R[2], const size_t cur_depth);
 
   template<typename prgkey_t>
   auto prg_mpc(const prgkey_t& key, blockT seed0, blockT seed1,  const blindT* blind0, const blindT* blind1, const blindT* gamma0, const blindT* gamma1, 
                const size_t cur_depth, const bool LR);
 
   template<typename prgkey_t>
   void expand_mpc(const prgkey_t& key, blockT seed0, blockT seed1, blockT s0[2], blockT s1[2], __m128i t0[2], __m128i t1[2], const blindT* blind0, 
                   const blindT* blind1, const blindT* gamma0, const blindT* gamma1, const size_t cur_depth, const bool LR);
 
   auto multiply_mpc(const __m128i& x0, const __m128i& b0, const __m128i& x1, const __m128i& b1, __m128i results[2],   const size_t cur_depth);
 
   template<typename leaf_t, typename node_t, typename prgkey_t>
   void root_layer(const prgkey_t& key, const dpf_key<leaf_t, node_t, prgkey_t>& dpfkey0, const dpf_key<leaf_t, node_t, prgkey_t>& dpfkey1);
    
   template<typename leaf_t, typename node_t, typename prgkey_t>
   void middle_layers(const prgkey_t& key, const dpf_key<leaf_t, node_t, prgkey_t>& dpfkey0, const dpf_key<leaf_t, node_t, prgkey_t>& dpfkey1, const size_t cur_depth);
 
   template<typename leaf_t, typename node_t, typename prgkey_t>
   void leaf_layer(const dpf_key<leaf_t, node_t, prgkey_t>& dpfkey0, const dpf_key<leaf_t, node_t, prgkey_t>& dpfkey1);  
 
 
  ~ Simulator()
  {
 
  }
 
   private:
    
   MPCrandomness P0rand, P1rand, P2rand;
   
};
 
 
void Simulator::Gen_Blinds(blindT* blind0, blindT*  blind1, blindT* gamma0, blindT* gamma1)
{
   
  for(size_t r = 0; r < rounds; ++r)
  {     
      blind0[r]  = P0rand.next_blind();
      blind1[r]  = P1rand.next_blind();      
      blindT rand_P2 = P2rand.next_blind();
 
      for (int i = 0, j = 0; i < numofboxes; ++i, j+=3)
      {
       gamma0[r][j + 0] = (blind0[r][j + 1] & blind1[r][j + 2]) ^ rand_P2[j+2];
       gamma1[r][j + 0] = (blind1[r][j + 1] & blind0[r][j + 2]) ^ rand_P2[j+2];
 
       gamma0[r][j + 1] = (blind0[r][j + 2] & blind1[r][j + 0]) ^ rand_P2[j+1];
       gamma1[r][j + 1] = (blind1[r][j + 2] & blind0[r][j + 0]) ^ rand_P2[j+1];
 
       gamma0[r][j + 2] = (blind0[r][j + 0] & blind1[r][j + 1]) ^ rand_P2[j+0];
       gamma1[r][j + 2] = (blind1[r][j + 0] & blind0[r][j + 1]) ^ rand_P2[j+0];
      }
 }
 
}
 
  
 
 
auto Simulator::multiply_mpc(const __m128i& x0, const __m128i& b0, const __m128i& x1, const __m128i& b1, __m128i results[2],  const size_t cur_depth)
  {   
  
 
    __m128i D0 = P0rand.next_node_blind();   
 
    __m128i D1 = P1rand.next_node_blind();
 
    __m128i d0 = P0rand.next_node_blind();   
 
    __m128i d1 = P1rand.next_node_blind(); 
 
 
    __m128i alpha = P2rand.next_node_blind(); 
 
 
  
    __m128i c0 = xor_if(alpha, D0, d1);
    __m128i c1 = xor_if(alpha, D1, d0);
  
    const __m128i gamma0 = xor_if(c0, (x1 ^ D1), d0);
 
    __m128i xx0 = x0;
 
    const __m128i gamma1 = xor_if(c1, (x0 ^ D0), d1);
     
    __m128i xx1 = x1;
  
    results[0] = xor_if(gamma0, xx0, (b0 ^ (b1 ^ d1))); 
    results[1] = xor_if(gamma1, xx1, (b1 ^ (b0 ^ d0))); 
 
    std::array<__m128i, 2> block_transpose;
    std::array<__m128i, 2> gamma;
    std::array<__m128i, 2> direction;
 
    block_transpose[0] = x0 ^ D0;
    gamma[0] = c0;
    direction[0] = b0 ^ d0;
 
    block_transpose[1] = x1 ^ D1;
    gamma[1]     = c1;
    direction[1] = b1 ^ d1;
     
 
    return std::make_pair(std::make_pair(block_transpose, gamma), direction);
  
  }
 
 
  void Simulator::get_next_bits(const __m128i bit0_L[2], const __m128i bit0_R[2], const __m128i bit1_L[2], const __m128i bit1_R[2], const size_t cur_depth)
  {

    __m128i L0_xor_R0[2] = {bit0_L[0] ^ bit0_R[0], bit0_L[1] ^ bit0_R[1]};  
    __m128i L1_xor_R1[2] = {bit1_L[0] ^ bit1_R[0], bit1_L[1] ^ bit1_R[1]};  
        
    __m128i b_L_xor_R0[2];
    __m128i b_L_xor_R1[2];
 
  
    auto mul_out0 = multiply_mpc(L0_xor_R0[0], P0direction_[cur_depth], L0_xor_R0[1], P1direction_[cur_depth], b_L_xor_R0, cur_depth);
   
    if(cur_depth == 0)
    {
      P0_view_->root.next_bit_block[0] = mul_out0.first.first[0];
      P2_P0_view->root.next_bit_gamma[0] = mul_out0.first.second[0];
      P0_view_->root.next_bit_bit_[0]   = mul_out0.second[0];
 
      P1_view_->root.next_bit_block[0] = mul_out0.first.first[1];
      P2_P1_view->root.next_bit_gamma[0] = mul_out0.first.second[1];
      P1_view_->root.next_bit_bit_[0]   = mul_out0.second[1];
    }
    else
    {
      P0_view_->middle[cur_depth-1].next_bit_block[0] = mul_out0.first.first[0];
      P2_P0_view->middle[cur_depth-1].next_bit_gamma[0] = mul_out0.first.second[0];
      P0_view_->middle[cur_depth-1].next_bit_bit_[0]   = mul_out0.second[0];
 
      P1_view_->middle[cur_depth-1].next_bit_block[0] = mul_out0.first.first[1];
      P2_P1_view->middle[cur_depth-1].next_bit_gamma[0] = mul_out0.first.second[1];
      P1_view_->middle[cur_depth-1].next_bit_bit_[0]   = mul_out0.second[1];
    }
  
   auto mul_out = multiply_mpc(L1_xor_R1[0], P0direction_[cur_depth], L1_xor_R1[1], P1direction_[cur_depth], b_L_xor_R1, cur_depth);
    
   if(cur_depth == 0)
    {
      P0_view_->root.next_bit_block[1] = mul_out.first.first[0];
      P2_P0_view->root.next_bit_gamma[1] = mul_out.first.second[0];
      P0_view_->root.next_bit_bit_[1]   = mul_out.second[0];
 
      P1_view_->root.next_bit_block[1] = mul_out.first.first[1];
      P2_P1_view->root.next_bit_gamma[1] = mul_out.first.second[1];
      P1_view_->root.next_bit_bit_[1]   = mul_out.second[1];
    }
    else
    {
      P0_view_->middle[cur_depth-1].next_bit_block[1] = mul_out.first.first[0];
      P2_P0_view->middle[cur_depth-1].next_bit_gamma[1] = mul_out.first.second[0];
      P0_view_->middle[cur_depth-1].next_bit_bit_[1]   = mul_out.second[0];
 
      P1_view_->middle[cur_depth-1].next_bit_block[1] = mul_out.first.first[1];
      P2_P1_view->middle[cur_depth-1].next_bit_gamma[1] = mul_out.first.second[1];
      P1_view_->middle[cur_depth-1].next_bit_bit_[1]   = mul_out.second[1];
    }
 
 
    bit0_prev_L = b_L_xor_R0[0] ^ bit0_L[0];    
    bit0_prev_R = b_L_xor_R0[1] ^ bit0_L[1]; 
    bit1_prev_L = b_L_xor_R1[0] ^ bit1_L[0];    
    bit1_prev_R = b_L_xor_R1[1] ^ bit1_L[1]; 
  
  }
 
 
  template<typename leaf_t, typename node_t, typename prgkey_t>
  void Simulator::middle_layers(const prgkey_t& key, const dpf_key<leaf_t, node_t, prgkey_t>& dpfkey0, const dpf_key<leaf_t, node_t, prgkey_t>& dpfkey1, const size_t cur_depth)
  {
  
 //  std::cout << "middle_layers: " << cur_depth << std::endl << std::endl;
     
   blockT cw_array = transpose(dpfkey0.cw[cur_depth]);
  
   blindT * blind0 = (blindT *) std::aligned_alloc(sizeof(__m256i), (rounds + 1) * sizeof(blindT)); 
   blindT * blind1 = (blindT *) std::aligned_alloc(sizeof(__m256i), (rounds + 1) * sizeof(blindT)); 
 
   blindT * gamma0 = (blindT *) std::aligned_alloc(sizeof(__m256i), (rounds + 1) * sizeof(blindT)); 
   blindT * gamma1 = (blindT *) std::aligned_alloc(sizeof(__m256i), (rounds + 1) * sizeof(blindT)); 
 
   blockT  *s0   = (blockT *) std::aligned_alloc(sizeof(__m256i), 2 * sizeof(blockT)); 
   blockT  *s1   = (blockT *) std::aligned_alloc(sizeof(__m256i), 2 * sizeof(blockT)); 
   blockT  *s0_L = (blockT *) std::aligned_alloc(sizeof(__m256i), 2 * sizeof(blockT)); 
   blockT  *s1_L = (blockT *) std::aligned_alloc(sizeof(__m256i), 2 * sizeof(blockT));
   blockT  *s0_R = (blockT *) std::aligned_alloc(sizeof(__m256i), 2 * sizeof(blockT)); 
   blockT  *s1_R = (blockT *) std::aligned_alloc(sizeof(__m256i), 2 * sizeof(blockT)); 
 
   __m128i t0[2], t1[2];
 
   Gen_Blinds(blind0, blind1, gamma0, gamma1);
    
    for(size_t j = 0; j < rounds; ++j)
    {
      P2_P0_view->middle[cur_depth-1].gamma0[j] = gamma0[j];
      P2_P1_view->middle[cur_depth-1].gamma0[j] = gamma1[j];
    } 
  
   expand_mpc(key, seed0_prev_L, seed0_prev_R, s0, s1, t0, t1, blind0, blind1, gamma0, gamma1, cur_depth, false);
  
   for(size_t j = 2; j < blocklen; ++j)
   {
     s0_L[L][j] =  xor_if(s0[L][j], cw_array[j], bit0_prev_L); 
     s0_L[R][j] =  xor_if(s1[L][j], cw_array[j], (bit0_prev_R ^ ones));      
     s0_R[L][j] =  xor_if(s0[R][j], cw_array[j], bit0_prev_L); 
     s0_R[R][j] =  xor_if(s1[R][j], cw_array[j], (bit0_prev_R ^ ones));     
   }
 
 
   clear_lsb_parallel(s0_L[L], 0b11); 
   clear_lsb_parallel(s0_L[R], 0b11); 
   clear_lsb_parallel(s0_R[L], 0b11); 
   clear_lsb_parallel(s0_R[R], 0b11);
 
   blockT ss0[2]; 
   blockT ss1[2]; 
 
   __m128i tt0[2], tt1[2];
 
   Gen_Blinds(blind0, blind1, gamma0, gamma1);
    
   for(size_t j = 0; j < rounds; ++j)
   {
     P2_P0_view->middle[cur_depth-1].gamma1[j] = gamma0[j];
     P2_P1_view->middle[cur_depth-1].gamma1[j] = gamma1[j];
   } 
 
   expand_mpc(key, seed1_prev_L, seed1_prev_R, ss0, ss1, tt0, tt1, blind0, blind1, gamma0, gamma1, cur_depth, true);
   
    for(size_t j = 2; j < blocklen; ++j)
    {
      s1_L[L][j] =  xor_if(ss0[L][j], cw_array[j], bit1_prev_L);   
      s1_L[R][j] =  xor_if(ss1[L][j], cw_array[j], (bit1_prev_R ^ ones));      
      s1_R[L][j] =  xor_if(ss0[R][j], cw_array[j], bit1_prev_L);      
      s1_R[R][j] =  xor_if(ss1[R][j], cw_array[j], (bit1_prev_R ^ ones));     
    }
    
   clear_lsb_parallel(s1_L[L], 0b11); 
   clear_lsb_parallel(s1_L[R], 0b11); 
   clear_lsb_parallel(s1_R[L], 0b11); 
   clear_lsb_parallel(s1_R[R], 0b11); 
 
 
   conditional_swap_and_next_seed(s0_L, s0_R, s1_L, s1_R, cur_depth);
 
 
   __m128i bit0_L[2] = {t0[0], t1[0]}; 
   bit0_L[0] = xor_if(t0[0], cw_array[L], bit0_prev_L);
   bit0_L[1] = xor_if(t1[0], cw_array[L], bit0_prev_R);
   
   
   __m128i bit0_R[2] = {t0[1], t1[1]};    
   bit0_R[0] = xor_if(t0[1], cw_array[R], bit0_prev_L);   
   bit0_R[1] = xor_if(t1[1], cw_array[R], bit0_prev_R);
      
   __m128i bit1_L[2] = {tt0[0], tt1[0]}; 
   bit1_L[0] = xor_if(tt0[0], cw_array[L], bit1_prev_L);
   bit1_L[1] = xor_if(tt1[0], cw_array[L], bit1_prev_R);   
 
 
   __m128i bit1_R[2] = {tt0[1], tt1[1]}; 
   bit1_R[0] = xor_if(tt0[1], cw_array[R], bit1_prev_L);
   bit1_R[1] = xor_if(tt1[1], cw_array[R], bit1_prev_R);
 
   get_next_bits(bit0_L, bit0_R, bit1_L, bit1_R, cur_depth);
     
   free(blind0);
   free(blind1);
   free(gamma0);
   free(gamma1);
   free(s0_L);
   free(s0_R);
   free(s1_L);
   free(s1_R);
   free(s0);
   free(s1);
 
  }
 
  
    
  template<typename prgkey_t>
  auto Simulator::prg_mpc(const prgkey_t& key, blockT seed0, blockT seed1, const blindT* blind0, const blindT* blind1, const blindT* gamma0, const blindT* gamma1, const size_t cur_depth, const bool LR)
  {

 
      blockT seed0_ = clear_lsb_parallel(seed0, 0b11);
      blockT seed1_ = clear_lsb_parallel(seed1, 0b11);
 
      size_t len = 2;
      size_t from = 0;
                 
      blockT tmp0 = seed0_;
      blockT tmp1 = seed1_;
  
       
      blindT ** encrypt_outL = (blindT **) std::aligned_alloc(sizeof(__m256i), (2) * sizeof(blindT *));
      blindT ** encrypt_outR = (blindT **) std::aligned_alloc(sizeof(__m256i), (2) * sizeof(blindT *));
 
 
      std::array< std::pair<blockT, blockT> , 2> PRG_out;
 
      for(size_t i = 0; i < 2; ++i)
      {
        encrypt_outL[i] = (blindT *) std::aligned_alloc(sizeof(__m256i), (rounds + 1) * sizeof(blindT));
        encrypt_outR[i] = (blindT *) std::aligned_alloc(sizeof(__m256i), (rounds + 1) * sizeof(blindT));
      }
 
      
 
      PRG_out[0] = key.encrypt_MPC_proof_(tmp0, tmp1, blind0, blind1, gamma0, gamma1, encrypt_outL[0], encrypt_outR[0]);  
       
  
      if(!LR)
      {
       for(size_t r = 0; r <= rounds; ++r)
        {
          P1_view_->middle[cur_depth-1].seed0L_encrypt[r] = encrypt_outR[0][r];
          P0_view_->middle[cur_depth-1].seed0L_encrypt[r] = encrypt_outL[0][r];
        }
      }
 
      
     if(LR)
      {
       for(size_t r = 0; r <= rounds; ++r)
        {
          P1_view_->middle[cur_depth-1].seed1L_encrypt[r] = encrypt_outR[0][r];
          P0_view_->middle[cur_depth-1].seed1L_encrypt[r] = encrypt_outL[0][r];
        }
      }
 
      for(size_t t = 0; t < blocklen; ++t) PRG_out[0].first[t]  = PRG_out[0].first[t]   ^ tmp0[t];
      for(size_t t = 0; t < blocklen; ++t) PRG_out[0].second[t] = PRG_out[0].second[t]  ^ tmp1[t];
 
      for (size_t i = 1; i < len; ++i)
      {
 
        tmp0[0] = seed0_[0] ^ _mm_set1_epi64x(-1); 
  
        PRG_out[i] = key.encrypt_MPC_proof_(tmp0, tmp1, blind0, blind1, gamma0, gamma1, encrypt_outL[i], encrypt_outR[i]);  
 
        if(!LR)
        {
         for(size_t r = 0; r <= rounds; ++r)
          {
            P1_view_->middle[cur_depth-1].seed0R_encrypt[r] = encrypt_outR[i][r];
            P0_view_->middle[cur_depth-1].seed0R_encrypt[r] = encrypt_outL[i][r];
          }
        }
 
       if(LR)
        {
         for(size_t r = 0; r <= rounds; ++r)
          {
            P1_view_->middle[cur_depth-1].seed1R_encrypt[r] = encrypt_outR[i][r];
            P0_view_->middle[cur_depth-1].seed1R_encrypt[r] = encrypt_outL[i][r];
          }
        }
 
        for(size_t t = 0; t < blocklen; ++t) PRG_out[i].first[t]  = PRG_out[i].first[t]  ^ tmp0[t];
        for(size_t t = 0; t < blocklen; ++t) PRG_out[i].second[t] = PRG_out[i].second[t] ^ tmp1[t];
       
      } 
 
      for(size_t i = 0; i < 2; ++i)
      {
       free(encrypt_outL[i]); 
       free(encrypt_outR[i]);
      }
      free(encrypt_outL);
      free(encrypt_outR);

     return std::move(PRG_out);//  std::make_pair(encrypt_outL, encrypt_outR);
  }
   
 
  template<typename prgkey_t>
  void Simulator::expand_mpc(const prgkey_t& key, blockT seed0, blockT seed1, blockT s0[2], blockT s1[2], __m128i t0[2], __m128i t1[2],
                             const blindT* blind0, const blindT* blind1, const blindT* gamma0, const blindT* gamma1, const size_t cur_depth, const bool LR)
  {
  
  
   auto prg_out = prg_mpc(key, seed0, seed1, blind0, blind1, gamma0, gamma1, cur_depth, LR);
    
   auto prg_out_L = prg_out[0];
   auto prg_out_R = prg_out[1];
 
   s0[L] = prg_out_L.first;//[rounds];
   s0[R] = prg_out_R.first;//[rounds];
 
   s1[L] = prg_out_L.second;//[rounds];
   s1[R] = prg_out_R.second;//[rounds];
 
   t0[L] = get_lsb_array(s0[L]);
   t1[L] = get_lsb_array(s1[L]);
   s0[L] = clear_lsb_parallel(s0[L], 0b11);
   s1[L] = clear_lsb_parallel(s1[L], 0b11);
 
   t0[R] = get_lsb_array(s0[R]);
   t1[R] = get_lsb_array(s1[R]);
   s0[R] = clear_lsb_parallel(s0[R], 0b11);
   s1[R] = clear_lsb_parallel(s1[R], 0b11); 
    
  }
 
 
 
 
  void Simulator::conditional_swap_and_next_seed(const blockT * s0_L, const blockT * s0_R, const blockT * s1_L, const blockT * s1_R, const size_t cur_depth)
  {

 
 
     blockT bL_xor_R0, bL_xor_R1;
      
     blockT LEFT0, LEFT1;
 
     for(size_t j = 0; j < blocklen; ++j) 
     {      
        __m128i L0_xor_R0[2] = {s0_L[0][j] ^ s0_R[0][j], s0_L[1][j] ^ s0_R[1][j]};  
        __m128i L1_xor_R1[2] = {s1_L[0][j] ^ s1_R[0][j], s1_L[1][j] ^ s1_R[1][j]};  
          
        __m128i b_L_xor_R0[2];
        __m128i b_L_xor_R1[2];
 
        auto mul_out0 =  multiply_mpc(L0_xor_R0[0], P0direction_[cur_depth], L0_xor_R0[1], P1direction_[cur_depth], b_L_xor_R0, cur_depth);
      
        if(cur_depth == 0)
        {
          P0_view_->root.swap_block[0][j]    = mul_out0.first.first[0];
          P2_P0_view->root.swap_gamma[0][j] = mul_out0.first.second[0];
          P0_view_->root.swap_bit_[0][j]      = mul_out0.second[0];
 
          P1_view_->root.swap_block[0][j]    = mul_out0.first.first[1];
          P2_P1_view->root.swap_gamma[0][j] = mul_out0.first.second[1];
          P1_view_->root.swap_bit_[0][j]      = mul_out0.second[1];
        }
        else
        {
          P0_view_->middle[cur_depth-1].swap_block[0][j]    = mul_out0.first.first[0];
          P2_P0_view->middle[cur_depth-1].swap_gamma[0][j] = mul_out0.first.second[0];
          P0_view_->middle[cur_depth-1].swap_bit_[0][j]      = mul_out0.second[0];
 
          P1_view_->middle[cur_depth-1].swap_block[0][j]    = mul_out0.first.first[1];
          P2_P1_view->middle[cur_depth-1].swap_gamma[0][j] = mul_out0.first.second[1];
          P1_view_->middle[cur_depth-1].swap_bit_[0][j]      = mul_out0.second[1];
        }
 
        auto mul_out1 =  multiply_mpc(L1_xor_R1[0], P0direction_[cur_depth], L1_xor_R1[1], P1direction_[cur_depth], b_L_xor_R1, cur_depth);
  
        if(cur_depth == 0)
        {
          P0_view_->root.swap_block[1][j]    = mul_out1.first.first[0];
          P2_P0_view->root.swap_gamma[1][j] = mul_out1.first.second[0];
          P0_view_->root.swap_bit_[1][j]      = mul_out1.second[0];
 
          P1_view_->root.swap_block[1][j]    = mul_out1.first.first[1];
          P2_P1_view->root.swap_gamma[1][j] = mul_out1.first.second[1];
          P1_view_->root.swap_bit_[1][j]      = mul_out1.second[1];
        } 
        else
        {
          P0_view_->middle[cur_depth-1].swap_block[1][j]    = mul_out1.first.first[0];
          P2_P0_view->middle[cur_depth-1].swap_gamma[1][j] = mul_out1.first.second[0];
          P0_view_->middle[cur_depth-1].swap_bit_[1][j]      = mul_out1.second[0];
 
          P1_view_->middle[cur_depth-1].swap_block[1][j]    = mul_out1.first.first[1];
          P2_P1_view->middle[cur_depth-1].swap_gamma[1][j] = mul_out1.first.second[1];
          P1_view_->middle[cur_depth-1].swap_bit_[1][j]      = mul_out1.second[1];
        }
 
        bL_xor_R0[j] =  b_L_xor_R0[0] ^ b_L_xor_R0[1];
        bL_xor_R1[j] =  b_L_xor_R1[0] ^ b_L_xor_R1[1];
    
        LEFT0[j] =  b_L_xor_R0[0] ^ b_L_xor_R1[0] ^ (s0_L[0][j] ^ s1_L[0][j]);
        LEFT1[j] =  b_L_xor_R1[1] ^ b_L_xor_R0[1] ^ (s0_L[1][j] ^ s1_L[1][j]);
 
        zero_share0[cur_depth][j] = LEFT0[j] ^ L0_xor_R0[0] ^ L1_xor_R1[0];
        zero_share1[cur_depth][j] =  LEFT1[j] ^ L0_xor_R0[1] ^ L1_xor_R1[1];
 
        seed0_prev_L[j] = b_L_xor_R0[0] ^ s0_L[0][j];      
        seed0_prev_R[j] = b_L_xor_R0[1] ^ s0_L[1][j];
        seed1_prev_L[j] = b_L_xor_R1[0] ^ s1_L[0][j];
        seed1_prev_R[j] = b_L_xor_R1[1] ^ s1_L[1][j];
     }
 
      
     // std::cout << "zero      = ";
     // for(size_t j = 0; j < blocklen; ++j)
     // {
     //  std::cout << (block<__m128i>(zero_share0[cur_depth][j] ^ zero_share1[cur_depth][j])).bits[0];
     // }
     // std::cout << std::endl << " --- " << std::endl;
     // for(size_t j = 0; j < blocklen; ++j)
     // {
     //  std::cout << (block<__m128i>(zero_share0[cur_depth][j])).bits[0];
     // }
     // std::cout << std::endl << " --- " << std::endl;
     // for(size_t j = 0; j < blocklen; ++j)
     // {
     //  std::cout << (block<__m128i>(zero_share1[cur_depth][j])).bits[0];
     // }
     //hash(T val , byte_t hashed_val[])
     //std::cout << std::endl << " --- " << std::endl;
      
  }
 
  template<typename leaf_t, typename node_t, typename prgkey_t>
  void Simulator::root_layer(const prgkey_t & prgkey, const dpf_key<leaf_t, node_t, prgkey_t>& dpfkey0, const dpf_key<leaf_t, node_t, prgkey_t>& dpfkey1)
  {
    
    std::cout << "root_layer: " << std::endl;
    const size_t cur_depth = 0;
     
    blockT seed0_array = transpose(dpfkey0.root);
    blockT seed1_array = transpose(dpfkey1.root);
  
    blockT cw_array = transpose(dpfkey0.cw[0]);
 
    __m128i t0[2], t1[2];
    
    blockT* s0 = (blockT *) std::aligned_alloc(sizeof(__m256i), 2 * sizeof(blockT));
    blockT* s1 = (blockT *) std::aligned_alloc(sizeof(__m256i), 2 * sizeof(blockT));
     
     
    expand_parallel(prgkey, seed0_array, s0, t0);
     
    expand_parallel(prgkey, seed1_array,  s1 , t1); 
    
   // // s0[L] and s0[R] are P0's left and right children after the correction word is applied
    bool root_t = _mm_testz_si128(seed0_array[0], seed0_array[0]);
    
       
    for(size_t j = 2; j < blocklen; ++j)
    {
      if(root_t)
      {
        s0[L][j] ^=  cw_array[j];
        s0[R][j] ^=  cw_array[j];
      }
      else
      {
        s1[L][j] ^=  cw_array[j];
        s1[R][j] ^=  cw_array[j];  
      }
    }
  
    clear_lsb_parallel(s0[L], 0b11);
    clear_lsb_parallel(s0[R], 0b11);
    clear_lsb_parallel(s1[L], 0b11);
    clear_lsb_parallel(s1[R], 0b11);
 
    blockT* s0_L = (blockT *) std::aligned_alloc(sizeof(__m256i), 2 * sizeof(blockT));
    blockT* s0_R = (blockT *) std::aligned_alloc(sizeof(__m256i), 2 * sizeof(blockT));
    blockT* s1_L = (blockT *) std::aligned_alloc(sizeof(__m256i), 2 * sizeof(blockT));
    blockT* s1_R = (blockT *) std::aligned_alloc(sizeof(__m256i), 2 * sizeof(blockT));
    
    s0_L[0] = P0rand.next_block();   
    s0_R[0] = P0rand.next_block();

    s1_L[0] = P1rand.next_block();
    s1_R[0] = P1rand.next_block();


   
    for(size_t j = 0; j < blocklen; ++j)
    {
     s0_L[R][j] = s0_L[L][j] ^ s0[L][j];
     s0_R[R][j] = s0_R[L][j] ^ s0[R][j]; 
    }
 
    for(size_t j = 0; j < blocklen; ++j)
    { 
     s1_L[R][j] = s1_L[L][j] ^ s1[L][j];
     s1_R[R][j] = s1_R[L][j] ^ s1[R][j]; 
    }
  


    for(size_t j = 0; j < blocklen; ++j) P1_view_->root.L_shares_recv[j] = s1_L[0][j];
    for(size_t j = 0; j < blocklen; ++j) P1_view_->root.R_shares_recv[j] = s1_R[0][j];  
 
    for(size_t j = 0; j < blocklen; ++j) P0_view_->root.L_shares_recv[j] = s0_L[1][j];
    for(size_t j = 0; j < blocklen; ++j) P0_view_->root.R_shares_recv[j] = s0_R[1][j];  
 
    conditional_swap_and_next_seed(s0_L, s0_R, s1_L, s1_R, cur_depth);
    
    __m128i bit0_L[2];
    bit0_L[0] = P0rand.next_node_blind(); 
 
    bit0_L[1] = root_t ? bit0_L[0] ^ t0[L] : bit0_L[0] ^ t0[L] ^ cw_array[L];
 
    __m128i bit0_R[2];
    bit0_R[0] = P0rand.next_node_blind(); 
 
    bit0_R[1] = root_t ? bit0_R[0] ^ t0[R] : bit0_R[0] ^ t0[R]^ cw_array[R];
 
    __m128i bit1_L[2];
    bit1_L[0] = P1rand.next_node_blind(); 
 
    bit1_L[1] = !root_t ? bit1_L[0] ^ t1[L] : bit1_L[0] ^ t1[L] ^ cw_array[L];
 
    __m128i bit1_R[2];
    bit1_R[0] = P1rand.next_node_blind(); 
 
    bit1_R[1] = !root_t ? bit1_R[0] ^ t1[R] : bit1_R[0] ^ t1[R] ^ cw_array[R];
 
    P1_view_->root.bit_L_shares_recv = bit1_L[0];
    P1_view_->root.bit_R_shares_recv = bit1_R[0];  
 
    P0_view_->root.bit_L_shares_recv = bit0_L[1];
    P0_view_->root.bit_R_shares_recv = bit0_R[1];  
 
    get_next_bits(bit0_L, bit0_R, bit1_L, bit1_R, cur_depth);
 
  
  }
 
    
 template<typename leaf_t, typename node_t, typename prgkey_t>
 void Simulator::leaf_layer(const dpf_key<leaf_t, node_t, prgkey_t>& dpfkey0, const dpf_key<leaf_t, node_t, prgkey_t>& dpfkey1) 
 {
     
     std::array<blockT, dpfkey0.nodes_per_leaf> final0_array, final1_array;
      
     for(size_t j = 0; j < dpfkey0.nodes_per_leaf; ++j)
     {
      final0_array[j] = transpose(dpfkey0.finalizer[j]);
      final1_array[j] = transpose(dpfkey1.finalizer[j]);
     }
  
    for(size_t i = 0; i < blocklen; ++i)
    {
        for(size_t j = 0; j < dpfkey0.nodes_per_leaf; ++j)
        {
         seed0_prev_L[i] = xor_if(seed0_prev_L[i], final0_array[j][i], bit0_prev_L);
         seed0_prev_R[i] = xor_if(seed0_prev_R[i], final0_array[j][i], bit0_prev_R);
 
         seed1_prev_L[i] = xor_if(seed1_prev_L[i], final1_array[j][i], bit1_prev_L);
         seed1_prev_R[i] = xor_if(seed1_prev_R[i], final1_array[j][i], bit1_prev_R);
 
         P0_view_->leaf.final_cw[i] = seed0_prev_L[i] ^ seed1_prev_L[i];
         P1_view_->leaf.final_cw[i] = seed0_prev_R[i] ^ seed1_prev_R[i];
        }
 
    }
        
 
        blockT final_out;
         
        for(size_t i = 0; i < blocklen; ++i)  final_out[i] = (seed0_prev_L[i] ^ seed0_prev_R[i] ^ seed1_prev_L[i] ^ seed1_prev_R[i]);
 
        std::cout << std::endl << "final_out: ";  print_first_col(final_out);
          
 }