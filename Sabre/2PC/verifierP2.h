class  Verifier_P2
{

  public:

  const size_t depth;

  std::vector<bool> P0direction;
  std::vector<bool> P1direction;
  std::vector<uint64_t> P0direction_;
  std::vector<uint64_t> P1direction_;
  block64_T seed0_prev_L;
  block64_T seed0_prev_R;

  block64_T seed1_prev_L;
  block64_T seed1_prev_R;  

  uint64_t bit0_prev_L, bit0_prev_R, bit1_prev_L, bit1_prev_R;
   
  Verifier_P2(size_t depth_,  const randomness_prgkey_t key, blockT seed0_, blockT seed1_, blockT seed2_, size_t len)
      : depth(depth_), P0rand(key, seed0_, len), P1rand( key, seed1_, len), P2rand( key, seed2_, len)
  { 
    
    P0direction.reserve(depth_+1);
    P1direction.reserve(depth_+1);
    P0direction_.reserve(depth_+1);
    P1direction_.reserve(depth_+1);
  }



 
   void conditional_swap_and_next_seed(size_t cur_depth, const uint64_t not_challenge[2]);

   void Gen_Blinds(blind64_T gamma0[], blind64_T gamma1[], const uint64_t not_challenge[2]);

   void get_next_bits(size_t cur_depth, const uint64_t not_challenge[2]);

   auto multiply_mpc(const uint64_t not_challenge[2]);

 
   void root_layer(const uint64_t not_challenge[2]);
   
 
   void middle_layers(size_t cur_depth, const uint64_t not_challenge[2]);



  ~ Verifier_P2()
  {

  }

   MPCrandomness P0rand, P1rand, P2rand;
  
};


void Verifier_P2::Gen_Blinds(blind64_T gamma0[], blind64_T gamma1[], const uint64_t not_challenge[2])
{
 
 
  blind64_T blind0, blind1, rand_P2; 
  for(size_t r = 0; r < rounds; ++r)
  {    
      blind0  = P0rand.next_blind_64(not_challenge);
      blind1  = P1rand.next_blind_64(not_challenge);      
      rand_P2 = P2rand.next_blind_64(not_challenge);

      for (int i = 0, j = 0; i < numofboxes; ++i, j+=3)
      {
       gamma0[r][j + 0] = (blind0[j + 1] & blind1[j + 2]) ^ rand_P2[j+2];
       gamma1[r][j + 0] = (blind1[j + 1] & blind0[j + 2]) ^ rand_P2[j+2];

       gamma0[r][j + 1] = (blind0[j + 2] & blind1[j + 0]) ^ rand_P2[j+1];
       gamma1[r][j + 1] = (blind1[j + 2] & blind0[j + 0]) ^ rand_P2[j+1];

       gamma0[r][j + 2] = (blind0[j + 0] & blind1[j + 1]) ^ rand_P2[j+0];
       gamma1[r][j + 2] = (blind1[j + 0] & blind0[j + 1]) ^ rand_P2[j+0];
      }
 }

}

 


auto Verifier_P2::multiply_mpc(const uint64_t not_challenge[2])
  {   
 

    uint64_t D0 = P0rand.next_node_blind_64(not_challenge);   
    uint64_t D1 = P1rand.next_node_blind_64(not_challenge);
   
    uint64_t d0 = P0rand.next_node_blind_64(not_challenge);   
    uint64_t d1 = P1rand.next_node_blind_64(not_challenge); 

    uint64_t alpha = P2rand.next_node_blind_64(not_challenge); 

    std::array<uint64_t, 2> gamma;

    gamma[0] = xor_if(alpha, D0, d1);
    gamma[1] = xor_if(alpha, D1, d0);
 
    return gamma;
  }


  void Verifier_P2::get_next_bits(size_t cur_depth, const uint64_t not_challenge[2])
  {
 

 
    auto mul_out0 = multiply_mpc(not_challenge);
  
    if(cur_depth == 0)
    {
      P2_P0_view_V->root.next_bit_gamma[0] = mul_out0[0];
      P2_P1_view_V->root.next_bit_gamma[0] = mul_out0[1];
    }
    else
    {
      P2_P0_view_V->middle[cur_depth-1].next_bit_gamma[0] = mul_out0[0];
      P2_P1_view_V->middle[cur_depth-1].next_bit_gamma[0] = mul_out0[1];
    }
 
   auto mul_out = multiply_mpc(not_challenge);
   
   if(cur_depth == 0)
    {
      P2_P0_view_V->root.next_bit_gamma[1] = mul_out[0];
      P2_P1_view_V->root.next_bit_gamma[1] = mul_out[1];
    }
    else
    {
      P2_P0_view_V->middle[cur_depth-1].next_bit_gamma[1] = mul_out[0];
      P2_P1_view_V->middle[cur_depth-1].next_bit_gamma[1] = mul_out[1];
    }


 
 
  }
 
  void Verifier_P2::middle_layers(size_t cur_depth, const uint64_t not_challenge[2])
  {
 
    blind64_T * gamma0 = (blind64_T *) std::aligned_alloc(sizeof(__m256i), (rounds + 1) * sizeof(blind64_T)); 
    blind64_T * gamma1 = (blind64_T *) std::aligned_alloc(sizeof(__m256i), (rounds + 1) * sizeof(blind64_T)); 

    Gen_Blinds(gamma0, gamma1, not_challenge);
   
    for(size_t j = 0; j < rounds; ++j)
    {
      P2_P0_view_V->middle[cur_depth-1].gamma0[j] = gamma0[j];
      P2_P1_view_V->middle[cur_depth-1].gamma0[j] = gamma1[j];
    } 
 
   Gen_Blinds(gamma0, gamma1, not_challenge);
   
   for(size_t j = 0; j < rounds; ++j)
   {
    P2_P0_view_V->middle[cur_depth-1].gamma1[j] = gamma0[j];
    P2_P1_view_V->middle[cur_depth-1].gamma1[j] = gamma1[j];
   } 
 
   conditional_swap_and_next_seed(cur_depth, not_challenge);

   get_next_bits(cur_depth, not_challenge);

 
   free(gamma0);
   free(gamma1);
  }

 
   
 
 



  void Verifier_P2::conditional_swap_and_next_seed(size_t cur_depth, const uint64_t not_challenge[2])
  {

 
    

     for(size_t j = 0; j < blocklen; ++j)
     {      
 

        auto mul_out0 =  multiply_mpc(not_challenge);
     
        if(cur_depth == 0)
        {
          P2_P0_view_V->root.swap_gamma[0][j] = mul_out0[0];
          P2_P1_view_V->root.swap_gamma[0][j] = mul_out0[1];
        }
        else
        {
          P2_P0_view_V->middle[cur_depth-1].swap_gamma[0][j] = mul_out0[0]; 
          P2_P1_view_V->middle[cur_depth-1].swap_gamma[0][j] = mul_out0[1];
        }

        auto mul_out1 =  multiply_mpc(not_challenge);
 
        if(cur_depth == 0)
        {        
          P2_P0_view_V->root.swap_gamma[1][j] = mul_out1[0];
          P2_P1_view_V->root.swap_gamma[1][j] = mul_out1[1];
        } 
        else
        {
        
          P2_P0_view_V->middle[cur_depth-1].swap_gamma[1][j] = mul_out1[0];
         
          P2_P1_view_V->middle[cur_depth-1].swap_gamma[1][j] = mul_out1[1];
 
        }

 
     }  
  }

 
  void Verifier_P2::root_layer(const uint64_t not_challenge[2])
  {
    std::cout << "root_layer: " << std::endl;
    const size_t cur_depth = 0;
    
    block64_T  next_share;
    uint64_t next_bit;
       
    next_share = P0rand.next_block_64(not_challenge);   
    next_share = P0rand.next_block_64(not_challenge);
    next_share = P1rand.next_block_64(not_challenge);
    next_share = P1rand.next_block_64(not_challenge);

    conditional_swap_and_next_seed(cur_depth, not_challenge);
 
    next_bit = P0rand.next_node_blind_64(not_challenge); 
    next_bit = P0rand.next_node_blind_64(not_challenge);     
    next_bit = P1rand.next_node_blind_64(not_challenge);    
    next_bit = P1rand.next_node_blind_64(not_challenge); 
   
    get_next_bits(cur_depth, not_challenge);

 
  }

   