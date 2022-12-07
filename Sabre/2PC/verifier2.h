class  Verifier2
{

  public:

  const size_t depth;
 
 
 
  
  Verifier2(randomness_prgkey_t randomness_prgkey, __m128i seed0_, __m128i seed1_, __m128i seed2_, size_t len, size_t depth_)
      : depth(depth_), P0rand(randomness_prgkey, seed0_, len), P1rand(randomness_prgkey, seed1_, len), P2rand(randomness_prgkey, seed2_, len)
  { 
    
 
 
  }

   template<typename prgkey_t>
   void Gen_Blinds(prgkey_t& key, block_t blinds0[], block_t blinds1[], block_t gamma[2][rounds]);

   void get_next_bits( P2_transcript& from_P2_to_P0, P2_transcript& from_P2_to_P1,   size_t cur_depth);
  
 
  
   void conditional_swap_and_next_seed( P2_transcript& from_P2_to_P0, P2_transcript& from_P2_to_P1,  size_t cur_depth);
  
   template<typename prgkey_t>
   void middle_layers(prgkey_t& key, P2_transcript& from_P2_to_P0, P2_transcript& from_P2_to_P1, size_t cur_depth);  

   void multiply_mpc(P2_transcript& from_P2_to_P0, P2_transcript& from_P2_to_P1,  size_t mul, size_t cur_depth);

   void multiply_mpc_b(P2_transcript& from_P2_to_P0, P2_transcript& from_P2_to_P1,  size_t mul, size_t cur_depth);
   
  template<typename prgkey_t>
   void root_layer(prgkey_t& key, P2_transcript& from_P2_to_P0, P2_transcript& from_P2_to_P1);
 

  ~ Verifier2()
  {

  }

//private:
  MPCrandomness P0rand, P1rand, P2rand;
  
};


template<typename prgkey_t>
  void Verifier2::Gen_Blinds(prgkey_t& key, block_t blinds0[rounds], block_t blinds1[rounds], block_t gamma[2][rounds])
  {
    block_t rand[rounds];
    for (unsigned r = 0; r < rounds; ++r)
     {        
        blinds0[r] = (P0rand.next_block() & key.mask_comp);
        blinds1[r] = (P1rand.next_block() & key.mask_comp);
        rand[r]    = (P2rand.next_block() & key.mask_comp);

        const block_t tmp1 = ((blinds0[r] >> 1) & blinds1[r]) ^ ((blinds1[r] >> 1) & blinds0[r]);
        const block_t tmp2 = ((blinds0[r] >> 2) & blinds1[r]) ^ ((blinds1[r] >> 2) & blinds0[r]);
    
        const block_t bc = (tmp1 << 2) & maska;
        const block_t ac = (tmp2 << 1) & maskb;
        const block_t ab = (tmp1 >> 1) & maskc;
    
        gamma[0][r] = ((bc | ac | ab) ^ rand[r]) & key.mask_comp;
        gamma[1][r] = rand[r];
     }
  }

 

  void Verifier2::multiply_mpc_b(P2_transcript& from_P2_to_P0, P2_transcript& from_P2_to_P1,  size_t mul, size_t cur_depth)
  {
    bool D0 = P0rand.next_bool(); 
    bool D1 = P1rand.next_bool(); 
     
    bool d0 = P0rand.next_bool();     
    bool d1 = P1rand.next_bool();
      
    const bool alpha = P2rand.next_bool(); 

    bool c0 = xor_if(alpha, D0, d1);
    bool c1 = xor_if(alpha, D1, d0);
  
    if(cur_depth == 0)
    {
     from_P2_to_P0.root.c_bit[mul]       = c0;
     from_P2_to_P1.root.c_bit[mul]       = c1;
    }

    if(cur_depth > 0)
    {
    from_P2_to_P0.middle[cur_depth-1].c_bit[mul]       = c0;
    from_P2_to_P1.middle[cur_depth-1].c_bit[mul]       = c1;
    }
    
  }


  void Verifier2::get_next_bits(P2_transcript& from_P2_to_P0, P2_transcript& from_P2_to_P1,  size_t cur_depth)
  {    
 
    multiply_mpc_b(from_P2_to_P0, from_P2_to_P1,  0, cur_depth); // L_0 * (direction - 1)
 
    multiply_mpc_b(from_P2_to_P0, from_P2_to_P1,  1, cur_depth); // L_1 * (direction - 1)
    
    multiply_mpc_b(from_P2_to_P0, from_P2_to_P1,  2, cur_depth);
 
    multiply_mpc_b(from_P2_to_P0, from_P2_to_P1,  3, cur_depth); // R_1 * direction     

  }
 

 
 


 
  void Verifier2::multiply_mpc(P2_transcript& from_P2_to_P0, P2_transcript& from_P2_to_P1,   size_t mul, size_t cur_depth)
  {   

    block_t D0 = P0rand.next_block();   
    block_t D1 = P1rand.next_block();
  
    bool d0 = P0rand.next_bool();   
    bool d1 = P1rand.next_bool(); 

    const block_t alpha = P2rand.next_block();

    block_t c0 = xor_if(alpha, D0, d1);
    block_t c1 = xor_if(alpha, D1, d0);
 
    if(cur_depth == 0)
    {
     from_P2_to_P0.root.c[mul] = c0;
     from_P2_to_P1.root.c[mul] = c1;
    }
    else
    {
     from_P2_to_P0.middle[cur_depth-1].c[mul] = c0;
     from_P2_to_P1.middle[cur_depth-1].c[mul] = c1;
    }
 
  }
   void Verifier2::conditional_swap_and_next_seed(P2_transcript& from_P2_to_P0, P2_transcript& from_P2_to_P1,  size_t cur_depth)
  {
     
 
 
     multiply_mpc(from_P2_to_P0, from_P2_to_P1, 0, cur_depth); // L_0 * direction 
 
     
     multiply_mpc(from_P2_to_P0, from_P2_to_P1, 1, cur_depth); // L_1 * direction     
 
     
     multiply_mpc(from_P2_to_P0, from_P2_to_P1, 2, cur_depth); // R_0 * direction      
 

     multiply_mpc(from_P2_to_P0, from_P2_to_P1, 3, cur_depth); // R_1 * direction
 
  }

 
  template<typename prgkey_t>
  void Verifier2::root_layer(prgkey_t& key, P2_transcript& from_P2_to_P0, P2_transcript& from_P2_to_P1)
  {
    size_t cur_depth = 0;

    block_t next_share; 
    bool next_bit;
       
    next_share = P0rand.next_block();
    next_share = P0rand.next_block();  
    next_share = P1rand.next_block();    
    next_share = P1rand.next_block();

    
        
      
    

    conditional_swap_and_next_seed(from_P2_to_P0, from_P2_to_P1,   cur_depth);

    next_bit = P0rand.next_bool();
    next_bit = P0rand.next_bool();
    next_bit = P1rand.next_bool();
    next_bit = P1rand.next_bool();

    get_next_bits( from_P2_to_P0, from_P2_to_P1,   cur_depth);

  }

  template<typename prgkey_t>
  void Verifier2::middle_layers(prgkey_t& key, P2_transcript& from_P2_to_P0, P2_transcript& from_P2_to_P1, size_t cur_depth) 
  {
    
    block_t P0gamma[2][rounds];
    block_t P0blinds0[rounds];
    block_t P0blinds1[rounds];

    Gen_Blinds(key, P0blinds0, P0blinds1, P0gamma);
    

    for(size_t j = 0; j < rounds; ++j)
    {
      from_P2_to_P0.middle[cur_depth-1].gamma0[j] = P0gamma[0][j];
      from_P2_to_P1.middle[cur_depth-1].gamma0[j] = P0gamma[1][j];
    } 
    
    block_t P1gamma[2][rounds];
    block_t P1blinds0[rounds];
    block_t P1blinds1[rounds];

    Gen_Blinds(key, P1blinds0, P1blinds1, P1gamma);
    
    for(size_t j = 0; j < rounds; ++j)
    {
      from_P2_to_P0.middle[cur_depth-1].gamma1[j] = P1gamma[0][j];
      from_P2_to_P1.middle[cur_depth-1].gamma1[j] = P1gamma[1][j]; 
    } 
  
   conditional_swap_and_next_seed(from_P2_to_P0, from_P2_to_P1, cur_depth);
   
   get_next_bits(from_P2_to_P0, from_P2_to_P1, cur_depth);  
 
 }


 