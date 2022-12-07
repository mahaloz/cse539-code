 struct  from_PB_root_64
 {
  
   block64_T  L_shares_recv, R_shares_recv; // root layer  

   uint64_t bit_L_shares_recv, bit_R_shares_recv; // root layer
   
   uint64_t swap_block[2][blocklen];
   uint64_t swap_bit_[2][blocklen];

   uint64_t next_bit_block[2];
   uint64_t next_bit_bit_[2];
 };
 
 struct from_PB_middle_64
 {
  
  blind64_T seed0L_encrypt[rounds+1]; // Used in encrypt
  blind64_T seed0R_encrypt[rounds+1]; // Used in encrypt
  blind64_T seed1L_encrypt[rounds+1]; // Used in encrypt
  blind64_T seed1R_encrypt[rounds+1]; // Used in encrypt
  
  uint64_t swap_block[2][blocklen];
  uint64_t swap_bit_[2][blocklen]; 
  uint64_t next_bit_block[2];
  uint64_t next_bit_bit_[2];
 
 };

 struct from_PB_leaf_64
 {
  block64_T final_cw; // final layer
 };
 
 struct PB_transcript_64
 {
  from_PB_root_64   root;
  from_PB_middle_64  * middle;
  from_PB_leaf_64 leaf;
 };






  struct from_P2_root_64
  {   
   uint64_t swap_gamma[2][blocklen];
   uint64_t next_bit_gamma[2];
  }; 


  struct from_P2_middle_64
  {    
    blind64_T gamma0[rounds]; // Used in encrypt
    blind64_T gamma1[rounds]; // Used in encrypt
    
    uint64_t swap_gamma[2][blocklen];
    uint64_t next_bit_gamma[2];

  };

  struct from_P2_leaf_64
  {
    size_t data = 0;
  };


  struct P2_transcript_64
  {
    from_P2_root_64   root;
    from_P2_middle_64 *middle;
    from_P2_leaf_64 leaf ;
  };






 struct  from_PB_root
 {
  
   blockT  L_shares_recv, R_shares_recv; // root layer  

   __m128i bit_L_shares_recv, bit_R_shares_recv; // root layer
   
   __m128i swap_block[2][blocklen];
   __m128i swap_bit_[2][blocklen];

   __m128i next_bit_block[2];
   __m128i next_bit_bit_[2];


 
 };
 
 struct from_PB_middle
 {
  
  blindT seed0L_encrypt[rounds+1]; // Used in encrypt
  blindT seed0R_encrypt[rounds+1]; // Used in encrypt
  blindT seed1L_encrypt[rounds+1]; // Used in encrypt
  blindT seed1R_encrypt[rounds+1]; // Used in encrypt
  
  __m128i swap_block[2][blocklen];
  __m128i swap_bit_[2][blocklen]; 

  __m128i next_bit_block[2];
  __m128i next_bit_bit_[2];

 

 };

 struct from_PB_leaf
 {
   blockT final_cw; // final layer

   void zero_out_cols(__m128i& challange)
   {
   for(size_t j = 0; j < blocklen; ++j)
    {
      final_cw[j] = _mm_and_si128(final_cw[j], challange);
    }
   }
 };
 
 struct PB_transcript
 {
  from_PB_root   root;
  from_PB_middle  * middle;
  from_PB_leaf leaf;
 };




 struct  from_PB_rootT
 {
    bool L_shares_recv[blocklen], R_shares_recv[blocklen]; // root layer  
   
    bool swap_block[2][blocklen];
    bool swap_bit_[2][blocklen];

    bool next_bit_block[2];
    bool next_bit_bit_[2];

    bool bit_L_shares_recv, bit_R_shares_recv; // root layer   
 };
 
 struct from_PB_middleT
 {
    bool seed0L_encrypt[3 * numofboxes][rounds+1]; // Used in encrypt
    bool seed0R_encrypt[3 * numofboxes][rounds+1]; // Used in encrypt
    bool seed1L_encrypt[3 * numofboxes][rounds+1]; // Used in encrypt
    bool seed1R_encrypt[3 * numofboxes][rounds+1]; // Used in encrypt
  
    bool swap_block[2][blocklen];
    bool swap_bit_[2][blocklen]; 

    bool next_bit_block[2];
    bool next_bit_bit_[2];
 };

 struct from_PB_leafT
 {
     bool final_cw[blocklen];
     // bool final_cw[blocklen]; // final layer
 };
 
 struct PB_transcriptT
 {
  from_PB_rootT   rootT;
  from_PB_middle_64 middleT[depth-1];
  from_PB_leafT   leafT;
 };





  struct from_P2_root
  {   
   __m128i swap_gamma[2][blocklen];
   __m128i next_bit_gamma[2];
  }; 


  struct from_P2_middle
  {    
    blindT gamma0[rounds]; // Used in encrypt
    blindT gamma1[rounds]; // Used in encrypt
    
   __m128i swap_gamma[2][blocklen];
   __m128i next_bit_gamma[2];

  };

  struct from_P2_leaf
  {
    size_t data = 0;
  };


  struct P2_transcript
  {
    from_P2_root   root;
    from_P2_middle *middle;
    from_P2_leaf leaf ;
  };

 
 struct from_P2_rootT
  {   
   bool swap_gamma[2][blocklen];
   bool next_bit_gamma[2];
  }; 


  struct from_P2_middleT
  {    
    bool gamma0[3 * numofboxes ][rounds]; // Used in encrypt
    bool gamma1[3 * numofboxes ][rounds]; // Used in encrypt
    
   bool swap_gamma[2][blocklen];
   bool next_bit_gamma[2];

  };

  struct from_P2_leafT
  {
    size_t data = 0;
  };


  struct P2_transcriptT
  {
    from_P2_rootT  rootT;
    from_P2_middleT middleT[depth-1];
    from_P2_leafT leafT ;
  };



template<typename leaf_t, typename node_t, typename prgkey_t>  
struct Proof
{
  PB_transcript_64 PB_view;
  P2_transcript_64 P2_view; 
};


 inline void transpose_transcript(PB_transcript_64 * view, PB_transcriptT viewT[])
 {
  for(size_t i = 0; i < 64; ++i)
  {
    viewT[i].rootT.bit_L_shares_recv =  ((view->root.bit_L_shares_recv & (1ULL << i)) >> i);
    viewT[i].rootT.bit_R_shares_recv =  ((view->root.bit_R_shares_recv & (1ULL << i)) >> i);
    

   
    viewT[i].rootT.next_bit_bit_[0]  = ((view->root.next_bit_bit_[0] & (1ULL << i)) >> i);
    viewT[i].rootT.next_bit_bit_[1]  = ((view->root.next_bit_bit_[1] & (1ULL << i)) >> i);

    viewT[i].rootT.next_bit_block[0] = ((view->root.next_bit_block[0] & (1ULL << i)) >> i);
    viewT[i].rootT.next_bit_block[1] = ((view->root.next_bit_block[1] & (1ULL << i)) >> i);

    for(size_t j = 0; j < blocklen; ++j)
    {

     viewT[i].rootT.L_shares_recv[j] = ((view->root.L_shares_recv[j] & (1ULL << i)) >> i);
     viewT[i].rootT.R_shares_recv[j] = ((view->root.R_shares_recv[j] & (1ULL << i)) >> i);
     
     viewT[i].rootT.swap_bit_[0][j]  = ((view->root.swap_bit_[0][j] & (1ULL << i)) >> i);
     viewT[i].rootT.swap_bit_[1][j]  = ((view->root.swap_bit_[1][j]& (1ULL << i)) >> i);

     viewT[i].rootT.swap_block[0][j] = ((view->root.swap_block[0][j] & (1ULL << i)) >> i);
     viewT[i].rootT.swap_block[1][j] = ((view->root.swap_block[1][j] & (1ULL << i)) >> i);
     viewT[i].leafT.final_cw[j]      = ((view->leaf.final_cw[j] & (1ULL << i)) >> i);
    }
  }

 
  for(size_t i = 0; i < 64; ++i)
  {
    for(size_t cur_depth  = 0; cur_depth < depth - 1; ++cur_depth)
    {


      viewT[i].middleT[cur_depth].next_bit_bit_[0] = ((view->middle[cur_depth].next_bit_bit_[0] & (1ULL << i)) >> i);
      viewT[i].middleT[cur_depth].next_bit_bit_[1] = ((view->middle[cur_depth].next_bit_bit_[1] & (1ULL << i)) >> i);

      viewT[i].middleT[cur_depth].next_bit_block[0] = ((view->middle[cur_depth].next_bit_block[0] & (1ULL << i)) >> i);
      viewT[i].middleT[cur_depth].next_bit_block[1] = ((view->middle[cur_depth].next_bit_block[1] & (1ULL << i)) >> i);

      for(size_t j = 0; j < blocklen; ++j)
      {
       viewT[i].middleT[cur_depth].swap_bit_[0][j] = ((view->middle[cur_depth].swap_bit_[0][j] & (1ULL << i)) >> i);
       viewT[i].middleT[cur_depth].swap_bit_[1][j] = ((view->middle[cur_depth].swap_bit_[1][j] & (1ULL << i)) >> i);

       viewT[i].middleT[cur_depth].swap_block[0][j] = ((view->middle[cur_depth].swap_block[0][j] & (1ULL << i)) >> i);
       viewT[i].middleT[cur_depth].swap_block[1][j] = ((view->middle[cur_depth].swap_block[1][j] & (1ULL << i)) >> i);
      }

      for(size_t j = 0; j < 3 * numofboxes; ++j)
      {
        for(size_t r = 0; r < rounds + 1; ++r)
        {
         viewT[i].middleT[cur_depth].seed0L_encrypt[j][r] = ((view->middle[cur_depth].seed0L_encrypt[r][j] & (1ULL << i)) >> i);
         viewT[i].middleT[cur_depth].seed0R_encrypt[j][r] = ((view->middle[cur_depth].seed0R_encrypt[r][j] & (1ULL << i)) >> i);
         viewT[i].middleT[cur_depth].seed1L_encrypt[j][r] = ((view->middle[cur_depth].seed1L_encrypt[r][j] & (1ULL << i)) >> i);
         viewT[i].middleT[cur_depth].seed1R_encrypt[j][r] = ((view->middle[cur_depth].seed1R_encrypt[r][j] & (1ULL << i)) >> i);
        }
      }
    }
  }
 }


 inline void transpose_transcript(P2_transcript_64 * view, P2_transcriptT viewT[])
 {

 
  for(size_t i = 0; i < 64; ++i)
  {  
 
    viewT[i].rootT.next_bit_gamma[0] = ((view->root.next_bit_gamma[0] & (1ULL << i)) >> i);
    viewT[i].rootT.next_bit_gamma[1] = ((view->root.next_bit_gamma[1] & (1ULL << i)) >> i);

    for(size_t j = 0; j < blocklen; ++j)
    {
     viewT[i].rootT.swap_gamma[0][j] = ((view->root.swap_gamma[0][j] & (1ULL << i)) >> i);
     viewT[i].rootT.swap_gamma[1][j] = ((view->root.swap_gamma[1][j] & (1ULL << i)) >> i); 
    }
  }


    for(size_t i = 0; i < 64; ++i)
    {
      for(size_t cur_depth  = 0; cur_depth < depth - 1; ++cur_depth)
      {
        viewT[i].middleT[cur_depth].next_bit_gamma[0] = ((view->middle[cur_depth].next_bit_gamma[0] & (1ULL << i)) >> i);
        viewT[i].middleT[cur_depth].next_bit_gamma[1] = ((view->middle[cur_depth].next_bit_gamma[1] & (1ULL << i)) >> i);

        for(size_t j = 0; j < blocklen; ++j)
        {
         viewT[i].middleT[cur_depth].swap_gamma[0][j] = ((view->middle[cur_depth].swap_gamma[0][j] & (1ULL << i)) >> i);
         viewT[i].middleT[cur_depth].swap_gamma[1][j] =  ((view->middle[cur_depth].swap_gamma[1][j] & (1ULL << i)) >> i);
        }

        for(size_t j = 0; j < 3 * numofboxes; ++j)
        {
          for(size_t r = 0; r < rounds; ++r)
          {
           viewT[i].middleT[cur_depth].gamma0[j][r] =  ((view->middle[cur_depth].gamma0[r][j] & (1ULL << i)) >> i);
           viewT[i].middleT[cur_depth].gamma1[j][r] =  ((view->middle[cur_depth].gamma1[r][j] & (1ULL << i)) >> i);
          }
        }
      }
    }


 }


 uint64_t __m128i_to_uint64_t(__m128i& x, const uint64_t challenge[2])
{
  uint64_t out;
  uint32_t * tmp = (uint32_t*)&out;

  tmp[0] = static_cast<uint32_t>(_pext_u64(_mm_extract_epi64(x, 0), challenge[0]));
  tmp[1] = static_cast<uint32_t>(_pext_u64(_mm_extract_epi64(x, 1), challenge[1]));

  return out;
}

block64_T blockT_to_block64_T(blockT& x, const uint64_t challenge[2])
{
  block64_T out;

  for(size_t j = 0; j < blocklen; ++j)
  {
    out[j] = __m128i_to_uint64_t(x[j], challenge);
  }

  return out;
}


blind64_T blindT_to_blind64_T(blindT& x, const uint64_t challenge[2])
{
  blind64_T out;

  for(size_t j = 0; j < 3 * numofboxes; ++j)
  {
     // std::cout << "x[" << j << "] = " << (block<__m128i>(x[j])).bits << std::endl;
     out[j] = __m128i_to_uint64_t(x[j], challenge);
     // std::cout << "out[" << j << "] = " << std::bitset<64>(out[j]) << std::endl << std::endl;
  }

  return out;
}

void compress_root_layer(PB_transcript* PB, PB_transcript_64* PB_64, uint64_t challenge[2])
{
  for(size_t j = 0; j < blocklen; ++j)
  {
    PB_64->root.L_shares_recv[j] = __m128i_to_uint64_t(PB->root.L_shares_recv[j], challenge);
    
    PB_64->root.R_shares_recv[j] = __m128i_to_uint64_t(PB->root.R_shares_recv[j], challenge);

    PB_64->root.swap_block[0][j] = __m128i_to_uint64_t(PB->root.swap_block[0][j], challenge);
    PB_64->root.swap_block[1][j] = __m128i_to_uint64_t(PB->root.swap_block[1][j], challenge);

    PB_64->root.swap_bit_[0][j]  = __m128i_to_uint64_t(PB->root.swap_bit_[0][j], challenge);
    PB_64->root.swap_bit_[1][j]  = __m128i_to_uint64_t(PB->root.swap_bit_[1][j], challenge);
  }

  PB_64->root.bit_L_shares_recv = __m128i_to_uint64_t(PB->root.bit_L_shares_recv, challenge);
  PB_64->root.bit_R_shares_recv = __m128i_to_uint64_t(PB->root.bit_R_shares_recv, challenge);

  PB_64->root.next_bit_block[0] = __m128i_to_uint64_t(PB->root.next_bit_block[0], challenge);
  PB_64->root.next_bit_block[1] = __m128i_to_uint64_t(PB->root.next_bit_block[1], challenge);

  PB_64->root.next_bit_bit_[0] = __m128i_to_uint64_t(PB->root.next_bit_bit_[0], challenge);
  PB_64->root.next_bit_bit_[1] = __m128i_to_uint64_t(PB->root.next_bit_bit_[1], challenge);
}

void compress_middle_layers(PB_transcript* PB, PB_transcript_64* PB_64, uint64_t challenge[2])
{
  for(size_t d = 0; d < depth-1; ++d)
  {
      for(size_t j = 0; j < blocklen; ++j)
      {   
        PB_64->middle[d].swap_block[0][j] = __m128i_to_uint64_t(PB->middle[d].swap_block[0][j], challenge);
        PB_64->middle[d].swap_block[1][j] = __m128i_to_uint64_t(PB->middle[d].swap_block[1][j], challenge);

        PB_64->middle[d].swap_bit_[0][j]  = __m128i_to_uint64_t(PB->middle[d].swap_bit_[0][j], challenge);
        PB_64->middle[d].swap_bit_[1][j]  = __m128i_to_uint64_t(PB->middle[d].swap_bit_[1][j], challenge);
      }

      PB_64->middle[d].next_bit_block[0] = __m128i_to_uint64_t(PB->middle[d].next_bit_block[0], challenge);
      PB_64->middle[d].next_bit_block[1] = __m128i_to_uint64_t(PB->middle[d].next_bit_block[1], challenge);

      PB_64->middle[d].next_bit_bit_[0]  = __m128i_to_uint64_t(PB->middle[d].next_bit_bit_[0], challenge);
      PB_64->middle[d].next_bit_bit_[1]  = __m128i_to_uint64_t(PB->middle[d].next_bit_bit_[1], challenge);

      for(size_t r = 0; r < rounds + 1; ++r)
      {
        for(size_t j = 0; j < 3 * numofboxes; ++j)
        {
          PB_64->middle[d].seed0L_encrypt[r][j] = __m128i_to_uint64_t(PB->middle[d].seed0L_encrypt[r][j], challenge);
          PB_64->middle[d].seed0R_encrypt[r][j] = __m128i_to_uint64_t(PB->middle[d].seed0R_encrypt[r][j], challenge);
          PB_64->middle[d].seed1L_encrypt[r][j] = __m128i_to_uint64_t(PB->middle[d].seed1L_encrypt[r][j], challenge);
          PB_64->middle[d].seed1R_encrypt[r][j] = __m128i_to_uint64_t(PB->middle[d].seed1R_encrypt[r][j], challenge);
        }
      }

  }
}

void compress_final_layer(PB_transcript * PB, PB_transcript_64* PB_64, uint64_t challenge[2])
{
  for(size_t j = 0; j < blocklen; ++j)
  {
    PB_64->leaf.final_cw[j] = __m128i_to_uint64_t(PB->leaf.final_cw[j], challenge);
  }
}

void compress_transcript(PB_transcript* PB, PB_transcript_64* PB_64, uint64_t challenge[2])
{
    compress_root_layer(PB, PB_64, challenge);

    compress_middle_layers(PB, PB_64, challenge);

    compress_final_layer(PB, PB_64, challenge);
}




void compress_root_layer(P2_transcript* P2, P2_transcript_64* P2_64, uint64_t challenge[2])
{
   
  
  for(size_t j = 0; j < blocklen; ++j)
  {
    P2_64->root.swap_gamma[0][j] = __m128i_to_uint64_t(P2->root.swap_gamma[0][j], challenge);
    P2_64->root.swap_gamma[1][j] = __m128i_to_uint64_t(P2->root.swap_gamma[1][j], challenge);
  }

  P2_64->root.next_bit_gamma[0] = __m128i_to_uint64_t(P2->root.next_bit_gamma[0], challenge);
  P2_64->root.next_bit_gamma[1] = __m128i_to_uint64_t(P2->root.next_bit_gamma[1], challenge);
}

void compress_middle_layers(P2_transcript* P2, P2_transcript_64* P2_64, uint64_t challenge[2])
{
 for(size_t d = 0; d < depth-1; ++d)
 {
  for(size_t j = 0; j < blocklen; ++j)
  {
    P2_64->middle[d].swap_gamma[0][j] = __m128i_to_uint64_t(P2->middle[d].swap_gamma[0][j], challenge);
    P2_64->middle[d].swap_gamma[1][j] = __m128i_to_uint64_t(P2->middle[d].swap_gamma[1][j], challenge);
  } 


  P2_64->middle[d].next_bit_gamma[0] = __m128i_to_uint64_t(P2->middle[d].next_bit_gamma[0], challenge);
  P2_64->middle[d].next_bit_gamma[1] = __m128i_to_uint64_t(P2->middle[d].next_bit_gamma[1], challenge);

    for(size_t r = 0; r < rounds; ++r)
    {
      for(size_t j = 0; j < 3 * numofboxes; ++j)
      {
        P2_64->middle[d].gamma0[r][j] = __m128i_to_uint64_t(P2->middle[d].gamma0[r][j], challenge);
        P2_64->middle[d].gamma1[r][j] = __m128i_to_uint64_t(P2->middle[d].gamma1[r][j], challenge);
      }
    }

 }
}

void compress_transcript(P2_transcript* P2, P2_transcript_64* P2_64, uint64_t challenge[2])
{
    compress_root_layer(P2, P2_64, challenge);

    compress_middle_layers(P2, P2_64, challenge);

   
}

inline void transpose_transcript(P2_transcript* view, P2_transcriptT viewT[], __m128i challenge = ones)
 {

 
  for(size_t i = 0; i < 128; ++i)
  {  
    if(!(block<__m128i>(challenge)).bits[i]) continue;
    viewT[i].rootT.next_bit_gamma[0] = (block<__m128i>(view->root.next_bit_gamma[0])).bits[i];
    viewT[i].rootT.next_bit_gamma[1] = (block<__m128i>(view->root.next_bit_gamma[1])).bits[i];

    for(size_t j = 0; j < blocklen; ++j)
    {
     viewT[i].rootT.swap_gamma[0][j] = (block<__m128i>(view->root.swap_gamma[0][j])).bits[i];
     viewT[i].rootT.swap_gamma[1][j] = (block<__m128i>(view->root.swap_gamma[1][j])).bits[i]; 
    }
  }


    for(size_t i = 0; i < 128; ++i)
    {
        if(!(block<__m128i>(challenge)).bits[i]) continue;
      for(size_t cur_depth  = 0; cur_depth < depth - 1; ++cur_depth)
      {
        viewT[i].middleT[cur_depth].next_bit_gamma[0] = (block<__m128i>(view->middle[cur_depth].next_bit_gamma[0])).bits[i];
        viewT[i].middleT[cur_depth].next_bit_gamma[1] = (block<__m128i>(view->middle[cur_depth].next_bit_gamma[1])).bits[i];

        for(size_t j = 0; j < blocklen; ++j)
        {
         viewT[i].middleT[cur_depth].swap_gamma[0][j] = (block<__m128i>(view->middle[cur_depth].swap_gamma[0][j])).bits[i];
         viewT[i].middleT[cur_depth].swap_gamma[1][j] =  (block<__m128i>(view->middle[cur_depth].swap_gamma[1][j])).bits[i];
        }

        for(size_t j = 0; j < 3 * numofboxes; ++j)
        {
          for(size_t r = 0; r < rounds; ++r)
          {
           viewT[i].middleT[cur_depth].gamma0[j][r] =  (block<__m128i>(view->middle[cur_depth].gamma0[r][j])).bits[i];
           viewT[i].middleT[cur_depth].gamma1[j][r] =   (block<__m128i>(view->middle[cur_depth].gamma1[r][j])).bits[i];
          }
        }
      }
    }


 }



 void transpose_transcript(PB_transcript* view0, PB_transcript* view1,  PB_transcriptT view0T[], PB_transcriptT view1T[])
 {

 
  for(size_t i = 0; i < 128; ++i)
  {
    view0T[i].rootT.bit_L_shares_recv = (block<__m128i>(view0->root.bit_L_shares_recv)).bits[i];
    view0T[i].rootT.bit_R_shares_recv = (block<__m128i>(view0->root.bit_R_shares_recv)).bits[i];

   
    view0T[i].rootT.next_bit_bit_[0]  = (block<__m128i>(view0->root.next_bit_bit_[0])).bits[i];
    view0T[i].rootT.next_bit_bit_[1]  = (block<__m128i>(view0->root.next_bit_bit_[1])).bits[i];

    view0T[i].rootT.next_bit_block[0] = (block<__m128i>(view0->root.next_bit_block[0])).bits[i];
    view0T[i].rootT.next_bit_block[1] = (block<__m128i>(view0->root.next_bit_block[1])).bits[i];


    view1T[i].rootT.bit_L_shares_recv = (block<__m128i>(view1->root.bit_L_shares_recv)).bits[i];
    view1T[i].rootT.bit_R_shares_recv = (block<__m128i>(view1->root.bit_R_shares_recv)).bits[i];
   
   
    view1T[i].rootT.next_bit_bit_[0]  = (block<__m128i>(view1->root.next_bit_bit_[0])).bits[i];
    view1T[i].rootT.next_bit_bit_[1]  = (block<__m128i>(view1->root.next_bit_bit_[1])).bits[i];

    view1T[i].rootT.next_bit_block[0] = (block<__m128i>(view1->root.next_bit_block[0])).bits[i];
    view1T[i].rootT.next_bit_block[1] = (block<__m128i>(view1->root.next_bit_block[1])).bits[i];


    for(size_t j = 0; j < blocklen; ++j)
    {    

     view0T[i].rootT.L_shares_recv[j]  = (block<__m128i>(view0->root.L_shares_recv[j])).bits[i];
     view0T[i].rootT.R_shares_recv[j]  = (block<__m128i>(view0->root.R_shares_recv[j])).bits[i];
    
     view0T[i].rootT.swap_bit_[0][j]  = (block<__m128i>(view0->root.swap_bit_[0][j])).bits[i];
     view0T[i].rootT.swap_bit_[1][j]  = (block<__m128i>(view0->root.swap_bit_[1][j])).bits[i];

     view0T[i].rootT.swap_block[0][j] = (block<__m128i>(view0->root.swap_block[0][j])).bits[i];
     view0T[i].rootT.swap_block[1][j] = (block<__m128i>(view0->root.swap_block[1][j])).bits[i]; 
     view0T[i].leafT.final_cw[j] = (block<__m128i>(view0->leaf.final_cw[j])).bits[i]; 

     view1T[i].rootT.L_shares_recv[j]  = (block<__m128i>(view1->root.L_shares_recv[j])).bits[i];
     view1T[i].rootT.R_shares_recv[j]  = (block<__m128i>(view1->root.R_shares_recv[j])).bits[i];

     view1T[i].rootT.swap_bit_[0][j]  = (block<__m128i>(view1->root.swap_bit_[0][j])).bits[i];
     view1T[i].rootT.swap_bit_[1][j]  = (block<__m128i>(view1->root.swap_bit_[1][j])).bits[i];

     view1T[i].rootT.swap_block[0][j] = (block<__m128i>(view1->root.swap_block[0][j])).bits[i];
     view1T[i].rootT.swap_block[1][j] = (block<__m128i>(view1->root.swap_block[1][j])).bits[i]; 
     view1T[i].leafT.final_cw[j] = (block<__m128i>(view1->leaf.final_cw[j])).bits[i]; 
    }
  }

 
  for(size_t i = 0; i < 128; ++i)
  {
    for(size_t cur_depth  = 0; cur_depth < depth - 1; ++cur_depth)
    {


      view0T[i].middleT[cur_depth].next_bit_bit_[0] = (block<__m128i>(view0->middle[cur_depth].next_bit_bit_[0])).bits[i];
      view0T[i].middleT[cur_depth].next_bit_bit_[1] = (block<__m128i>(view0->middle[cur_depth].next_bit_bit_[1])).bits[i];

      view0T[i].middleT[cur_depth].next_bit_block[0] = (block<__m128i>(view0->middle[cur_depth].next_bit_block[0])).bits[i];
      view0T[i].middleT[cur_depth].next_bit_block[1] = (block<__m128i>(view0->middle[cur_depth].next_bit_block[1])).bits[i];


      view1T[i].middleT[cur_depth].next_bit_bit_[0] = (block<__m128i>(view1->middle[cur_depth].next_bit_bit_[0])).bits[i];
      view1T[i].middleT[cur_depth].next_bit_bit_[1] = (block<__m128i>(view1->middle[cur_depth].next_bit_bit_[1])).bits[i];

      view1T[i].middleT[cur_depth].next_bit_block[0] = (block<__m128i>(view1->middle[cur_depth].next_bit_block[0])).bits[i];
      view1T[i].middleT[cur_depth].next_bit_block[1] = (block<__m128i>(view1->middle[cur_depth].next_bit_block[1])).bits[i];


      for(size_t j = 0; j < blocklen; ++j)
      {
       view0T[i].middleT[cur_depth].swap_bit_[0][j] = (block<__m128i>(view0->middle[cur_depth].swap_bit_[0][j])).bits[i];
       view0T[i].middleT[cur_depth].swap_bit_[1][j] = (block<__m128i>(view0->middle[cur_depth].swap_bit_[1][j])).bits[i];

       view0T[i].middleT[cur_depth].swap_block[0][j] = (block<__m128i>(view0->middle[cur_depth].swap_block[0][j])).bits[i];
       view0T[i].middleT[cur_depth].swap_block[1][j] = (block<__m128i>(view0->middle[cur_depth].swap_block[1][j])).bits[i];


       view1T[i].middleT[cur_depth].swap_bit_[0][j] = (block<__m128i>(view1->middle[cur_depth].swap_bit_[0][j])).bits[i];
       view1T[i].middleT[cur_depth].swap_bit_[1][j] = (block<__m128i>(view1->middle[cur_depth].swap_bit_[1][j])).bits[i];

       view1T[i].middleT[cur_depth].swap_block[0][j] = (block<__m128i>(view1->middle[cur_depth].swap_block[0][j])).bits[i];
       view1T[i].middleT[cur_depth].swap_block[1][j] = (block<__m128i>(view1->middle[cur_depth].swap_block[1][j])).bits[i];
      }

      for(size_t j = 0; j < 3 * numofboxes; ++j)
      {
        for(size_t r = 0; r < rounds + 1; ++r)
        {
         view0T[i].middleT[cur_depth].seed0L_encrypt[j][r] = (block<__m128i>(view0->middle[cur_depth].seed0L_encrypt[r][j])).bits[i];
         view0T[i].middleT[cur_depth].seed0R_encrypt[j][r] = (block<__m128i>(view0->middle[cur_depth].seed0R_encrypt[r][j])).bits[i];
         view0T[i].middleT[cur_depth].seed1L_encrypt[j][r] = (block<__m128i>(view0->middle[cur_depth].seed1L_encrypt[r][j])).bits[i];
         view0T[i].middleT[cur_depth].seed1R_encrypt[j][r] = (block<__m128i>(view0->middle[cur_depth].seed1R_encrypt[r][j])).bits[i];


         view1T[i].middleT[cur_depth].seed0L_encrypt[j][r] = (block<__m128i>(view1->middle[cur_depth].seed0L_encrypt[r][j])).bits[i];
         view1T[i].middleT[cur_depth].seed0R_encrypt[j][r] = (block<__m128i>(view1->middle[cur_depth].seed0R_encrypt[r][j])).bits[i];
         view1T[i].middleT[cur_depth].seed1L_encrypt[j][r] = (block<__m128i>(view1->middle[cur_depth].seed1L_encrypt[r][j])).bits[i];
         view1T[i].middleT[cur_depth].seed1R_encrypt[j][r] = (block<__m128i>(view1->middle[cur_depth].seed1R_encrypt[r][j])).bits[i];
        }
      }
    }
  }


}

 
void assert_transcripts_match(PB_transcriptT * view0T, PB_transcriptT * view1T,  PB_transcriptT * gen_view0T, PB_transcriptT * gen_view1T  )
{
  // for(size_t j = 0; j < 128; ++j)
  // { 
 
  //   if((block<__m128i>(challenge)).bits[j])  continue;
  
  //   assert(P2_P0_viewT[j].rootT.next_bit_gamma[0] == P2_P0_view_VT[j].rootT.next_bit_gamma[0]);
  //   assert(P2_P0_viewT[j].rootT.next_bit_gamma[1] == P2_P0_view_VT[j].rootT.next_bit_gamma[1]);
    
 
  //    for(size_t i = 0; i < blocklen; ++i)
  //    { 
  //     assert(P2_P0_viewT[j].rootT.swap_gamma[0][i] == P2_P0_view_VT[j].rootT.swap_gamma[0][i]);
  //     assert(P2_P0_viewT[j].rootT.swap_gamma[1][i] == P2_P0_view_VT[j].rootT.swap_gamma[1][i]);
  //     assert(P2_P1_viewT[j].rootT.swap_gamma[0][i] == P2_P1_view_VT[j].rootT.swap_gamma[0][i]);
  //     assert(P2_P1_viewT[j].rootT.swap_gamma[1][i] == P2_P1_view_VT[j].rootT.swap_gamma[1][i]);
  //    }
 
 
  //   for(size_t cur_depth = 0; cur_depth < depth - 1; ++cur_depth)
  //   {
  //    assert(P2_P0_viewT[j].middleT[cur_depth].next_bit_gamma[0] == P2_P0_view_VT[j].middleT[cur_depth].next_bit_gamma[0]);
  //    assert(P2_P0_viewT[j].middleT[cur_depth].next_bit_gamma[1] == P2_P0_view_VT[j].middleT[cur_depth].next_bit_gamma[1]);
  //    assert(P2_P1_viewT[j].middleT[cur_depth].next_bit_gamma[0] == P2_P1_view_VT[j].middleT[cur_depth].next_bit_gamma[0]);
  //    assert(P2_P1_viewT[j].middleT[cur_depth].next_bit_gamma[1] == P2_P1_view_VT[j].middleT[cur_depth].next_bit_gamma[1]);
 
  //    for(size_t i = 0; i < blocklen; ++i)
  //    {
  //     assert(P2_P0_viewT[j].middleT[cur_depth].swap_gamma[0][i] == P2_P0_view_VT[j].middleT[cur_depth].swap_gamma[0][i]);
  //     assert(P2_P0_viewT[j].middleT[cur_depth].swap_gamma[1][i] == P2_P0_view_VT[j].middleT[cur_depth].swap_gamma[1][i]);
  //     assert(P2_P1_viewT[j].middleT[cur_depth].swap_gamma[0][i] == P2_P1_view_VT[j].middleT[cur_depth].swap_gamma[0][i]);
  //     assert(P2_P1_viewT[j].middleT[cur_depth].swap_gamma[1][i] == P2_P1_view_VT[j].middleT[cur_depth].swap_gamma[1][i]);
  //    }
 
  //     for(size_t r = 0; r < rounds ; ++r)
  //     {
  //       for(size_t k = 0; k < 3 * numofboxes; ++k)
  //       {
  //         assert(P2_P0_viewT[j].middleT[cur_depth].gamma0[k][r] == P2_P0_view_VT[j].middleT[cur_depth].gamma0[k][r]);
  //         assert(P2_P0_viewT[j].middleT[cur_depth].gamma1[k][r] == P2_P0_view_VT[j].middleT[cur_depth].gamma1[k][r]);
  //         assert(P2_P1_viewT[j].middleT[cur_depth].gamma0[k][r] == P2_P1_view_VT[j].middleT[cur_depth].gamma0[k][r]);
  //         assert(P2_P1_viewT[j].middleT[cur_depth].gamma1[k][r] == P2_P1_view_VT[j].middleT[cur_depth].gamma1[k][r]);
  //       }
  //     }
  //   }
  // }
 
   for(size_t j = 0; j < 64; ++j)
  { 
 
    // if(!(block<__m128i>(challenge)).bits[j])  continue;
     
   //  assert(block<__m128i>(view0T[j].rootT.L_shares_recv) == block<__m128i>(gen_view0T[j].rootT.L_shares_recv));
   //  assert(block<__m128i>(view0T[j].rootT.R_shares_recv) == block<__m128i>(gen_view0T[j].rootT.R_shares_recv));
     
   // assert(view0T[j].rootT.next_bit_bit_[0] == gen_view0T[j].rootT.next_bit_bit_[0]);
   //  assert(view0T[j].rootT.next_bit_bit_[1] == gen_view0T[j].rootT.next_bit_bit_[1]);
    
 
     for(size_t i = 0; i < blocklen; ++i)
     {
      assert(view0T[j].rootT.swap_block[0][i] == gen_view0T[j].rootT.swap_block[0][i]);
      assert(view0T[j].rootT.swap_block[1][i] == gen_view0T[j].rootT.swap_block[1][i]);
      assert(view0T[j].rootT.swap_bit_[0][i] == gen_view0T[j].rootT.swap_bit_[0][i]);
      assert(view0T[j].rootT.swap_bit_[1][i] == gen_view0T[j].rootT.swap_bit_[1][i]);
     }
 
    //std::cout << " j = " << j << std::endl;
    for(size_t cur_depth = 0; cur_depth < depth - 1; ++cur_depth)
    {
     assert(view0T[j].middleT[cur_depth].next_bit_bit_[0] == gen_view0T[j].middleT[cur_depth].next_bit_bit_[0]);
     assert(view0T[j].middleT[cur_depth].next_bit_bit_[1] == gen_view0T[j].middleT[cur_depth].next_bit_bit_[1]);
    
 
     for(size_t i = 0; i < blocklen; ++i)
     {
      assert(view0T[j].middleT[cur_depth].swap_block[0][i] == gen_view0T[j].middleT[cur_depth].swap_block[0][i]);
      assert(view0T[j].middleT[cur_depth].swap_block[1][i] == gen_view0T[j].middleT[cur_depth].swap_block[1][i]);
      assert(view0T[j].middleT[cur_depth].swap_bit_[0][i] == gen_view0T[j].middleT[cur_depth].swap_bit_[0][i]);
      assert(view0T[j].middleT[cur_depth].swap_bit_[1][i] == gen_view0T[j].middleT[cur_depth].swap_bit_[1][i]);
     }
 
      for(size_t r = 0; r < rounds + 1; ++r)
      {
        for(size_t k = 0; k < 3 * numofboxes; ++k)
        {
          assert(view0T[j].middleT[cur_depth].seed0L_encrypt[k][r] == gen_view0T[j].middleT[cur_depth].seed0L_encrypt[k][r]);
          assert(view0T[j].middleT[cur_depth].seed0R_encrypt[k][r] == gen_view0T[j].middleT[cur_depth].seed0R_encrypt[k][r]);
          assert(view0T[j].middleT[cur_depth].seed1L_encrypt[k][r] == gen_view0T[j].middleT[cur_depth].seed1L_encrypt[k][r]);
          assert(view0T[j].middleT[cur_depth].seed1R_encrypt[k][r] == gen_view0T[j].middleT[cur_depth].seed1R_encrypt[k][r]);
        }
      }
    }
  }
  
  for(size_t j = 0; j < 64; ++j)
  { 
 
    //if(!(block<__m128i>(challenge)).bits[j])  continue;
     for(size_t i = 0; i < blocklen; ++i)
     {
      assert(view0T[j].leafT.final_cw[i] == gen_view0T[j].leafT.final_cw[i]);
     }
  }
 
 
  for(size_t j = 0; j < 64; ++j)
  { 
 
    // if(!(block<__m128i>(challenge)).bits[j])  continue;
     
    // assert(block<__m128i>(view1T[j].rootT.L_shares_recv) == block<__m128i>(gen_view1T[j].rootT.L_shares_recv));
    // assert(block<__m128i>(view1T[j].rootT.R_shares_recv) == block<__m128i>(gen_view1T[j].rootT.R_shares_recv));
     
    assert(view1T[j].rootT.next_bit_bit_[0] == gen_view1T[j].rootT.next_bit_bit_[0]);
    assert(view1T[j].rootT.next_bit_bit_[1] == gen_view1T[j].rootT.next_bit_bit_[1]);
    
 
     for(size_t i = 0; i < blocklen; ++i)
     {
      assert(view1T[j].rootT.swap_block[0][i] == gen_view1T[j].rootT.swap_block[0][i]);
      assert(view1T[j].rootT.swap_block[1][i] == gen_view1T[j].rootT.swap_block[1][i]);
      assert(view1T[j].rootT.swap_bit_[0][i] == gen_view1T[j].rootT.swap_bit_[0][i]);
      assert(view1T[j].rootT.swap_bit_[1][i] == gen_view1T[j].rootT.swap_bit_[1][i]);
     }
 
 
    for(size_t cur_depth = 0; cur_depth < depth - 1; ++cur_depth)
    {
     assert(view1T[j].middleT[cur_depth].next_bit_bit_[0] == gen_view1T[j].middleT[cur_depth].next_bit_bit_[0]);
     assert(view1T[j].middleT[cur_depth].next_bit_bit_[1] == gen_view1T[j].middleT[cur_depth].next_bit_bit_[1]);
    
 
     for(size_t i = 0; i < blocklen; ++i)
     {
      assert(view1T[j].middleT[cur_depth].swap_block[0][i] == gen_view1T[j].middleT[cur_depth].swap_block[0][i]);
      assert(view1T[j].middleT[cur_depth].swap_block[1][i] == gen_view1T[j].middleT[cur_depth].swap_block[1][i]);
      assert(view1T[j].middleT[cur_depth].swap_bit_[0][i] == gen_view1T[j].middleT[cur_depth].swap_bit_[0][i]);
      assert(view1T[j].middleT[cur_depth].swap_bit_[1][i] == gen_view1T[j].middleT[cur_depth].swap_bit_[1][i]);
     }
 
      for(size_t r = 0; r < rounds + 1; ++r)
      {
        for(size_t k = 0; k < 3 * numofboxes; ++k)
        {
          assert(view1T[j].middleT[cur_depth].seed0L_encrypt[k][r] == gen_view1T[j].middleT[cur_depth].seed0L_encrypt[k][r]);
          assert(view1T[j].middleT[cur_depth].seed0R_encrypt[k][r] == gen_view1T[j].middleT[cur_depth].seed0R_encrypt[k][r]);
          assert(view1T[j].middleT[cur_depth].seed1L_encrypt[k][r] == gen_view1T[j].middleT[cur_depth].seed1L_encrypt[k][r]);
          assert(view1T[j].middleT[cur_depth].seed1R_encrypt[k][r] == gen_view1T[j].middleT[cur_depth].seed1R_encrypt[k][r]);
        }
      }
    }
  }
  
  for(size_t j = 0; j < 64; ++j)
  { 
 
    //if(!(block<__m128i>(challenge)).bits[j])  continue;
     for(size_t i = 0; i < blocklen; ++i)
     {
      assert(view1T[j].leafT.final_cw[i] == gen_view1T[j].leafT.final_cw[i]);
     }
  }
}
