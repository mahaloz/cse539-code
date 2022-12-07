 static inline void trans(uint8_t const * inp, uint8_t * out, int nrows, int ncols)
{
    #define INP(x,y) inp[(x)*ncols/8 + (y)/8]
    #define OUT(x,y) out[(y)*nrows/8 + (x)/8]

    for (size_t row = 0; row < nrows; row += sizeof(__m256i))
    {
      for (size_t col = 0; col < ncols; col += 8)
      {
        __m256i x = _mm256_setr_epi8(INP(row + 0, col), INP(row + 1, col), INP(row + 2, col), INP(row + 3, col),
        INP(row + 4, col), INP(row + 5, col), INP(row + 6, col), INP(row + 7, col),
        INP(row + 8, col), INP(row + 9, col), INP(row + 10, col), INP(row + 11, col),
        INP(row + 12, col), INP(row + 13, col), INP(row + 14, col), INP(row + 15, col),
        INP(row + 16, col), INP(row + 17, col), INP(row + 18, col), INP(row + 19, col),
        INP(row + 20, col), INP(row + 21, col), INP(row + 22, col), INP(row + 23, col),
        INP(row + 24, col), INP(row + 25, col), INP(row + 26, col), INP(row + 27, col),
        INP(row + 28, col), INP(row + 29, col), INP(row + 30, col), INP(row + 31, col));

        *(uint32_t*)&OUT(row, col+7)= _mm256_movemask_epi8(_mm256_slli_epi64(x, 0));
        *(uint32_t*)&OUT(row, col+6)= _mm256_movemask_epi8(_mm256_slli_epi64(x, 1));
        *(uint32_t*)&OUT(row, col+5)= _mm256_movemask_epi8(_mm256_slli_epi64(x, 2));
        *(uint32_t*)&OUT(row, col+4)= _mm256_movemask_epi8(_mm256_slli_epi64(x, 3));
        *(uint32_t*)&OUT(row, col+3)= _mm256_movemask_epi8(_mm256_slli_epi64(x, 4));
        *(uint32_t*)&OUT(row, col+2)= _mm256_movemask_epi8(_mm256_slli_epi64(x, 5));
        *(uint32_t*)&OUT(row, col+1)= _mm256_movemask_epi8(_mm256_slli_epi64(x, 6));
        *(uint32_t*)&OUT(row, col+0)= _mm256_movemask_epi8(_mm256_slli_epi64(x, 7));
      }
    }
}

 struct  from_PB_root_64
 {  
  uint64_t swap_block[2][blocklen];
  uint64_t swap_bit_[2][blocklen];


  block64_T  L_shares_recv, R_shares_recv; // root layer  (2 * blocklen)
   
  std::array<uint64_t, 124> padding_root;

  uint64_t next_bit_block[2];
  uint64_t next_bit_bit_[2]; 

  uint64_t bit_L_shares_recv, bit_R_shares_recv; // root layer
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
  uint64_t padding_middle[128 -  (((4 * (rounds + 1) * 3 * numofboxes) + (4 * blocklen) + 4) % 128)];
 
 };

 struct from_PB_leaf_64
 {
  block64_T final_cw; // final layer
 // uint64_t extra_padding[10];
 };
 
 struct PB_transcript_64
 {
  from_PB_root_64    root;
  from_PB_middle_64  middle[depth-1];
  from_PB_leaf_64 leaf;
 };


  struct from_P2_root_64
  {   
   uint64_t swap_gamma[2][blocklen];
   std::array<uint64_t, 126> padding;
   uint64_t next_bit_gamma[2];
  
  }; 


  struct from_P2_middle_64
  { 

    std::array<uint64_t, blocklen + (128 -  (((2 * (rounds) * 3 * numofboxes) + (2 * blocklen) + 2) % 128))> padding_middle;

    uint64_t swap_gamma[2][blocklen];

    blind64_T gamma0[rounds]; // Used in encrypt
    blind64_T gamma1[rounds]; // Used in encrypt 
   
    uint64_t next_bit_gamma[2];
  };

  struct from_P2_leaf_64
  {

    block64_T padding;
    //  uint64_t padding[8] = {0};
  };


  struct P2_transcript_64
  {
    from_P2_root_64   root;
    from_P2_middle_64 middle[depth-1];
    from_P2_leaf_64 leaf ;
  };


  struct from_P2_root
  {   
   __m128i swap_gamma[2][blocklen];
    
   std::array<__m128i,126> padding;
    
   __m128i next_bit_gamma[2];
  
  // __m128i padding[6];
  }; 


  struct from_P2_middle
  {

     std::array<__m128i, blocklen +  (128 -  (((2 * (rounds) * 3 * numofboxes) + (2 * blocklen) + 2) % 128))> padding_middle;

    __m128i swap_gamma[2][blocklen];

    blindT gamma0[rounds]; // Used in encrypt
    blindT gamma1[rounds]; // Used in encrypt
    

  
   
   // __m128i padding_middle[128 -  (((2 * (rounds) * 3 * numofboxes) + (2 * blocklen) + 2) % 128)];
   __m128i next_bit_gamma[2];

  };

  struct from_P2_leaf
  {

    blockT padding;
   // __m128i padding[8];// = {0, 0};
  };


  struct P2_transcript
  {
    from_P2_root    root;
    from_P2_middle  middle[depth-1];
    from_P2_leaf leaf ;
  };




 struct  from_PB_root
 {
  
   __m128i swap_block[2][blocklen];
  
   __m128i swap_bit_[2][blocklen];

   blockT  L_shares_recv, R_shares_recv; // root layer  
   
   //__m128i padding_root[124];
   std::array<__m128i, 124> padding_root;

  __m128i next_bit_block[2];
  __m128i next_bit_bit_[2];

  

  __m128i bit_L_shares_recv, bit_R_shares_recv; // root layer
 
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

  __m128i padding_middle[128 -  (((4 * (rounds + 1) * 3 * numofboxes) + (4 * blocklen) + 4) % 128)];

 };


 struct from_PB_leaf
 {
   blockT final_cw; // final layer

   //__m128i extra_padding[10];

 
 };
 
 struct PB_transcript
 {
  from_PB_root   root;
  from_PB_middle  middle[depth-1];
  from_PB_leaf leaf;
 };




 





 
 


template<typename leaf_t, typename node_t, typename prgkey_t>  
struct Proof
{
  PB_transcript_64 PB_view;
  P2_transcript_64 P2_view; 
};


 

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

 