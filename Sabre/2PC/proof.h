
template<typename leaf_t, typename node_t, typename prgkey_t, size_t nodes_per_leaf>
struct proof_PB
{

    std::bitset<depth> direction;

    byte_t PB_root[SHA256_DIGEST_LENGTH];

    byte_t P0_hash[128][SHA256_DIGEST_LENGTH];
    byte_t P2_0_hash[128][SHA256_DIGEST_LENGTH];

    byte_t P1_hash[128][SHA256_DIGEST_LENGTH];
    byte_t P2_1_hash[128][SHA256_DIGEST_LENGTH];

    blockT seed;
    blockT seed_other;
    blockT seed2;
    PB_transcript_64 * PB_other;
    P2_transcript_64 * P2_view;
  
    dpf_key<leaf_t, node_t, prgkey_t> dpfkey_; 
  
  inline proof_PB(proof_PB &&) = default;
  inline proof_PB & operator=(proof_PB &&) = default;
  inline proof_PB(const proof_PB &) = default;
  inline proof_PB & operator=(const proof_PB &) = default;

    proof_PB(
              dpf_key<leaf_t, node_t, prgkey_t>& dpfkey
              //size_t nitems, const block_t& root, const std::vector<block_t> cw, const std::array<block_t, nodes_per_leaf>& finalizer, const prgkey_t& prgkey
            )
    :dpfkey_(dpfkey)
    {
      PB_other = new PB_transcript_64;
      P2_view  = new P2_transcript_64; 
      // PB_other->middle =  new from_PB_middle_64[depth-1];
      // P2_view->middle  = new from_P2_middle_64[depth-1];
    }
 
};










void write_proof(std::string filename, proof_PB<leaf_t, node_t, prgkey_t, nodes_per_leaf>& proof_for_P0)
{
  std::ofstream out(filename);
 
  
  out.write(reinterpret_cast<const char*>(&proof_for_P0.dpfkey_.nitems), sizeof(size_t));
  out.write(reinterpret_cast<const char*>(&proof_for_P0.dpfkey_.root), sizeof(node_t));
  
  for(size_t d = 0; d < depth; ++d)
  {
   out.write(reinterpret_cast<const char*>(&proof_for_P0.dpfkey_.cw[d]), sizeof(block_t));
  }
  
  out.write(reinterpret_cast<const char*>(&proof_for_P0.dpfkey_.finalizer), sizeof(std::array<block_t, nodes_per_leaf>));
  out.write(reinterpret_cast<const char*>(&proof_for_P0.dpfkey_.prgkey.key.mX), sizeof(__m128i));
  
  out.write(reinterpret_cast<const char*>(&proof_for_P0.PB_root), sizeof(proof_for_P0.PB_root));
  
   for(size_t i = 0; i < 128; ++i)
   {
    out.write(reinterpret_cast<const char*>(&proof_for_P0.P0_hash[i]), sizeof(proof_for_P0.P0_hash[i]));
    out.write(reinterpret_cast<const char*>(&proof_for_P0.P2_0_hash[i]), sizeof(proof_for_P0.P2_0_hash[i]));  
    out.write(reinterpret_cast<const char*>(&proof_for_P0.P1_hash[i]), sizeof(proof_for_P0.P1_hash[i]));
    out.write(reinterpret_cast<const char*>(&proof_for_P0.P2_1_hash[i]), sizeof(proof_for_P0.P2_1_hash[i])); 
   }

  out.write(reinterpret_cast<const char*>(&proof_for_P0.seed), sizeof(blockT));
  out.write(reinterpret_cast<const char*>(&proof_for_P0.seed_other), sizeof(blockT));
  out.write(reinterpret_cast<const char*>(&proof_for_P0.seed2), sizeof(blockT));
 
  out.write(reinterpret_cast<const char*>(&proof_for_P0.PB_other->root), sizeof(proof_for_P0.PB_other->root));
  for(size_t d = 0; d < depth-1; ++d)
  {
    out.write(reinterpret_cast<const char*>(&proof_for_P0.PB_other->middle[d]), sizeof(proof_for_P0.PB_other->middle[d]));
  } 
  out.write(reinterpret_cast<const char*>(&proof_for_P0.PB_other->leaf), sizeof(proof_for_P0.PB_other->leaf));
 
 
  out.write(reinterpret_cast<const char*>(&proof_for_P0.P2_view->root), sizeof(proof_for_P0.P2_view->root));
  for(size_t d = 0; d < depth-1; ++d)
  {
    out.write(reinterpret_cast<const char*>(&proof_for_P0.P2_view->middle[d]), sizeof(proof_for_P0.P2_view->middle[d]));
  } 
  out.write(reinterpret_cast<const char*>(&proof_for_P0.P2_view->leaf), sizeof(proof_for_P0.P2_view->leaf));

  out.write(reinterpret_cast<const char*>(&proof_for_P0.direction), sizeof(proof_for_P0.direction));

}

 



auto read_proof(std::string filename)
{
  std::ifstream in(filename);

  size_t nitems_; 
  node_t root_;
  std::vector<block_t> cw_(depth);
 
  __m128i key;

  std::array<block_t, nodes_per_leaf> finalizer_;
  



  in.read(reinterpret_cast<char*>(&nitems_), sizeof(size_t));
  in.read(reinterpret_cast<char*>(&root_), sizeof(node_t));
  
  for(size_t d = 0; d < depth; ++d)
  {
   in.read(reinterpret_cast<char*>(&cw_[d]), sizeof(block_t));
  }
  
  in.read(reinterpret_cast<char*>(&finalizer_), sizeof(std::array<block_t, nodes_per_leaf>));
  in.read(reinterpret_cast<char*>(&key), sizeof(__m128i));

  prgkey_t prgkey(_mm_setzero_si128());

  dpf_key<leaf_t, node_t, prgkey_t> dpfkey_read(nitems_,  std::move(root_), std::move(cw_), std::move(finalizer_), std::move(prgkey));
  proof_PB<leaf_t, node_t, prgkey_t, nodes_per_leaf> proof_recv(dpfkey_read);
  
   
   in.read(reinterpret_cast<char*>(&proof_recv.PB_root), sizeof(proof_recv.PB_root));
  
   for(size_t i = 0; i < 128; ++i)
   {
    in.read(reinterpret_cast<char*>(&proof_recv.P0_hash[i]), sizeof(proof_recv.P0_hash[i]));
    in.read(reinterpret_cast<char*>(&proof_recv.P2_0_hash[i]), sizeof(proof_recv.P2_0_hash[i]));
    
    in.read(reinterpret_cast<char*>(&proof_recv.P1_hash[i]), sizeof(proof_recv.P1_hash[i]));
    in.read(reinterpret_cast<char*>(&proof_recv.P2_1_hash[i]), sizeof(proof_recv.P2_1_hash[i]));
   }

  in.read(reinterpret_cast<char*>(&proof_recv.seed), sizeof(blockT));
  in.read(reinterpret_cast<char*>(&proof_recv.seed_other), sizeof(blockT));
  in.read(reinterpret_cast<char*>(&proof_recv.seed2), sizeof(blockT));

  in.read(reinterpret_cast<char*>(&proof_recv.PB_other->root), sizeof(proof_recv.PB_other->root));
  for(size_t d = 0; d < depth-1; ++d)
  {
    in.read(reinterpret_cast<char*>(&proof_recv.PB_other->middle[d]), sizeof(proof_recv.PB_other->middle[d]));
  }
  in.read(reinterpret_cast<char*>(&proof_recv.PB_other->leaf), sizeof(proof_recv.PB_other->leaf));

  in.read(reinterpret_cast<char*>(&proof_recv.P2_view->root), sizeof(proof_recv.P2_view->root));
  for(size_t d = 0; d < depth-1; ++d)
  {
    in.read(reinterpret_cast<char*>(&proof_recv.P2_view->middle[d]), sizeof(proof_recv.P2_view->middle[d]));
  }
  in.read(reinterpret_cast<char*>(&proof_recv.P2_view->leaf), sizeof(proof_recv.P2_view->leaf));

  in.read(reinterpret_cast<char*>(&proof_recv.direction), sizeof(proof_recv.direction));
   
  return proof_recv;
  
}

// __m128i get_root_hash (
//                         __m128i& challenge_ = ones, __m128i& not_challenge_ = ones
//                       )
// {   
  
//   constexpr size_t ncols = 128;
  
//   constexpr size_t nrows_p2_root   = 3 * blocklen;
//    constexpr size_t nrows_p2_middle = blocklen + ( ( (2 * rounds * 3 * numofboxes)  + 2 + (2 * blocklen)) + (128 - (( (2 * rounds * 3 * numofboxes)  + 2 + (2 * blocklen)) % 128))) * (depth-1);
//   constexpr size_t nrows_p2_leaf = blocklen;  
//   constexpr size_t nrows_p2 =   nrows_p2_root + nrows_p2_middle + nrows_p2_leaf;
  
//   std::cout << "nrows_p2 = " << nrows_p2 << std::endl;

//   constexpr size_t nrows_r =   (7 * blocklen);
//   constexpr size_t nrows_m =   (((4 * (rounds + 1) * 3 * numofboxes) + (4 * blocklen) + 4) + (128 -  (((4 * (rounds + 1) * 3 * numofboxes) + (4 * blocklen) + 4) % 128)) ) * (depth-1);
//   constexpr size_t nrows_l =   blocklen;
//   constexpr size_t nrows_total =  nrows_r + nrows_m + nrows_l;
  
//   std::cout << "nrows_m = " << nrows_m << std::endl;

//   uint8_t transposed_p2_0[ncols][nrows_p2/8];
//   uint8_t transposed_p2_1[ncols][nrows_p2/8];


//   // uint8_t ** transposed_p2_0 =  (uint8_t **) malloc(sizeof(uint8_t*) * ncols);
//   // uint8_t ** transposed_p2_1 =  (uint8_t **) malloc(sizeof(uint8_t*) * ncols);
  
//   // for(size_t col = 0; col < ncols; ++col)
//   // {
//   //   transposed_p2_0[col] = (uint8_t *) std::aligned_alloc(sizeof(__m256i), nrows_p2);
//   //   transposed_p2_1[col] = (uint8_t *) std::aligned_alloc(sizeof(__m256i), nrows_p2);
//   // }

//   uint8_t transposed_p0[ncols][nrows_total/8];
//   uint8_t transposed_p1[ncols][nrows_total/8];
 
//   const uint8_t * P2_P0_view_transpose = reinterpret_cast<const uint8_t* >((P2_P0_view));
//   const uint8_t * P2_P1_view_transpose = reinterpret_cast<const uint8_t* >((P2_P1_view));

//   const uint8_t * P1_view_transpose_t  = reinterpret_cast<const uint8_t* >((P1_view_));
//   const uint8_t * P0_view_transpose_t  = reinterpret_cast<const uint8_t* >((P0_view_));

   

//    trans((uint8_t*)P0_view_transpose_t,   (uint8_t*)transposed_p0, nrows_total, ncols);
//    trans((uint8_t*)P1_view_transpose_t,   (uint8_t*)transposed_p1, nrows_total, ncols);
//    trans((uint8_t*)P2_P0_view_transpose,   (uint8_t*)transposed_p2_0, nrows_p2 , ncols);
//    trans((uint8_t*)P2_P1_view_transpose,   (uint8_t*)transposed_p2_1, nrows_p2 , ncols);


//    for(size_t j = 0; j < ncols; ++j)
//    {
//      SHA256_CTX sha256_P2_P0;
//      SHA256_Init(&sha256_P2_P0);   
     
//      SHA256_CTX sha256_P2_P1;
//      SHA256_Init(&sha256_P2_P1);

//      SHA256_CTX sha256_P0;
//      SHA256_Init(&sha256_P0);

//      SHA256_CTX sha256_P1;
//      SHA256_Init(&sha256_P1);

//      if(!SHA256_Update(&sha256_P2_P0, reinterpret_cast<const char* >(&transposed_p2_0[j]), sizeof(transposed_p2_0[j]))){ /*gah!*/ } 
//      SHA256_Final(hashP2_0_new[j], &sha256_P2_P0);


//       if(!SHA256_Update(&sha256_P2_P1, reinterpret_cast<const char* >(&transposed_p2_1[j]), sizeof(transposed_p2_1[j]))){ /*gah!*/ } 
//       SHA256_Final(hashP2_1_new[j], &sha256_P2_P1);

//       if(!SHA256_Update(&sha256_P0, reinterpret_cast<const char* >(&transposed_p0[j]), sizeof(transposed_p0[j]))){ /*gah!*/ } 
//       SHA256_Final(hash0_new[j], &sha256_P0);
      


//       if(!SHA256_Update(&sha256_P1, reinterpret_cast<const char* >(&transposed_p1[j]), sizeof(transposed_p1[j]))){ /*gah!*/ } 
//       SHA256_Final(hash1_new[j], &sha256_P1);
 
//      // std::cout << j << " = "; for(size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) printf("%x", hashP2_0_new[j][i]);
//      // std::cout << std::endl;
//      // std::cout << j << " = "; for(size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) printf("%x", hashP2_1_new[j][i]);
//      // std::cout << std::endl;
//      // std::cout << j << " = "; for(size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) printf("%x", hash0_new[j][i]);
//      // std::cout << std::endl;
//      // std::cout << j << " = "; for(size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) printf("%x", hash1_new[j][i]);
//      // std::cout << std::endl << std::endl;
//    }
 
//   auto start_gen2 = std::chrono::high_resolution_clock::now();
//   SHA256_CTX sha256_F;
//   SHA256_Init(&sha256_F);
  
//   for(size_t j = 0; j < 128; ++j)
//   {
//     SHA256_CTX sha256;
//     SHA256_Init(&sha256);

 
//     // std::cout << j << " ---> hash0_new = "; for(size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) printf("%x", hash0_new[j][i]);
//     // std::cout << std::endl;
//     // std::cout << j << " ---> hash1_new = "; for(size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) printf("%x", hash1_new[j][i]);
//     // std::cout << std::endl;
//     // std::cout << j << " ---> hashP2_0_new = "; for(size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) printf("%x", hashP2_0_new[j][i]);
//     // std::cout << std::endl;
//     // std::cout << j << " ---> hashP2_1_new = "; for(size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) printf("%x", hashP2_1_new[j][i]);
//     // std::cout << std::endl;


//     SHA256_Update(&sha256, reinterpret_cast<char* >(&hash0_new[j]),  sizeof(SHA256_DIGEST_LENGTH));
//     SHA256_Update(&sha256, reinterpret_cast<char* >(&hash1_new[j]),  sizeof(SHA256_DIGEST_LENGTH)); 
//     SHA256_Update(&sha256, reinterpret_cast<char* >(&hashP2_0_new[j]), sizeof(SHA256_DIGEST_LENGTH));
//     SHA256_Update(&sha256, reinterpret_cast<char* >(&hashP2_1_new[j]), sizeof(SHA256_DIGEST_LENGTH));

//     SHA256_Final(hash_array, &sha256);
   
//     // std::cout << j << "----> = "; for(size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) printf("%x", hash_array[i]);
//     // std::cout << std::endl;
   
//     char * hash_array_char = reinterpret_cast<char* >(&hash_array); 
    
//     SHA256_Update(&sha256_F, hash_array_char, sizeof(SHA256_DIGEST_LENGTH));  
//   }

//   SHA256_Final(final_hash, &sha256_F);


//   auto finish_gen2 = std::chrono::high_resolution_clock::now();
  
//   std::chrono::duration<double, std::milli> elapsed_gen2 = finish_gen2 - start_gen2;
 
 
  
//   // for(size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) fprintf(stderr,"%x", final_hash[i]);
//   // std::cerr << std::endl;
    
//   __m128i challenge  = _mm_loadu_si128((__m128i*) final_hash);

//   return challenge;
// }


__m128i get_root_hash (
                        __m128i& challenge_ = ones, __m128i& not_challenge_ = ones
                      )
{   
  
  constexpr size_t ncols = 128;
  
  constexpr size_t nrows_p2_root   = 3 * blocklen;
   constexpr size_t nrows_p2_middle = blocklen + ( ( (2 * rounds * 3 * numofboxes)  + 2 + (2 * blocklen)) + (128 - (( (2 * rounds * 3 * numofboxes)  + 2 + (2 * blocklen)) % 128))) * (depth-1);
  constexpr size_t nrows_p2_leaf = blocklen;  
  constexpr size_t nrows_p2 =  nrows_p2_root + nrows_p2_middle + nrows_p2_leaf;
  
  std::cout << "nrows_p2 = " << nrows_p2 << std::endl;

  constexpr size_t nrows_r =   (7 * blocklen);
  constexpr size_t nrows_m =   (((4 * (rounds + 1) * 3 * numofboxes) + (4 * blocklen) + 4) + (128 -  (((4 * (rounds + 1) * 3 * numofboxes) + (4 * blocklen) + 4) % 128)) ) * (depth-1);
  constexpr size_t nrows_l =   blocklen;
  constexpr size_t nrows_total =    nrows_r + nrows_m + nrows_l;
  
  std::cout << "nrows_m = " << nrows_m << std::endl;


  
  // uint8_t ** transposed_p2_0 =  (uint8_t **) malloc(sizeof(uint8_t*) * ncols);
  // uint8_t ** transposed_p2_1 =  (uint8_t **) malloc(sizeof(uint8_t*) * ncols);
  


  // uint8_t ** transposed_p0 =  (uint8_t **) malloc(sizeof(uint8_t*) * ncols);
  // uint8_t ** transposed_p1 =  (uint8_t **) malloc(sizeof(uint8_t*) * ncols);
  



  uint8_t transposed_p2_0[ncols][nrows_p2/8];
  uint8_t transposed_p2_1[ncols][nrows_p2/8];

  uint8_t transposed_p0[ncols][nrows_total/8];
  uint8_t transposed_p1[ncols][nrows_total/8];
 
  // for(size_t col = 0; col < ncols; ++col)
  // {
  //   transposed_p2_0[col] = (uint8_t *) malloc(nrows_p2);
  //   transposed_p2_1[col] = (uint8_t *) malloc(nrows_p2);
  // }
  // for(size_t col = 0; col < ncols; ++col)
  // {
  //   transposed_p0[col] = (uint8_t *) malloc(nrows_total);
  //   transposed_p1[col] = (uint8_t *) malloc(nrows_total);
  // }

  const uint8_t * P2_P0_view_transpose = reinterpret_cast<const uint8_t* >((P2_P0_view));
  const uint8_t * P2_P1_view_transpose = reinterpret_cast<const uint8_t* >((P2_P1_view));

  const uint8_t * P1_view_transpose_t  = reinterpret_cast<const uint8_t* >((P1_view_));
  const uint8_t * P0_view_transpose_t  = reinterpret_cast<const uint8_t* >((P0_view_));

   

    trans((uint8_t*)P0_view_transpose_t,   (uint8_t*)transposed_p0, nrows_total, ncols);
    trans((uint8_t*)P1_view_transpose_t,   (uint8_t*)transposed_p1, nrows_total, ncols);
    trans((uint8_t*)P2_P0_view_transpose,   (uint8_t*)transposed_p2_0, nrows_p2 , ncols);
    trans((uint8_t*)P2_P1_view_transpose,   (uint8_t*)transposed_p2_1, nrows_p2 , ncols);


   for(size_t j = 0; j < ncols; ++j)
   {
     SHA256_CTX sha256_P2_P0;
     SHA256_Init(&sha256_P2_P0);   
     
     SHA256_CTX sha256_P2_P1;
     SHA256_Init(&sha256_P2_P1);

     SHA256_CTX sha256_P0;
     SHA256_Init(&sha256_P0);

     SHA256_CTX sha256_P1;
     SHA256_Init(&sha256_P1);

     if(!SHA256_Update(&sha256_P2_P0, reinterpret_cast<const char* >(&transposed_p2_0[j]), sizeof(transposed_p2_0[j]))){ /*gah!*/ } 
     SHA256_Final(hashP2_0_new[j], &sha256_P2_P0);


      if(!SHA256_Update(&sha256_P2_P1, reinterpret_cast<const char* >(&transposed_p2_1[j]), sizeof(transposed_p2_1[j]))){ /*gah!*/ } 
      SHA256_Final(hashP2_1_new[j], &sha256_P2_P1);

      if(!SHA256_Update(&sha256_P0, reinterpret_cast<const char* >(&transposed_p0[j]), sizeof(transposed_p0[j]))){ /*gah!*/ } 
      SHA256_Final(hash0_new[j], &sha256_P0);
      


      if(!SHA256_Update(&sha256_P1, reinterpret_cast<const char* >(&transposed_p1[j]), sizeof(transposed_p1[j]))){ /*gah!*/ } 
      SHA256_Final(hash1_new[j], &sha256_P1);
   }
 
  auto start_gen2 = std::chrono::high_resolution_clock::now();
  SHA256_CTX sha256_F;
  SHA256_Init(&sha256_F);
  
  for(size_t j = 0; j < 128; ++j)
  {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    SHA256_Update(&sha256, reinterpret_cast<char* >(&hash0_new[j]),  sizeof(SHA256_DIGEST_LENGTH));
    SHA256_Update(&sha256, reinterpret_cast<char* >(&hash1_new[j]),  sizeof(SHA256_DIGEST_LENGTH)); 
    SHA256_Update(&sha256, reinterpret_cast<char* >(&hashP2_0_new[j]), sizeof(SHA256_DIGEST_LENGTH));
    SHA256_Update(&sha256, reinterpret_cast<char* >(&hashP2_1_new[j]), sizeof(SHA256_DIGEST_LENGTH));

    SHA256_Final(hash_array, &sha256);
   
    
    char * hash_array_char = reinterpret_cast<char* >(&hash_array); 
    
    SHA256_Update(&sha256_F, hash_array_char, sizeof(SHA256_DIGEST_LENGTH));  
  }

  SHA256_Final(final_hash, &sha256_F);


  auto finish_gen2 = std::chrono::high_resolution_clock::now();
  
  std::chrono::duration<double, std::milli> elapsed_gen2 = finish_gen2 - start_gen2;
   
  __m128i challenge  = _mm_loadu_si128((__m128i*) final_hash);

  return challenge;
}

template<typename leaf_t, typename node_t, typename prgkey_t, size_t nodes_per_leaf>
void verify_root_hash(proof_PB<leaf_t, node_t, prgkey_t, nodes_per_leaf> &recv_proof, byte_t final_hash[SHA256_DIGEST_LENGTH],  __m128i& challenge_ = ones, __m128i& not_challenge_ = ones)
{       

  size_t t0 = 0;
  size_t t1 = 0;
  size_t t2 = 0;
  size_t t3 = 0;



  constexpr size_t ncols = 64;
  
  constexpr size_t nrows_p2_root   = 3 * blocklen;
  constexpr size_t nrows_p2_middle = blocklen + ( ( (2 * rounds * 3 * numofboxes)  + 2 + (2 * blocklen)) + (128 - (( (2 * rounds * 3 * numofboxes)  + 2 + (2 * blocklen)) % 128))) * (depth-1);
  constexpr size_t nrows_p2_leaf = blocklen;  
  constexpr size_t nrows_p2 =  nrows_p2_root + nrows_p2_middle + nrows_p2_leaf;
  
  constexpr size_t nrows_r =   (7 * blocklen);
  constexpr size_t nrows_m =   (((4 * (rounds + 1) * 3 * numofboxes) + (4 * blocklen) + 4) + (128 -  (((4 * (rounds + 1) * 3 * numofboxes) + (4 * blocklen) + 4) % 128)) ) * (depth-1);
  constexpr size_t nrows_l =   blocklen;
  constexpr size_t nrows_total = nrows_r + nrows_m + nrows_l;
 

  uint8_t transposed_p2_0[ncols][nrows_p2/8];
  uint8_t transposed_p2_1[ncols][nrows_p2/8];

  uint8_t transposed_p0[ncols][nrows_total/8];
  uint8_t transposed_p1[ncols][nrows_total/8];
 
  const uint8_t * P2_P0_view_transpose = reinterpret_cast<const uint8_t* >((P2_P0_view_V));
  const uint8_t * P2_P1_view_transpose = reinterpret_cast<const uint8_t* >((P2_P1_view_V));

  const uint8_t * P1_view_transpose_t  = reinterpret_cast<const uint8_t* >((gen_view1_64));
  const uint8_t * P0_view_transpose_t  = reinterpret_cast<const uint8_t* >((gen_view0_64));

   trans((uint8_t*)P0_view_transpose_t,   (uint8_t*)transposed_p0, nrows_total, ncols);
   trans((uint8_t*)P1_view_transpose_t,   (uint8_t*)transposed_p1, nrows_total, ncols);
   trans((uint8_t*)P2_P0_view_transpose,   (uint8_t*)transposed_p2_0, nrows_p2 , ncols);
   trans((uint8_t*)P2_P1_view_transpose,   (uint8_t*)transposed_p2_1, nrows_p2 , ncols);
 
  for(size_t j = 0; j < 128; ++j)
  {
      
     if((block<__m128i>(challenge_)).bits[j])
     {
       SHA256_CTX sha256_0;
       SHA256_Init(&sha256_0);   
       
       SHA256_CTX sha256_1;
       SHA256_Init(&sha256_1); 

       const char * view0T_char = reinterpret_cast<const char* >(&transposed_p0[t0]);
       const char * view1T_char = reinterpret_cast<const char* >(&transposed_p1[t0]);
       SHA256_Update(&sha256_0, view0T_char, sizeof(transposed_p0[t0])); 
       SHA256_Final(hash0_v[j], &sha256_0);
      


       SHA256_Update(&sha256_1, view1T_char, sizeof(transposed_p1[t0])); 
       SHA256_Final(hash1_v[j], &sha256_1);

        // std::cout << j << " j = "; for(size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) printf("%x", hash0_v[j][i]);
        // std::cout << std::endl;
        // std::cout << j << " j = "; for(size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) printf("%x", hash1_v[j][i]);
        // std::cout << std::endl;

 
        ++t0;  
      }
      else
      {
        for(size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        {
         hash0_v[j][i] =  recv_proof.P0_hash[j][i];      
         
         hash1_v[j][i] =  recv_proof.P1_hash[j][i];

        }

        
        // std::cout << j << " = << "; for(size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) printf("%x", hash0_v[j][i]);
        // std::cout << std::endl;
        // std::cout << j << " = << "; for(size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) printf("%x", hash1_v[j][i]);
        // std::cout << std::endl;
        
        ++t1;
      }

      if(!(block<__m128i>(challenge_)).bits[j])
      {
       
         SHA256_CTX sha256_P0;
         SHA256_Init(&sha256_P0);

         SHA256_CTX sha256_P1;
         SHA256_Init(&sha256_P1);  
         const char * P2_P0_viewT_char = reinterpret_cast<const char* >(&transposed_p2_0[t2]);
         const char * P2_P1_viewT_char = reinterpret_cast<const char* >(&transposed_p2_1[t2]); 

         SHA256_Update(&sha256_P0, P2_P0_viewT_char, sizeof(transposed_p2_0[t2]));
         SHA256_Update(&sha256_P1, P2_P1_viewT_char, sizeof(transposed_p2_1[t2])); 
       
         SHA256_Final(hashP2_0_v[j], &sha256_P0);
         SHA256_Final(hashP2_1_v[j], &sha256_P1);

        // std::cout << j << " j = "; for(size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) printf("%x", hashP2_0_v[j][i]);
        // std::cout << std::endl;
        // std::cout << j << " j = "; for(size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) printf("%x", hashP2_1_v[j][i]);
        // std::cout << std::endl << std::endl;

       ++t2;
     }
     else
     {
 
       for(size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        {
         hashP2_0_v[j][i] =  recv_proof.P2_0_hash[j][i];
         hashP2_1_v[j][i] =  recv_proof.P2_1_hash[j][i];
       }

        // std::cout << j << " = < "; for(size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) printf("%x", hashP2_0_v[j][i]);
        // std::cout << std::endl;
        // std::cout << j << " = < "; for(size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) printf("%x", hashP2_1_v[j][i]);
        // std::cout << std::endl << std::endl;

       ++t3;
     }
  }
  
 
   
  
  SHA256_CTX sha256_F;
  SHA256_Init(&sha256_F);
  
  for(size_t j = 0; j < 128; ++j)
  {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    char * hash0_char  = reinterpret_cast<char* >(&hash0_v[j]);
    char * hash1_char  = reinterpret_cast<char* >(&hash1_v[j]); 
    char * hashP0_char = reinterpret_cast<char* >(&hashP2_0_v[j]);
    char * hashP1_char = reinterpret_cast<char* >(&hashP2_1_v[j]);
    
    SHA256_Update(&sha256, hash0_char, sizeof(SHA256_DIGEST_LENGTH));
    SHA256_Update(&sha256, hash1_char, sizeof(SHA256_DIGEST_LENGTH)); 
    SHA256_Update(&sha256, hashP0_char, sizeof(SHA256_DIGEST_LENGTH));
    SHA256_Update(&sha256, hashP1_char, sizeof(SHA256_DIGEST_LENGTH));

    SHA256_Final(hash_array_v, &sha256);
    

    // std::cout << j << " ---> hash0_v = "; for(size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) printf("%x", hash0_v[j][i]);
    // std::cout << std::endl;
    // std::cout << j << " ---> hash1_v = "; for(size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) printf("%x", hash1_v[j][i]);
    // std::cout << std::endl;
    // std::cout << j << " ---> hash1_new = "; for(size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) printf("%x", hash1_new[j][i]);
    // std::cout << std::endl;
    // std::cout << j << " ---> hashP2_0_v = "; for(size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) printf("%x", hashP2_0_v[j][i]);
    // std::cout << std::endl;
    // std::cout << j << " ---> hashP2_1_v = "; for(size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) printf("%x", hashP2_1_v[j][i]);
    // std::cout << std::endl;
    // std::cout << j << " ---> = "; for(size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) printf("%x", hash_array_v[i]);
    // std::cout << j << " ---> = "; for(size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) printf("%x", hash_array[i]);
    // std::cout << std::endl;
    
    // for(size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) 
    // {
      
    //     if(hash0_v[j][i] != hash0_new[j][i]) 
    //     {

    //        std::cerr << " (hash0_v) j = " << j << std::endl;
    //     }


    //    if(hash1_v[j][i] != hash1_new[j][i]) 
    //     {

    //        std::cerr << " (hash0_v)  j = " << j << std::endl;
    //     }

    //     if(hashP2_0_v[j][i] != hashP2_0_new[j][i]) 
    //     {

    //        std::cerr << " (hashP2_0_v) j = " << j << std::endl;
    //     }


    //      if(hashP2_1_v[j][i] != hashP2_1_new[j][i]) 
    //     {

    //        std::cerr << " (hashP2_1_v) j = " << j << std::endl;
    //     }


        
    //     assert(hash1_v[j][i] == hash1_new[j][i]);
    //     assert(hash0_v[j][i] == hash0_new[j][i]);
    //     assert(hashP2_0_v[j][i] == hashP2_0_new[j][i]);
    //     assert(hashP2_1_v[j][i] == hashP2_1_new[j][i]);

    //   //if(j != 0) assert(hash_array_v[i] == hash_array[i]);
    // }

    char * hash_array_char = reinterpret_cast<char* >(&hash_array_v); 
    SHA256_Update(&sha256_F, hash_array_char, sizeof(SHA256_DIGEST_LENGTH));  
  }

  SHA256_Final(final_hash_v, &sha256_F);
  
  // final_hash32_t_v = *(uint32_t *)final_hash;
 
 // for(size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) fprintf(stderr,"%x", final_hash_v[i]);
  //std::cerr << std::endl;
 
  // std::cout << std::endl;
  // std::cout << "final_hash32_t_v = " << final_hash32_t_v << std::endl; 
 
}


 

 

 void get_swap_hashes(blockT * zero_share0, blockT * zero_share1, blockT * zero_share_v0, blockT * zero_share_v1, __m128i& challenge)
 {
  
   bool zero_share0_[depth][128][blocklen];
   bool zero_share1_[depth][128][blocklen];
   bool zero_share0_v[depth][128][blocklen];
   bool zero_share1_v[depth][128][blocklen];
   
 
  for(size_t d = 0; d < depth; ++d)
  {
   for(size_t i = 0; i < 128; ++i)
   {
    for(size_t j = 0; j < blocklen; ++j)
    {
      zero_share0_[d][i][j] = (block<__m128i>(zero_share0[d][j])).bits[i];
      zero_share1_[d][i][j] = (block<__m128i>(zero_share1[d][j])).bits[i];
      zero_share0_v[d][i][j] = (block<__m128i>(zero_share_v0[d][j])).bits[i];
      zero_share1_v[d][i][j] = (block<__m128i>(zero_share_v1[d][j])).bits[i];
    }
   }
  }
    
    char outputBuffer[65];
    char outputBuffer_v[65];
    char * string = (char * ) malloc(100 * sizeof(char));
    
    byte_t hash[SHA256_DIGEST_LENGTH];
    byte_t hash_v[SHA256_DIGEST_LENGTH];
    
    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    SHA256_CTX sha256_v;
    SHA256_Init(&sha256_v);

   for(size_t d = 0; d < depth; ++d)
   {
      for(size_t i = 0; i < 128; ++i)
      {
         if(!(block<__m128i>(challenge)).bits[i])  continue;
          
         for(size_t j = 0; j < blocklen; ++j) assert(zero_share1_[d][i][j] == zero_share1_v[d][i][j]);      

          char * zero_share1_char   = reinterpret_cast<char * >(zero_share1_[d][i]);
          SHA256_Update(&sha256, zero_share1_char, sizeof(zero_share1_[d][i]));

          char * zero_share1_char_v = reinterpret_cast<char * >(zero_share1_v[d][i]);
          SHA256_Update(&sha256_v, zero_share1_char_v, sizeof(zero_share1_v[d][i]));

         for(size_t j = 0; j < blocklen; ++j) assert(zero_share0_[d][i][j] == zero_share0_v[d][i][j]);
      }
    }

 

    SHA256_Final(hash, &sha256);
    SHA256_Final(hash_v, &sha256_v);
    // int i = 0;
    // for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
    // {
    // sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    // sprintf(outputBuffer_v + (i * 2), "%02x", hash_v[i]);
    // }
    // outputBuffer[64] = 0;
    // outputBuffer_v[64] = 0;
    // printf("x = %s\n", outputBuffer);
    // printf("y = %s\n", outputBuffer_v);
    
 }



template<typename leaf_t, typename node_t, typename prgkey_t>
void generate_proofs(uint64_t challenge[2], uint64_t not_challenge[2], blockT& seed0, blockT& seed1, blockT& seed2,  dpf_key<leaf_t, node_t, prgkey_t>& dpfkey0,  dpf_key<leaf_t, node_t, prgkey_t>& dpfkey1, 
                    byte_t hash0[128][SHA256_DIGEST_LENGTH], byte_t hash1[128][SHA256_DIGEST_LENGTH], byte_t hashP2_0[128][SHA256_DIGEST_LENGTH], byte_t hashP2_1[128][SHA256_DIGEST_LENGTH],
                    byte_t root_hash[SHA256_DIGEST_LENGTH], std::bitset<depth>  P0direction, std::bitset<depth> P1direction)
{

  std::cout << std::endl << "generate_proofs: " << std::endl; 
  proof_PB<leaf_t, node_t, prgkey_t, nodes_per_leaf> proof_for_P0(dpfkey0); 
  proof_PB<leaf_t, node_t, prgkey_t, nodes_per_leaf> proof_for_P1(dpfkey1);

  __m128i challenge_;
  challenge_[0] = challenge[0];
  challenge_[1] = challenge[1];

  __m128i not_challenge_;
  not_challenge_[0] = not_challenge[0];
  not_challenge_[1] = not_challenge[1];
  blockT seed0_v, seed1_v, seed2_v;
  size_t t0 = 0;
  size_t t2 = 0;
  for(size_t j = 0; j < blocklen; ++j)
  {
    seed0_v[j] = _mm_and_si128(seed0[j], not_challenge_);
    seed1_v[j] = _mm_and_si128(seed1[j], not_challenge_);
    seed2_v[j] = _mm_and_si128(seed2[j], not_challenge_);
  }


   proof_for_P0.direction = P0direction;
   proof_for_P1.direction = P1direction;


  for(size_t j = 0; j < SHA256_DIGEST_LENGTH; ++j)
  {
  
   proof_for_P0.PB_root[j] = final_hash[j];
   proof_for_P1.PB_root[j] = final_hash[j];
  }

  std::cout << "\n\n";

  for(size_t j = 0; j < 128; ++j)
  {
    if(!(block<__m128i>(challenge_)).bits[j])
    {
      for(size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i)
      {
       proof_for_P0.P0_hash[j][i] = hash0_new[j][i];
       proof_for_P0.P1_hash[j][i] = hash1_new[j][i];

       proof_for_P1.P0_hash[j][i] = hash0_new[j][i];
       proof_for_P1.P1_hash[j][i] = hash1_new[j][i];
      }
      ++t0;
    }
    else
    {  
      for(size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i)
      {
       proof_for_P0.P2_0_hash[j][i] = hashP2_0_new[j][i];
       proof_for_P0.P2_1_hash[j][i] = hashP2_1_new[j][i];

       proof_for_P1.P2_0_hash[j][i] = hashP2_0_new[j][i];
       proof_for_P1.P2_1_hash[j][i] = hashP2_1_new[j][i];
      }
      ++t2;
    }
  }

   proof_for_P0.seed = seed0;
   proof_for_P1.seed = seed1;

   proof_for_P0.seed_other = seed1_v;
   proof_for_P1.seed_other = seed0_v;
 
   proof_for_P0.seed2 = seed2;
   proof_for_P1.seed2 = seed2;

   proof_for_P0.PB_other->root = P1_view_64->root;
   proof_for_P0.P2_view->root = P2_P0_view_64->root;
 

  for(size_t d = 0; d < depth-1; ++d)
  {
     proof_for_P0.PB_other->middle[d] = P1_view_64->middle[d];
     proof_for_P0.P2_view->middle[d] = P2_P0_view_64->middle[d];
  }
   proof_for_P0.PB_other->leaf = P1_view_64->leaf;
   proof_for_P0.P2_view->leaf = P2_P0_view_64->leaf;
  
  
   proof_for_P1.PB_other->root = P0_view_64->root;
   proof_for_P1.P2_view->root = P2_P1_view_64->root;

   for(size_t d = 0; d < depth-1; ++d)
   {
     proof_for_P1.PB_other->middle[d] = P0_view_64->middle[d];
     proof_for_P1.P2_view->middle[d] = P2_P1_view_64->middle[d];
   }
   proof_for_P1.PB_other->leaf = P0_view_64->leaf;
   proof_for_P1.P2_view->leaf = P2_P1_view_64->leaf;
  
   
   write_proof("proof_for_P0.dat", proof_for_P0);
   write_proof("proof_for_P1.dat", proof_for_P1);
}

 