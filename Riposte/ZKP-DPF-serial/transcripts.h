

 struct from_P2_root
  {
    block_t c[4];  // Conditional Swap
    bool c_bit[4]; // Get Next Bits
  }; 


  struct from_P2_middle
  {
    block_t blindR[rounds]; // Used in encrypt
    block_t blindL[rounds]; // Used in encrypt
    
    block_t gamma0[rounds]; // Used in encrypt
    block_t gamma1[rounds]; // Used in encrypt
    
    block_t c[4];  // Conditional Swap
    bool c_bit[4]; // Get Next Bits
  };


  struct from_P2_middle_compressed
  {
    std::vector<bool> gamma0;
    std::vector<bool> gamma1;
    
    block_t c[4];
    bool c_bit[4];
  };


  struct from_P2_leaf
  {
    size_t data = 0;
  };


  struct P2_transcript
  {
    from_P2_root   root;
    from_P2_middle * middle;
    from_P2_leaf leaf ;
  };


 struct  from_PB_root
 {
   block_t blinds_recv[4];   // To do conditional swap
   bool bit_blinds_recv[4];  // To do conditional swap
   bool next_bit_L_recv[4];  
   bool next_bit_R_recv[4];  
   block_t L_shares_recv,  R_shares_recv; // root layer  
   bool bit_L_shares_recv, bit_R_shares_recv; // root layer  
 };
 
 struct from_PB_middle
 {
  block_t seed0L_encrypt[rounds+1]; // Used in encrypt
  block_t seed0R_encrypt[rounds+1]; // Used in encrypt
  block_t seed1L_encrypt[rounds+1]; // Used in encrypt
  block_t seed1R_encrypt[rounds+1]; // Used in encrypt
    
  block_t blinds_recv[4];   // To do conditional swap
  bool bit_blinds_recv[4];  // To do conditional swap
  bool next_bit_L_recv[4];  
  bool next_bit_R_recv[4];   
 };





 struct from_PB_middle_compressed
 { 
  std::bitset<3 * numofboxes + 1> seed0L_encrypt[rounds+1];
  std::bitset<3 * numofboxes> seed0R_encrypt[rounds+1];
  std::bitset<3 * numofboxes> seed1L_encrypt[rounds+1];
  std::bitset<3 * numofboxes> seed1R_encrypt[rounds+1];
    
  block_t blinds_recv[4];   // To do conditional swap
  bool bit_blinds_recv[4];  // To do conditional swap
  bool next_bit_L_recv[4];  
  bool next_bit_R_recv[4];   
 };


 struct from_PB_leaf
 {
    block_t final_cw; // final layer
 };
 

struct PB_transcript
{
  from_PB_root   root;
  from_PB_middle * middle;
  from_PB_leaf leaf;

};



 void decompress_transcript( block_t * gamma0_, block_t * gamma1_, block_t * blind0_, block_t *blind1_, 
                        block_t * gamma0, block_t * gamma1, block_t * blind0, block_t *blind1, size_t n_256)
 {
  size_t t = 0;
  for(size_t j = 0; j < n_256; ++j)
  {
  
    for(size_t i = 0; i < 85; ++ i)
    { 
      block_t mask_  = std::string("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000111");
      mask_.shiftl(i * nboxbits);
     
      blind0_[t] = blind0[j] & mask_;
      blind0_[t].shiftr(i * nboxbits);
     
      blind1_[t] = blind1[j] & mask_;
      blind1_[t].shiftr(i * nboxbits);
      
      gamma0_[t] = gamma0[j] & mask_;
      gamma0_[t].shiftr(i * nboxbits);
      
      gamma1_[t] = gamma1[j] & mask_;
      gamma1_[t].shiftr(i * nboxbits);
      
      ++t;
    }
  }
 }