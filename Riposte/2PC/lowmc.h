
#ifndef __LowMC_h__
#define __LowMC_h__

#include <climits>      // CHAR_BIT
#include <array>

#include "block.h"
#include<assert.h>
#include "lowmc-utils.h" 
using namespace dpf;
 
template <typename __mX = __m128i>
class LowMC
{ 
  public:
	using block_t  = block<__mX>;
	using keyblock_t = block<__m128i>;

  #include "roundconstants.h"
	 
  static constexpr unsigned rounds = 128;     // Number of rounds
	static constexpr unsigned numofboxes = 2; // Number of Sboxes
	static constexpr unsigned blocksize = CHAR_BIT * sizeof(__mX); // Block size in bits
	static constexpr unsigned keysize = 128;    // Key size in bits
 
	const size_t identitysize;
    // Size of the identity part in the Sbox layer 

	const block_t mask   = std::string("0100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100100");
  block_t maska;//  = bits_ >> (identitysize-1);  
	block_t maskb;//  = maska >> 1; 
	block_t maskc;//  = maska >> 2;
	block_t maskbc;// = maskb | maskc;
	const keyblock_t key;  //Stores the master key

	LowMC(const __m128i & key_ = _mm_setzero_si128())
	  : //rounds(128),
	    //numofboxes(63),
	    identitysize(blocksize - 3*numofboxes),
	    key(key_)
	{
         maska  = mask;  
         maska.shiftr(identitysize-1);
         maskb  = maska >> 1;
         maskc  = maska >> 2;
         maskbc = maskb | maskc;
		//instantiate_LowMC();  
		//keyschedule();
	}

//  template <typename T>
//  std::array<T, blocklen> mmul256(const uint64_t * matrix1, const std::array<T, blocklen>&  matrix2,  const block_t & initial_value) const;
  
  template<typename T>
  void temp(T x);

  //auto encrypt_(const std::array<__m128i, blocklen> & message) const; 
  
  template<typename T>
  auto encrypt_(const std::array<T, blocklen> & message) const;
	
  auto encrypt(const block_t & message) const;
	auto encrypt_MPC (const block_t & message, const block_t blind[], const block_t gamma[], const bool P = 0) const;
  
  template<typename T>
  auto encrypt_MPC_proof_(
    const std::array<T, blocklen> & m0, const std::array<T, blocklen> & m1, const std::array<T, 3 * numofboxes> * blind0, 
    const std::array<T, 3 * numofboxes> * blind1, const std::array<T, 3 * numofboxes> * gamma0, const std::array<T, 3 * numofboxes> * gamma1, 
    std::array<T, 3 * numofboxes> * encrypt_outL, std::array<T, 3 * numofboxes> * encrypt_outR) const;
  
  template<typename T>
  auto encrypt_MPC_verify_(const std::array<T, blocklen> & message, const std::array<T, 3 * numofboxes>* c2, 
                           const std::array<T, 3 * numofboxes> * blind, const std::array<T, 3 * numofboxes> * gamma, const bool P, 
                           std::array<T, 3 * numofboxes> * encrypt_out) const;

  auto encrypt_MPC_proof(const block_t & m0, const block_t & m1, const block_t blind0[], const block_t blind1[], block_t gamma0[], block_t gamma1[], block_t encrypt_outL[], block_t encrypt_outR[]) const;
	auto encrypt_MPC_verify(const block_t & message, const block_t c2[], const block_t blind[], block_t gamma[], const bool P, block_t encrypt_out[]) const;

  //private:
	// LowMC private data members // 
	std::vector<std::vector<block_t>> LinMatrices;
  
  std::vector<std::vector<block_t>> transposeLinMatrices;

	// Stores the binary matrices for each round 
	std::vector<std::vector<block_t>> invLinMatrices;
	// Stores the inverses of LinMatrices
	std::vector<block_t> roundkeysXORconstants;
	// Stores the round constants
	std::vector<std::vector<keyblock_t>> KeyMatrices;
	// Stores the matrices that generate the round keys

	// LowMC private functions //
	auto Substitution (const block_t & message) const;

  template<typename T>
  void Substitution_(std::array<T, blocklen> & message) const;
	// void Substitution_(std::array<uint64_t, blocklen> & message) const;
  auto Substitution_MPC (const block_t & message, const block_t & message2, const block_t & blind, const block_t & gamma) const;
	
  template<typename T>
  void Substitution_MPC_(std::array<T, blocklen> & message, const std::array<T, 3 * numofboxes> & message2, const std::array<T, 3 * numofboxes> & blind, const std::array<T, 3 * numofboxes> & gamma) const;
 
  void GenBlinds(block_t *blinds[2], block_t *gamma[2]);
  
   
  auto MultiplyWithGF2Matrix_(const std::vector<block_t> & matrix, const std::array<__m128i, blocklen> & message, const block_t & initial_value) const;
	
  auto MultiplyWithGF2Matrix(const block_t * matrix, const block_t & message, const block_t & initial_value = 0) const;
	// For the linear layer
	auto MultiplyWithGF2Matrix_Key(const std::vector<keyblock_t> & matrix, const keyblock_t & k) const;
	// For generating the round keys

	void keyschedule();
	//Creates the round keys from the master key

	void instantiate_LowMC ();
  void instantiate_LowMC_ ();
	//Fills the matrices and roundconstants with pseudorandom bits 

	// Binary matrix functions //
	unsigned rank_of_Matrix (const std::vector<block_t> & matrix);
	unsigned rank_of_Matrix_Key (const std::vector<keyblock_t> & matrix);
	auto invert_Matrix (const std::vector<block_t> & matrix)
	{
    //std::cout << "invert" << std::endl;
    std::vector<typename LowMC<__mX>::block_t> mat; //Copy of the matrix 
    for (auto u : matrix)
    {
        mat.push_back(u);
    }
    
   std::vector<typename LowMC<__mX>::block_t> invmat(LowMC<__mX>::blocksize, 0); //To hold the inverted matrix
   
   // for (unsigned i = 0; i < blocksize; ++i) {
   //      for (unsigned j = 0; j < blocksize; ++j) {
   //      invmat[i][j] = 0;
   //      }
   //  }
        //std::cout << "invert" << std::endl;
    for (unsigned i = 0; i < LowMC<__mX>::blocksize; ++i)
    {
        invmat[i][i] = 1;
    }

    unsigned size = mat[0].size();

    //Transform to upper triangular matrix

    unsigned row = 0;
    for (unsigned col = 0; col < size; ++col) {
        if ( !mat[row][col] ) {
            unsigned r = row+1;
            while (r < mat.size() && !mat[r][col]) {
                ++r;
            }
            if (r >= mat.size()) {
                continue;
            } else {
                auto temp = mat[row];
                mat[row] = mat[r];
                mat[r] = temp;
                temp = invmat[row]; 
                invmat[row] = invmat[r];
                invmat[r] = temp;
            }
        }
        for (unsigned i = row+1; i < mat.size(); ++i) {
            if ( mat[i][col] ) {
                mat[i] ^= mat[row];
                invmat[i] ^= invmat[row]; 
            }
        }

        ++row;
    }

  
    //Transform to identity matrix
    for (unsigned col = size; col > 0; --col) {
        for (unsigned r = 0; r < col-1; ++r) {
            if (mat[r][col-1]) {
                mat[r] ^= mat[col-1];
                invmat[r] ^= invmat[col-1];
            }
        }
    }
 // std::cout << "done: " << std::endl;
    return invmat;
}
  auto transpose_Matrix (const std::vector<block_t> & matrix)
  {
      std::vector<typename LowMC<__mX>::block_t> transposemat(LowMC<__mX>::blocksize, 0); //To hold the inverted matrix
      for(size_t i = 0; i < blocklen; ++i)
      {
        for(size_t j = 0; j < blocklen; ++j)
        {
          transposemat[j].bits[i] = matrix[i].bits[j];
        }
      }

    return transposemat;
  }

	// Random bits functions //
	block_t getrandblock_t();
	keyblock_t getrandkeyblock_t();
	bool getrandbit();

};






//template<typename T = __m128i>
std::array<__m128i, blocklen> mmul256(const uint64_t * matrix1, const std::array<__m128i, blocklen> & matrix2, const block<__m128i> & initial_value)
{
    std::array<__m128i, blocklen> answer;

    for (int i = 0; i < blocklen; ++i) answer[i] = _mm_set1_epi8(initial_value.bits[i] ? 0xff : 0);
 
    __m128i lut[8][256];

    for(int i = 0; i < sizeof(__m128i)/8; ++i)
    {
      populate_lut(i, matrix2, lut);

      for(int j = 0; j < blocklen; ++j)
       {
            uint64_t tmp_ = matrix1[i + (sizeof(__m128i)/8) * j];
            // std::bitset<64> tmp(matrix1[i + (2 * j)]);
        
            for(size_t k = 0; k < 8; ++k)
            {
                 answer[j] ^= lut[k][tmp_ & 0xff];  
                 tmp_ >>= 8;
            }

        }
    }

    return std::move(answer);
}

 
std::array<uint64_t, blocklen> mmul256(const uint64_t * matrix1, const std::array<uint64_t, blocklen> & matrix2, const block<__m128i> & initial_value)
{
    std::array<uint64_t, blocklen> answer;

    for (int i = 0; i < blocklen; ++i) answer[i] =  (initial_value.bits[i] ? -1 : 0);
 
    uint64_t lut[8][256];

    for(int i = 0; i < blocklen/64; ++i)
    {
      populate_lut(i, matrix2, lut);

      for(int j = 0; j < blocklen; ++j)
       {
            uint64_t tmp_ = matrix1[i + (blocklen/64) * j];
            // std::bitset<64> tmp(matrix1[i + (2 * j)]);
        
            for(size_t k = 0; k < 8; ++k)
            {
                 answer[j] ^= lut[k][tmp_ & 0xff];  
                 tmp_ >>= 8;
            }

        }
    }

    return std::move(answer);
}

template<typename __mX>
template<typename T>
void LowMC<__mX>::temp(T x)
{

}


// template <typename __mX>
// auto LowMC<__mX>::encrypt_(const std::array<__m128i, blocklen> & message) const   
// {
//     std::array<__m128i, blocklen> c;
//     for (int i = 0; i < blocklen; ++i) c[i] = message[i] ^ _mm_set1_epi8(roundkeysXORconstants_[0].bits[i] ? -1 : 0);
  
//     for (unsigned r = 1; r <= rounds; ++r)
//   {  
//          Substitution_(c);  
//         const uint64_t * M = transpose_mat[r-1];// reinterpret_cast<const uint64_t *>(transposeLinMatrices[r-1].data());
//         c = mmul256(M, c, roundkeysXORconstants_[r]);
//        //c = MultiplyWithGF2Matrix_(transposeLinMatrices[r-1], c, roundkeysXORconstants[r]);

//   } 

//   return c;
// }


template <typename __mX>
template <typename T>
auto LowMC<__mX>::encrypt_(const std::array<T, blocklen> & message) const   
{
    std::array<T, blocklen> c;

    //this function returns message[i] ^ _mm_set1_epi8(roundkeysXORconstants_[0].bits[i] ? -1 : 0);
    for (int i = 0; i < blocklen; ++i) c[i] = _mm_set1_epi8_xor(message[i], roundkeysXORconstants_[0].bits[i]);// (roundkeysXORconstants_[0].bits[i] ? -1 : 0);
    
    for (unsigned r = 1; r <= rounds; ++r)
    {  
      Substitution_(c);  
      const uint64_t * M = transpose_mat[r-1];// reinterpret_cast<const uint64_t *>(transposeLinMatrices[r-1].data());
      c = mmul256(M, c, roundkeysXORconstants_[r]);
       
    } 

    return c;
}

template <typename __mX>
auto LowMC<__mX>::encrypt(const block_t & message) const   
{
    block_t c = message ^ roundkeysXORconstants_[0];
    for (unsigned r = 1; r <= rounds; ++r)
    {  
       c =  Substitution(c);
     
       //std::vector<block_t> lin = (lin_mat[r-1]);
       const block_t * lin = reinterpret_cast<const block_t*>(lin_mat[r-1]);
       c =  MultiplyWithGF2Matrix(lin, c, roundkeysXORconstants_[r]);
    }
    return c;
}

 


template<typename __mX>
template<typename T>
auto LowMC<__mX>::encrypt_MPC_verify_( const std::array<T, blocklen> & message, const std::array<T, 3 * numofboxes> * c2, 
                                       const std::array<T, 3 * numofboxes> * blind, const std::array<T, 3 * numofboxes> * gamma, const bool P, 
                                       std::array<T, 3 * numofboxes >* encrypt_out) const
{



 
    std::array<T, blocklen> tmp;

    if(!P)
    {
      for(size_t j = 0; j < blocklen; ++j) tmp[j]  = message[j];
    } 
    else 
    {
      for(size_t j = 0; j < blocklen; ++j) tmp[j]  = _mm_set1_epi8_xor(message[j], roundkeysXORconstants_[0].bits[j]);
    }

    for(size_t r = 1; r <= rounds; ++r)
    {
        for(size_t j = 0; j < 3 * numofboxes; ++j)
        {
          encrypt_out[r-1][j] = tmp[j] ^ blind[r-1][j];         
        }

        Substitution_MPC_(tmp, c2[r-1], blind[r-1], gamma[r-1]);
        
        const uint64_t * M = transpose_mat[r-1];
        if(P)  tmp = mmul256(M, tmp, 0);
        if(!P) tmp = mmul256(M, tmp, roundkeysXORconstants_[r]);
 
    }

    for(size_t j = 0; j < 3 * numofboxes; ++j)
    {
      encrypt_out[rounds][j] = tmp[j];
    }

    return tmp;
}   


template <typename __mX>
template <typename T>
auto LowMC<__mX>::encrypt_MPC_proof_(
    const std::array<T, blocklen> & m0, const std::array<T, blocklen> & m1, const std::array<T, 3 * numofboxes> * blind0, 
    const std::array<T, 3 * numofboxes> * blind1, const std::array<T, 3 * numofboxes> * gamma0, const std::array<T, 3 * numofboxes> * gamma1, 
    std::array<T, 3 * numofboxes> * encrypt_outL, std::array<T, 3 * numofboxes> * encrypt_outR) const
{
    std::array<T, 3 * numofboxes> * c0   = (std::array<T, 3 * numofboxes> *) std::aligned_alloc(sizeof(__m256i), (rounds + 1) * sizeof(std::array<T, 3 * numofboxes>));  //[rounds+1];
 
    std::array<T, 3 * numofboxes> * c1  = (std::array<T, 3 * numofboxes> *) std::aligned_alloc(sizeof(__m256i), (rounds + 1) * sizeof(std::array<T, 3 * numofboxes>)); //[rounds+1];
 

    std::array<T, blocklen> tmp0;
    std::array<T, blocklen> tmp1;
 
    for(size_t j = 0; j < blocklen; ++j) tmp0[j] = m0[j];
 
    for(size_t j = 0; j < blocklen; ++j) tmp1[j]  =  _mm_set1_epi8_xor(m1[j], roundkeysXORconstants_[0].bits[j]);
 
    for (unsigned r = 1; r <= rounds; ++r) 
    {
       for(size_t j = 0; j < 3 * numofboxes; ++j) 
       {            
         encrypt_outL[r-1][j] = tmp0[j] ^ blind0[r-1][j];         
         c0[r-1][j] = encrypt_outL[r-1][j];
       }
    
            
       for(size_t j = 0; j < 3 * numofboxes; ++j)
       {
         encrypt_outR[r-1][j] = tmp1[j] ^ blind1[r-1][j];   
         c1[r-1][j] = encrypt_outR[r-1][j];   
       }    
          
 
        const uint64_t * M = transpose_mat[r-1];// reinterpret_cast<const uint64_t *>(transposeLinMatrices[r-1].data());
        // std::array<__m128i, 256> answer;

        Substitution_MPC_(tmp0, c1[r-1], blind0[r-1], gamma0[r-1]);
     
        tmp0 = mmul256(M, tmp0, roundkeysXORconstants_[r]);
        //tmp0 = MultiplyWithGF2Matrix_(transposeLinMatrices[r-1], tmp0, roundkeysXORconstants[r]);
 
        Substitution_MPC_(tmp1, c0[r-1], blind1[r-1], gamma1[r-1]);
       
        //tmp1 = MultiplyWithGF2Matrix_(transposeLinMatrices[r-1], tmp1, 0);
        tmp1 = mmul256(M, tmp1, 0);
 
    }
    
     for(size_t j = 0; j < 3 * numofboxes; ++j)
     {
      encrypt_outL[rounds][j] = tmp0[j];
      encrypt_outR[rounds][j] = tmp1[j];
     }

    // c0[rounds] = tmp0;
    // c1[rounds] = tmp1;

     free(c0);
     free(c1);
    return std::make_pair(std::move(tmp0), std::move(tmp1));
}

 

template <typename __mX>
auto LowMC<__mX>::Substitution(const block_t & message) const
{
  const block_t srli1 = (message >> 1) & maskbc;
  const block_t srli2 = (message >> 2) & maskc;
 
  const block_t tmp = message & srli1;
 
  const block_t bc = (tmp << 2) & maska;
  const block_t ac = (message & srli2) << 1;
  const block_t ab = (tmp >> 1) & maskc;
 
 
  return (bc | ac | ab) ^ message ^ srli1 ^ srli2;
}


template <typename __mX>
template <typename T>
void LowMC<__mX>::Substitution_(std::array<T, blocklen> & message) const
{
     
    for (int i = 0, j = 0; i < numofboxes; ++i, j+=3)
    {
        const T C = (message[j+2] & message[j+1]) ^ message[j+1] ^ message[j+2];
        const T B = (message[j+0] & message[j+2]) ^ message[j+2];
        const T A = (message[j+0] & message[j+1]);

        message[j+0] ^= C;
        message[j+1] ^= B;
        message[j+2] ^= A;
    }
}

// template <typename __mX>
// void LowMC<__mX>::Substitution_(std::array<uint64_t, blocklen> & message) const
// {
     
//     for (int i = 0, j = 0; i < numofboxes; ++i, j+=3)
//     {
//         const uint64_t C = (message[j+2] & message[j+1]) ^ message[j+1] ^ message[j+2];
//         const uint64_t B = (message[j+0] & message[j+2]) ^ message[j+2];
//         const uint64_t A = (message[j+0] & message[j+1]);

//         message[j+0] ^= C;
//         message[j+1] ^= B;
//         message[j+2] ^= A;
//     }
// }

template <typename __mX>
template <typename T>
void LowMC<__mX>::Substitution_MPC_(std::array<T, blocklen> & message, const std::array<T, 3 * numofboxes > & message2, const std::array<T, 3 * numofboxes > & blind, const std::array<T, 3  * numofboxes> & gamma) const
{
      std::array<T, 3 * numofboxes> message3;// = {message[j+0] ^ message2[j+0], message[j+1] ^ message2[j+1], message[j+2] ^ message2[j+2]} ;
      
      for(size_t j = 0; j < 3 * numofboxes; ++j)
      {
        message3[j] = message[j] ^ message2[j]; 
      }
  for (int i = 0, j = 0; i < numofboxes; ++i, j+=3)
  {


      const T C = (message3[j+2] & message[j+1]) ^ (blind[j+2] & message2[j+1]) ^ message[j+1] ^ message[j+2] ;
      const T B = (message3[j+0] & message[j+2]) ^ (blind[j+0] & message2[j+2]) ^ message[j+2] ;
      const T A = (message3[j+1] & message[j+0]) ^ (blind[j+1] & message2[j+0]);// ^ message[j] 
      
    
      message[j+0] ^= (C ^ gamma[j + 0]);
      message[j+1] ^= (B ^ gamma[j + 1]);
      message[j+2] ^= (A ^ gamma[j + 2]);
      
  }
  //  return (bc | ac | ab) ^ message ^ srli1 ^ srli2 ^ gamma;
}




template <typename __mX>
auto LowMC<__mX>::Substitution_MPC(const block_t & message, const block_t & message2, const block_t & blind, const block_t & gamma) const
{
      
    const block_t srli1 = (message >> 1) & maskbc;
    const block_t srli2 = (message >> 2) & maskc;

    const block_t message3 = message ^ message2;
    const block_t tmp = (message3 & srli1) ^ (blind & (message2 >> 1));
    const block_t bc = (tmp << 2) & maska;
    const block_t ac = (((message3 & srli2) ^ (blind & (message2 >> 2))) << 1) & maskb;
    const block_t ab = (tmp >> 1) & maskc;

    return (bc | ac | ab) ^ message ^ srli1 ^ srli2 ^ gamma;
}

template <typename __mX>
void LowMC<__mX>::GenBlinds(block_t *blinds[2], block_t *gamma[2])
{
  block_t rand;
  arc4random_buf(blinds, 2*sizeof(blinds[0]));
  for (unsigned r = 0; r < rounds; ++r)
  {
    arc4random_buf(&rand, sizeof(rand));
    const block_t tmp1 = ((blinds[0][r] >> 1) & blinds[1][r]) ^ ((blinds[1][r] >> 1) & blinds[0][r]);
    const block_t tmp2 = ((blinds[0][r] >> 2) & blinds[1][r]) ^ ((blinds[1][r] >> 2) & blinds[0][r]);

    const block_t bc = (tmp1 << 2) & maska;
    const block_t ac = (tmp2 << 1) & maskb;
    const block_t ab = (tmp1 >> 1) & maskc;

    gamma[0][r] = (bc | ac | ab) ^ rand;
    gamma[1][r] = rand ^ roundkeysXORconstants_[r+1];
  }
}

template <typename __mX>
auto LowMC<__mX>::MultiplyWithGF2Matrix_(const std::vector<block_t> & matrix, const std::array<__m128i, blocklen> & message, const block_t & initial_value) const
{
    std::array<__m128i, blocklen> temp;
    for (int i = 0; i < blocklen; ++i) temp[i] = _mm_set1_epi8(initial_value.bits[i] ? 0xff : 0);
 

    for (size_t i = 0; i < blocklen; ++i)
    {
        for (size_t k = 0; k < sizeof(block_t)/8; ++k)
        {
            uint64_t bitset = static_cast<__mX>(matrix[i])[k];
            
            while (bitset != 0)
            {
              uint64_t t = bitset & -bitset;
              int j = k * 64 + __builtin_ctzl(bitset);                
              temp[i] ^= message[j]; 
              bitset ^= t;
            }
             
        }
    }
 

    return temp;
}

template <typename __mX>
auto LowMC<__mX>::MultiplyWithGF2Matrix(const block_t* matrix, const block_t & message, const block_t & initial_value) const
{
  block_t temp =  initial_value;
    uint64_t bitset ;
 
     for (size_t k = 0; k < sizeof(block_t)/8; ++k)
   {
    bitset = static_cast<__mX>(message)[k];
        while (bitset != 0)
    {
      uint64_t t = bitset & -bitset;
      int j = k * 64 + __builtin_ctzl(bitset);
      
            temp =  temp ^ matrix[j];
          bitset ^= t;
    }
   }

  return temp;
}

template <typename __mX>
auto LowMC<__mX>::MultiplyWithGF2Matrix_Key(const std::vector<keyblock_t> & matrix, const keyblock_t & k) const
{
  block_t temp = 0;
  for (unsigned i = 0; i < blocksize; ++i)
  {
    temp[i] = (k & matrix[i]).parity();
  }
  return temp;
}

template <typename __mX>
void LowMC<__mX>::keyschedule ()
{
  for (unsigned r = 0; r <= rounds; ++r)
  {
    roundkeysXORconstants[r] ^= MultiplyWithGF2Matrix_Key (KeyMatrices[r], key);
  }
}



template <typename __mX>
void LowMC<__mX>::instantiate_LowMC ()
{

 
  LinMatrices.clear();
  //invLinMatrices.clear();
  for (unsigned r = 0; r < rounds; ++r)
  {
    // Create matrix
    std::vector<block_t> mat;
    // Fill matrix with random bits
    do
    {
      mat.clear();
      for (unsigned i = 0; i < blocksize; ++i)
      {
        mat.push_back(getrandblock_t());
      }

    // Repeat if matrix is not invertible
    } while ( rank_of_Matrix(mat) != blocksize );
    LinMatrices.push_back(mat);
    //invLinMatrices.push_back(invert_Matrix (LinMatrices.back()));
        //transposeLinMatrices.push_back(transpose_Matrix (LinMatrices.back()));
  }
    
 
  // Create roundconstants
  // roundkeysXORconstants.clear();
  // roundkeysXORconstants.push_back(0);
 
    //for (unsigned r = 0; r < rounds; ++r)
  // {
  //  roundkeysXORconstants.push_back( getrandblock_t () );
  // } 

    // Create KeyMatrices
  // KeyMatrices.clear();
  // for (unsigned r = 0; r <= rounds; ++r)
  // {
  //  // Create matrix
  //  std::vector<keyblock_t> mat;
  //  // Fill matrix with random bits
  //  do
  //  {
  //    mat.clear();
  //    for (unsigned i = 0; i < blocksize; ++i)
  //    {
  //      mat.push_back( getrandkeyblock_t () );
  //  }
  //  // Repeat if matrix is not of maximal rank
  //  } while(rank_of_Matrix_Key(mat) < std::min(blocksize, keysize));
  //  KeyMatrices.push_back(mat);
  // }
 
}


/////////////////////////////
// Binary matrix functions //
/////////////////////////////

template <typename __mX>
unsigned LowMC<__mX>::rank_of_Matrix (const std::vector<block_t> & matrix) {
    std::vector<block_t> mat; //Copy of the matrix 
    for (auto u : matrix) {
        mat.push_back(u);
    }
    unsigned size = mat[0].size();
    //Transform to upper triangular matrix
    unsigned row = 0;
    for (unsigned col = 1; col <= size; ++col) {
        
        if ( !mat[row][size-col] ) {
            unsigned r = row;
            while (r < mat.size() && !mat[r][size-col]) {
                ++r;
            }


            if (r >= mat.size()) {
                continue;
            } else {
                auto temp = mat[row];
                mat[row] = mat[r];
                mat[r] = temp;
            }
        }
        for (unsigned i = row+1; i < mat.size(); ++i) {
            if ( mat[i][size-col] ) mat[i] ^= mat[row];
        }
        ++row;
        if (row == size) break;
    }
    return row;
}

template <typename __mX>
unsigned LowMC<__mX>::rank_of_Matrix_Key (const std::vector<keyblock_t> & matrix) {
    std::vector<keyblock_t> mat; //Copy of the matrix 
    for (auto u : matrix) {
        mat.push_back(u);
    }
    unsigned size = mat[0].size();
    //Transform to upper triangular matrix
    unsigned row = 0;
    for (unsigned col = 1; col <= size; ++col) {
        if ( !mat[row][size-col] ) {
            unsigned r = row;
            while (r < mat.size() && !mat[r][size-col]) {
                ++r;
            }
            if (r >= mat.size()) {
                continue;
            } else {
                auto temp = mat[row];
                mat[row] = mat[r];
                mat[r] = temp;
            }
        }
        for (unsigned i = row+1; i < mat.size(); ++i) {
            if ( mat[i][size-col] ) mat[i] ^= mat[row];
        }
        ++row;
        if (row == size) break;
    }
    return row;
}

//std::vector<block_t> invert_Matrix (const std::vector<block_t> matrix);

/*template <typename __mX>
std::vector<typename LowMC<__mX>::block_t> invert_Matrix(const std::vector<typename LowMC<__mX>::block_t> matrix)
{
    //std::cout << "invert" << std::endl;
    std::vector<typename LowMC<__mX>::block_t> mat; //Copy of the matrix 
    for (auto u : matrix)
    {
        mat.push_back(u);
    }
    
   std::vector<typename LowMC<__mX>::block_t> invmat(LowMC<__mX>::blocksize, 0); //To hold the inverted matrix
   
   // for (unsigned i = 0; i < blocksize; ++i) {
   //      for (unsigned j = 0; j < blocksize; ++j) {
   //      invmat[i][j] = 0;
   //      }
   //  }
        //std::cout << "invert" << std::endl;
    for (unsigned i = 0; i < LowMC<__mX>::blocksize; ++i)
    {
        invmat[i][i] = 1;
    }

    unsigned size = mat[0].size();

    //Transform to upper triangular matrix

    unsigned row = 0;
    for (unsigned col = 0; col < size; ++col) {
        if ( !mat[row][col] ) {
            unsigned r = row+1;
            while (r < mat.size() && !mat[r][col]) {
                ++r;
            }
            if (r >= mat.size()) {
                continue;
            } else {
                auto temp = mat[row];
                mat[row] = mat[r];
                mat[r] = temp;
                temp = invmat[row]; 
                invmat[row] = invmat[r];
                invmat[r] = temp;
            }
        }
        for (unsigned i = row+1; i < mat.size(); ++i) {
            if ( mat[i][col] ) {
                mat[i] ^= mat[row];
                invmat[i] ^= invmat[row]; 
            }
        }

        ++row;
    }

  
    //Transform to identity matrix
    for (unsigned col = size; col > 0; --col) {
        for (unsigned r = 0; r < col-1; ++r) {
            if (mat[r][col-1]) {
                mat[r] ^= mat[col-1];
                invmat[r] ^= invmat[col-1];
            }
        }
    }
 // std::cout << "done: " << std::endl;
    return invmat;
}*/

///////////////////////
// Pseudorandom bits //
///////////////////////

template <typename __mX>
typename LowMC<__mX>::block_t LowMC<__mX>::getrandblock_t () {
    block_t tmp = 0;
    for (unsigned i = 0; i < blocksize; ++i)
    {
     tmp[i] = getrandbit ();
     }
    return tmp;
}

template <typename __mX>
typename LowMC<__mX>::keyblock_t LowMC<__mX>::getrandkeyblock_t()
{
    keyblock_t tmp = 0;
    for (unsigned i = 0; i < keysize; ++i) tmp[i] = getrandbit();
    return tmp;
}


// Uses the Grain LSFR as self-shrinking generator to create pseudorandom bits
// Is initialized with the all 1s state
// The first 160 bits are thrown away
template <typename __mX>
bool LowMC<__mX>::getrandbit()
{
    static std::bitset<80> state; //Keeps the 80 bit LSFR state
    bool tmp = 0;
    //If state has not been initialized yet
    if (state.none ()) {
        state.set (); //Initialize with all bits set
        //Throw the first 160 bits away
        for (unsigned i = 0; i < 160; ++i) {
            //Update the state
            tmp =  state[0] ^ state[13] ^ state[23]
                       ^ state[38] ^ state[51] ^ state[62];
            state >>= 1;
            state[79] = tmp;
        }
    }
    //choice records whether the first bit is 1 or 0.
    //The second bit is produced if the first bit is 1.
    bool choice = false;
    do {
        //Update the state
        tmp =  state[0] ^ state[13] ^ state[23]
                   ^ state[38] ^ state[51] ^ state[62];
        state >>= 1;
        state[79] = tmp;
        choice = tmp;
        tmp =  state[0] ^ state[13] ^ state[23]
                   ^ state[38] ^ state[51] ^ state[62];
        state >>= 1;
        state[79] = tmp;
    } while (! choice);
    return tmp;
}
#endif
