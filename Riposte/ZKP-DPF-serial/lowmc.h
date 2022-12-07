#ifndef __LowMC_h__
#define __LowMC_h__

#include <climits>      // CHAR_BIT

#include "block.h"
 
using namespace dpf;

template <typename __mX = __m256i>
class LowMC
{
  public:
	using block_t = block<__mX>;
	using keyblock_t = block<__m128i>;

	static constexpr unsigned rounds = 128;     // Number of rounds
	static constexpr unsigned numofboxes = 1; // Number of Sboxes
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
		instantiate_LowMC();
		keyschedule();
	}

	auto encrypt (const block_t & message) const;
	auto encrypt_MPC (const block_t & message, const block_t blind[], const block_t gamma[], const bool P = 0) const;
  auto encrypt_MPC_proof(const block_t & m0, const block_t & m1, const block_t blind0[], const block_t blind1[], block_t gamma0[], block_t gamma1[], block_t encrypt_outL[], block_t encrypt_outR[]) const;
	auto encrypt_MPC_verify(const block_t & message, const block_t c2[], const block_t blind[], block_t gamma[], const bool P, block_t encrypt_out[]) const;

  //private:
	// LowMC private data members //
	std::vector<std::vector<block_t>> LinMatrices;
	// Stores the binary matrices for each round
	std::vector<std::vector<block_t>> invLinMatrices;
	// Stores the inverses of LinMatrices
	std::vector<block_t> roundkeysXORconstants;
	// Stores the round constants
	std::vector<std::vector<keyblock_t>> KeyMatrices;
	// Stores the matrices that generate the round keys

	// LowMC private functions //
	auto Substitution (const block_t & message) const;
	auto Substitution_MPC (const block_t & message, const block_t & message2, const block_t & blind, const block_t & gamma) const;
	void GenBlinds(block_t *blinds[2], block_t *gamma[2]);

	auto MultiplyWithGF2Matrix(const std::vector<block_t> & matrix, const block_t & message, const block_t & initial_value = 0) const;
	// For the linear layer
	auto MultiplyWithGF2Matrix_Key(const std::vector<keyblock_t> & matrix, const keyblock_t & k) const;
	// For generating the round keys

	void keyschedule();
	//Creates the round keys from the master key

	void instantiate_LowMC ();
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


	// Random bits functions //
	block_t getrandblock_t();
	keyblock_t getrandkeyblock_t();
	bool getrandbit();

};

#endif
