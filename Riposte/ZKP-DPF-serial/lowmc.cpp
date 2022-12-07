#include <vector>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <algorithm>
#include <bsd/stdlib.h>

#include "lowmc.h"

template <typename __mX>
auto LowMC<__mX>::encrypt(const block_t & message) const   
{
     
	block_t c = message ^ roundkeysXORconstants[0];
	for (unsigned r = 1; r <= rounds; ++r)
	{  
		c =  Substitution(c);  
		c =  MultiplyWithGF2Matrix(LinMatrices[r-1], c, roundkeysXORconstants[r]);
	}
	return c;
}

template <typename __mX>
auto LowMC<__mX>::encrypt_MPC(const block_t & message, const block_t blind[], const block_t gamma[], const bool P) const
{
	block_t c = P ? message : message ^ roundkeysXORconstants[0];

	for (unsigned r = 1; r <= rounds; ++r)
	{
		block_t c2; // obtain from other party
		c = Substitution_MPC(c, c2, blind[r-1], gamma[r-1]);
		c = MultiplyWithGF2Matrix(LinMatrices[r-1], c);
	}
	return c;
}

template <typename __mX>
 auto LowMC<__mX>::encrypt_MPC_verify(const block_t & message, const block_t c2[], const block_t blind[], block_t gamma[], const bool P, block_t encrypt_out[]) const
{
	std::vector<block_t> c;
	c.reserve(rounds+1);

	block_t tmp = P ? message : message ^ roundkeysXORconstants[0];

	for (unsigned r = 1; r <= rounds; ++r)
	{
	//	c.emplace_back(tmp ^ blind[r-1]);
        encrypt_out[r-1] = (tmp ^ blind[r-1]) ;
		tmp = Substitution_MPC(tmp, c2[r-1], blind[r-1], gamma[r-1]);
		tmp = MultiplyWithGF2Matrix(LinMatrices[r-1], tmp, P ? 0 : roundkeysXORconstants[r]);
	}

    encrypt_out[rounds] = tmp;
	
    c.emplace_back(tmp);

	return std::move(c);
}


template <typename __mX>
auto LowMC<__mX>::encrypt_MPC_proof(
    const block_t & m0, const block_t & m1, const block_t blind0[], const block_t blind1[], block_t gamma0[], block_t gamma1[], block_t encrypt_outL[], block_t encrypt_outR[]) const
{
	std::vector<block_t> c0;
	c0.reserve(rounds+1);
	std::vector<block_t> c1;
	c1.reserve(rounds+1);

	block_t tmp0 = m0;
	block_t tmp1 = m1 ^ roundkeysXORconstants[0];

	for (unsigned r = 1; r <= rounds; ++r) 
	{

        encrypt_outL[r-1] = (tmp0 ^ blind0[r-1]);

        // std::cout << "tmp0        = " << tmp0.bits << std::endl;
        // std::cout << "blind0[r-1] = " << blind0[r-1].bits << std::endl;
        // std::cout << "tmp0'       = " << encrypt_outL[r-1].bits << std::endl << std::endl;
		
        c0.emplace_back(encrypt_outL[r-1]);
        
        encrypt_outR[r-1] = (tmp1 ^ blind1[r-1]);
        
        c1.emplace_back(encrypt_outR[r-1]);
    
    	tmp0 = Substitution_MPC(tmp0, c1[r-1], blind0[r-1], gamma0[r-1]);
    	tmp0 = MultiplyWithGF2Matrix(LinMatrices[r-1], tmp0, roundkeysXORconstants[r]);
		
    	tmp1 = Substitution_MPC(tmp1, c0[r-1], blind1[r-1], gamma1[r-1]);
		tmp1 = MultiplyWithGF2Matrix(LinMatrices[r-1], tmp1, 0);
	}

    encrypt_outL[rounds] = tmp0;
    encrypt_outR[rounds] = tmp1;

	c0.emplace_back(tmp0);
	c1.emplace_back(tmp1);

	return std::make_pair(std::move(c0), std::move(c1));
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
auto LowMC<__mX>::Substitution_MPC(const block_t & message, const block_t & message2, const block_t & blind, const block_t & gamma) const
{
	// const block_t srli1 = (message >> 1) & maskbc;
	// const block_t srli2 = (message >> 2) & maskc;

	// const block_t message3 = message ^ message2;
	// const block_t tmp = (message3 & srli1) ^ (blind & (message2 >> 1));
	// const block_t bc = (tmp << 2) & maska;
	// const block_t ac = ((message3 ^ (blind & (message2 >> 2))) & srli2) << 1;
	// const block_t ab = (tmp >> 1) & maskc;

	// return (bc | ac | ab) ^ message ^ srli1 ^ srli2 ^ gamma;

    const block_t srli1 = (message >> 1) & maskbc;
    const block_t srli2 = (message >> 2) & maskc;


    const block_t message3 = message ^ message2;
    const block_t tmp = (message3 & srli1) ^ (blind & (message2 >> 1));
    const block_t bc = (tmp << 2) & maska;
    const block_t ac = (((message3 & srli2) ^ (blind & (message2 >> 2))) << 1) & maskb;
    //const block ac = ((message3 ^ (blind & (message2 >> 2))) & srli2) << 1;
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
		gamma[1][r] = rand ^ roundkeysXORconstants[r+1];
	}
}

template <typename __mX>
auto LowMC<__mX>::MultiplyWithGF2Matrix(const std::vector<block_t> & matrix, const block_t & message, const block_t & initial_value) const
{
	block_t temp = initial_value;
    
    uint64_t bitset ;

    for (size_t k = 0; k < sizeof(block_t) / 8; ++k)
	{
		bitset = static_cast<__mX>(message)[k];
        while (bitset != 0)
		{
			uint64_t t = bitset & -bitset;
			int i = k * 64 + __builtin_ctzl(bitset);
			
            temp =  temp ^ matrix[i];
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
	// Create LinMatrices and invLinMatrices
	LinMatrices.clear();
	invLinMatrices.clear();
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
		invLinMatrices.push_back(invert_Matrix (LinMatrices.back()));
	}

	// Create roundconstants
	roundkeysXORconstants.clear();
	roundkeysXORconstants.push_back(0);
	for (unsigned r = 0; r < rounds; ++r)
	{
		roundkeysXORconstants.push_back( getrandblock_t () );
	}
	// Create KeyMatrices
	KeyMatrices.clear();
	for (unsigned r = 0; r <= rounds; ++r)
	{
		// Create matrix
		std::vector<keyblock_t> mat;
		// Fill matrix with random bits
		do
		{
			mat.clear();
			for (unsigned i = 0; i < blocksize; ++i)
			{
				mat.push_back( getrandkeyblock_t () );
		}
		// Repeat if matrix is not of maximal rank
		} while(rank_of_Matrix_Key(mat) < std::min(blocksize, keysize));
		KeyMatrices.push_back(mat);
	}
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



