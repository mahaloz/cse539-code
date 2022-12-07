

#include <type_traits>
#include <set>
#include <vector>
#include <fstream> 
 //#include <x86intrin.h>  // SSE and AVX intrinsics
#define blocklen 128
#include "dpf.h"
#include <iostream>
#include <assert.h>
#include <chrono> 

using namespace std::chrono; 

typedef uint32_t leaf_t;
typedef __m128i node_t;
typedef LowMC<node_t> prgkey_t;
typedef block<node_t> block_t;
typedef  block<__m128i> keyblock_t;
  
  static constexpr unsigned rounds = 128;     // Number of rounds
  static constexpr unsigned numofboxes = 2; // Number of Sboxes
  static constexpr unsigned blocksize = CHAR_BIT * sizeof(__m128i); // Block size in bits
  static constexpr unsigned keysize = 128 ;    // Key size in bits

unsigned rank_of_Matrix (const std::vector<block_t> & matrix) {
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


unsigned rank_of_Matrix_Key (const std::vector<keyblock_t> & matrix) {
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

bool getrandbit()
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

block_t getrandblock_t () {
    block_t tmp = 0;
    for (unsigned i = 0; i < blocksize; ++i)
    {
     tmp[i] = getrandbit ();
     }
    return tmp;
}

  auto transpose_Matrix (const std::vector<block_t> & matrix)
  {
      std::vector<block_t> transposemat(blocksize, 0); //To hold the inverted matrix
      for(size_t i = 0; i < blocklen; ++i)
      {
        for(size_t j = 0; j < blocklen; ++j)
        {
          transposemat[j].bits[i] = matrix[i].bits[j];
        }
      }

    return transposemat;
  }

int main(int argc, char * argv[])
{

  std::vector<std::vector<block_t>> LinMatrices;
  
  std::vector<std::vector<block_t>> transposeLinMatrices;

  // Stores the binary matrices for each round 
  std::vector<std::vector<block_t>> invLinMatrices;
  // Stores the inverses of LinMatrices
  std::vector<block_t> roundkeysXORconstants;
  // Stores the round constants
  

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
        //invLinMatrices.push_back(invert_Matrix (LinMatrices.back()));
        transposeLinMatrices.push_back(transpose_Matrix (LinMatrices.back()));
    }


    std::ofstream LowMC_constants;
    LowMC_constants.open("roundconstants.h");

    size_t len = (sizeof(block_t) * 128) /sizeof(uint64_t);
    
    LowMC_constants << "uint64_t lin_mat[" << rounds << "][" << len << "] = {" << std::endl;
    for(size_t r = 0; r < rounds; ++r)
    {
        uint64_t * lin_mat   =  reinterpret_cast<uint64_t *> (LinMatrices[r].data());
       // std::cout << "----||> " <<  (uint64_t)transposeLinMatrices[r][0].mX[0] << " " << (uint64_t)transposeLinMatrices[r][0].mX[1] << std::endl;
        
       //  std::cout << "----||> " << transpose[0] << " " << transpose[1] << std::endl << std::endl;
        if (LowMC_constants.is_open())
        {    
            LowMC_constants << "{";  
            for(size_t j = 0; j < len; ++j)
            {
                LowMC_constants << lin_mat[j] << "ULL"; 
                if(j < len - 1) LowMC_constants << ", ";
            }

            LowMC_constants << "}";
            if(r < rounds-1) LowMC_constants << ", " << std::endl;
        }
        else
        {
            std::cerr << "unable to open file " << std::endl;
        }
    }
    LowMC_constants << "};" << std::endl;

 
    LowMC_constants << "uint64_t transpose_mat[" << rounds << "][" << len << "] = {" << std::endl;
    for(size_t r = 0; r < rounds; ++r)
    {
        uint64_t * transpose   =  reinterpret_cast<uint64_t *> (transposeLinMatrices[r].data());
       // std::cout << "----||> " <<  (uint64_t)transposeLinMatrices[r][0].mX[0] << " " << (uint64_t)transposeLinMatrices[r][0].mX[1] << std::endl;
        
       //  std::cout << "----||> " << transpose[0] << " " << transpose[1] << std::endl << std::endl;
        if (LowMC_constants.is_open())
        {    
            LowMC_constants << "{";  
            for(size_t j = 0; j < len; ++j)
            {
                LowMC_constants << transpose[j] << "ULL"; 
                if(j < len - 1) LowMC_constants << ", ";
            }

            LowMC_constants << "}";
            if(r < rounds-1) LowMC_constants << ", " << std::endl;
        }
        else
        {
            std::cerr << "unable to open file " << std::endl;
        }
    }
    LowMC_constants << "};" << std::endl;

    // Create roundconstants
    roundkeysXORconstants.clear();
    roundkeysXORconstants.push_back(0);

    len = (rounds + 1) * (sizeof(block_t))/sizeof(uint64_t);// 258;

    for (unsigned r = 0; r < rounds; ++r)
    {
        roundkeysXORconstants.push_back( getrandblock_t () );
    } 

    uint64_t * roundkeysconstants = reinterpret_cast<uint64_t *> (roundkeysXORconstants.data());

   
   LowMC_constants << " uint64_t __roundkeysXORconstants_[" << len << "] = {";
   
   // for (int i = 0; i <= rounds; ++i)
   // {
   //    std::cout << "--> " << i << ": roundkeysXORconstants: " << (uint64_t)roundkeysXORconstants[i].mX[0] << " " << (uint64_t)roundkeysXORconstants[i].mX[1] << std::endl;
   //    std::cout << "--> " << i << ": roundkeysXORconstants: " << roundkeysconstants[2*i] << " " << roundkeysconstants[2*i + 1] << std::endl << std::endl;
   //     /* code */
   // }

   for(size_t j = 0; j < len; ++j)
    {
      LowMC_constants << roundkeysconstants[j] << "ULL" ;
      if(j < len - 1) LowMC_constants << ", ";

      // std::cout << "--->:::  " << roundkeysconstants[j] <<  std::endl; 
      // std::cout << "--->:::  " << roundkeysXORconstants[1].mX[j]  << std::endl << std::endl;
    }
     
     LowMC_constants << "};" << std::endl <<  " block_t * roundkeysXORconstants_ = reinterpret_cast<block_t*>(__roundkeysXORconstants_);" << std::endl;
    
 
 
  LowMC_constants.close();

  //  prgkey_t key;
  //  auto start_sim = std::chrono::high_resolution_clock::now();
   
  //  key.instantiate_LowMC_();
   
  //  auto finish_sim = std::chrono::high_resolution_clock::now();
  //  std::chrono::duration<double, std::milli> elapsed_sim = finish_sim - start_sim;
 
  // std::cout << "elapsed_sim = " << elapsed_sim.count() << std::endl;
 return 0;
}

 