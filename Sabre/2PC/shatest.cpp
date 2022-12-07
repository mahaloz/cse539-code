#include <cstdio>
#include <cstdlib>
#include <chrono>
#include<iostream>

#include <openssl/sha.h>

int main(int argc, char * argv[])
{
  constexpr size_t len = 36 * (1ULL << 10);
  uint8_t ** buf = (uint8_t**)malloc(128 * sizeof(uint8_t*));
  for (int i  = 0; i < 128; ++i) buf[i] = (uint8_t*)malloc(len);

  unsigned char hash[4][128][32];



  for(size_t j = 0; j < 128; ++j)
  {
     auto start_gen1 = std::chrono::high_resolution_clock::now();
     
     SHA256_CTX sha256_0;
     SHA256_Init(&sha256_0);   
     
     SHA256_CTX sha256_1;
     SHA256_Init(&sha256_1); 

     // const char * view0T_char = reinterpret_cast<const char* >(&view0T[j]);
     // const char * view1T_char = reinterpret_cast<const char* >(&view1T[j]);
     if(!SHA256_Update(&sha256_0, reinterpret_cast<const char* >(buf[j]), len)){ /*gah!*/ } 
     SHA256_Final(hash[0][j], &sha256_0);
     if(!SHA256_Update(&sha256_1, reinterpret_cast<const char* >(buf[j]), len)){ /*gah!*/ }
     SHA256_Final(hash[1][j], &sha256_1);
    
     auto finish_gen1 = std::chrono::high_resolution_clock::now();  
     std::chrono::duration<double, std::milli> elapsed_gen1 = finish_gen1 - start_gen1;
     std::cout << "len = " << len << std::endl;
     std::cout << "elapsed_gen1 = " << elapsed_gen1.count() << std::endl; 

     SHA256_CTX sha256_P0;
     SHA256_Init(&sha256_P0);

     SHA256_CTX sha256_P1;
     SHA256_Init(&sha256_P1);  
     char * P2_P0_viewT_char = reinterpret_cast<char* >(buf[j]);
     char * P2_P1_viewT_char = reinterpret_cast<char* >(buf[j]); 

     SHA256_Update(&sha256_P0, buf[j], len);
     SHA256_Update(&sha256_P1, buf[j], len); 
   
     SHA256_Final(hash[2][j], &sha256_P0);
     SHA256_Final(hash[3][j], &sha256_P1);

printf("%x,%x,%x,%x\n",hash[0][j][0], hash[1][j][0], hash[2][j][0], hash[3][j][0]);
  }
	return 0;
}
