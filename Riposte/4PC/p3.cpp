#include <thread>
#include <iostream>
#include <chrono>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <fstream>
#include <numeric>
#include<set>
#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>
 #include "aes.h"
#include "sanity.h"
#include "common.h"

#include "network.h"
 
uint64_t shift[nqueries][2];
enum sanity_step
{
   shift0_out,
   shift1_out,
   num_steps,
};

size_t progress[sanity_step::num_steps] = {0};

 void keep_polling(boost::asio::io_context& io_context)
 {
      while(progress[sanity_step::shift0_out] < nqueries || progress[sanity_step::shift1_out] < nqueries)
      {
        io_context.reset();
        io_context.poll();
      }
 }


void write_shits_to_P0(size_t j, boost::asio::io_context& io_context, tcp::socket& sout)
{
 
  async_write(sout, boost::asio::buffer(shift[j],  2* sizeof(uint64_t)),
    [j, &io_context, &sout](boost::system::error_code ec, std::size_t) 
    
    { 
        if(!ec)
        {
           if(j + 1 < nqueries){ 
            write_shits_to_P0(j + 1, io_context, sout);
          }
        }          
        else
        {
          write_shits_to_P0(j , io_context, sout);
        }
    
    }); 

 
    progress[sanity_step::shift0_out] = j + 1; 
}

void write_shits_to_P1(size_t j, boost::asio::io_context& io_context, tcp::socket& sout)
{
 
  async_write(sout, boost::asio::buffer(shift[j],  2* sizeof(uint64_t)),
    [j, &io_context, &sout](boost::system::error_code ec, std::size_t) 
    
    { 
        if(!ec)
        {
           if(j + 1 < nqueries){ 
            write_shits_to_P1(j + 1, io_context, sout);
          }
        }          
        else
        {
          write_shits_to_P1(j , io_context, sout);
        }
    
    }); 

 
    progress[sanity_step::shift1_out] = j + 1; 
}


int main(int argc, char* argv[])
{ 

  using namespace dpf;
  
  try
  {
    AES_KEY aeskey;
    AES_set_encrypt_key(_mm_set_epi64x(597349, 121379), &aeskey);
    boost::asio::io_context io_context;
      

    tcp::acceptor acceptor1(io_context, tcp::endpoint(tcp::v4(), PORT_P1_P3));
    std::cout << " --- > " << std::endl;
    tcp::socket s1(acceptor1.accept());
    std::cerr << "Listenting on port: " << PORT_P1_P3 << std::endl;

    tcp::acceptor acceptor0(io_context, tcp::endpoint(tcp::v4(), PORT_P0_P3));
    std::cout << " --- > " << std::endl;
    tcp::socket s0(acceptor0.accept());
    std::cerr << "Listenting on port: " << PORT_P0_P3 << std::endl;

    size_t len0 = pad_to_multiple(std::ceil(std::sqrt(nitems)), sizeof(__m256i)/sizeof(uint64_t));
    size_t len1 = pad_to_multiple(std::ceil(double(nitems) / len0), sizeof(__m256i)/sizeof(uint64_t));

    for(size_t j = 0; j < nqueries; ++j)
    {
     arc4random_buf(shift[j], 2 * sizeof(uint64_t));
     shift[j][0] = shift[j][0] % len0;
     shift[j][1] = shift[j][1] % len1;
    }

    std::thread poller(keep_polling, std::ref(io_context));

    std::thread shifts_to_P0_writer(write_shits_to_P0, 0, std::ref(io_context), std::ref(s0));

    std::thread shifts_to_P1_writer(write_shits_to_P1, 0, std::ref(io_context), std::ref(s1));

    poller.join();
    
    shifts_to_P0_writer.join();
    
    shifts_to_P1_writer.join();
  }
  catch (std::exception & e)
  {
    std::cerr << "Exception: " << e.what() << std::endl;
  }

  return 0;
}
