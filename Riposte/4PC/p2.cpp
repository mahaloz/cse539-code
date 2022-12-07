#include <bsd/stdlib.h>
#include <cstdlib>
#include <iostream>
#include <utility>
#include <sys/mman.h>
#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>
 
 #include "network.h"
#include "aes.h"
#include "sanity.h"
#include "common.h"

__m128i seeds[2];

uint64_t dp0[nqueries], dp1[nqueries];

void send_sanity_seed_to_P0(tcp::socket& sout)
{
 
   boost::asio::write(sout, boost::asio::buffer(seeds, 2 * sizeof(__m128i)));
 
}


void send_sanity_seed_to_P1(tcp::socket& sout)
{
 
    boost::asio::write(sout, boost::asio::buffer(seeds, 2 * sizeof(__m128i)));
 
}

void read_dp_from_P0(tcp::socket& sout)
{
  for(size_t j = 0; j < nqueries; ++j)
  {
   boost::asio::read(sout, boost::asio::buffer(&dp0[j], sizeof(uint64_t)));
   //std::cout << "dp0 = " << dp0 << std::endl;
  }
}


void read_dp_from_P1(tcp::socket& sout)
{
  for(size_t j = 0; j < nqueries; ++j)
  {
    boost::asio::read(sout, boost::asio::buffer(&dp1[j], sizeof(uint64_t)));
    //std::cout << "dp1 = " << dp1 << std::endl;
  }
}

void verify_(const std::vector<uint64_t> & srt0, const std::vector<uint64_t> & inv1)
{
  size_t verified = 0;
  for(size_t j = 0; j < nqueries; ++j)
  {
   auto v = verify(dp0[j], dp1[j], srt0, inv1);
   if(v) ++verified;// std::cout << "true\n\n";
  }

  std::cout << "verified = " << verified << std::endl;
}

int main(int argc, char* argv[])
{ 

 using namespace dpf;

  AES_KEY prgkey;

  AES_set_encrypt_key(_mm_set_epi64x(597349, 121379), &prgkey);
  boost::asio::io_context io_context;


  tcp::acceptor acceptor1(io_context, tcp::endpoint(tcp::v4(), PORT_P1_P2));
  std::cout << " --- > " << std::endl;
  tcp::socket s1(acceptor1.accept());
  std::cerr << "Listenting on port: " << PORT_P1_P2 << std::endl;

  tcp::acceptor acceptor1_a(io_context, tcp::endpoint(tcp::v4(), PORT_P1_P2_a));
  std::cout << " --- > " << std::endl;
  tcp::socket s1_a(acceptor1_a.accept());
  std::cerr << "Listenting on port: " << PORT_P1_P2_a << std::endl;

  tcp::acceptor acceptor0(io_context, tcp::endpoint(tcp::v4(), PORT_P0_P2));
  std::cout << " --- > " << std::endl;
  tcp::socket s0(acceptor0.accept());
  std::cerr << "Listenting on port: " << PORT_P0_P2 << std::endl;
  
  tcp::acceptor acceptor0_a(io_context, tcp::endpoint(tcp::v4(), PORT_P0_P2_a));
  std::cout << " --- > " << std::endl;
  tcp::socket s0_a(acceptor0_a.accept());
  std::cerr << "Listenting on port: " << PORT_P0_P2_a << std::endl;  
    
  arc4random_buf(seeds, sizeof(seeds));
  
  auto [rnd0, rnd1] = gen_rands(prgkey, seeds, nitems);
  auto srt0 = sort(rnd0);
  auto inv1 = inverse(rnd1);

  send_sanity_seed_to_P0(s0);
  
  send_sanity_seed_to_P1(s1);

  read_dp_from_P0(s0_a);

  read_dp_from_P1(s1_a);
 
  verify_(srt0, inv1);
 

  
 

  return 0;
}