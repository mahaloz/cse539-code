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
#include "network.h"
#include "common.h"
 
#include <chrono>
#include <ctime>

using boost::asio::ip::tcp;
using namespace std::chrono;

using namespace dpf;

enum sanity_step
{
   seed_in,
   query_in,
   shifts_in,
   dp_gen,
   dp_out, 
   num_steps,
};

size_t progress[sanity_step::num_steps] = {0};


struct query {
  const size_t user;
  const dpf_key<> dpfkey;
  query(size_t u, dpf_key<> && k) : user(u), dpfkey(k) { }
  static inline query create(const AES_KEY & prgkey, std::istream & is)
  {
    size_t u; is >> u;
    return query(u, dpf_key<>::deserialize(prgkey, is));
  }
};
inline std::ostream & operator<<(std::ostream & os, const query & q) { return os << q.user << q.dpfkey; }
__m128i seeds[2];
uint64_t shift[nqueries][2];
uint64_t dp0[nqueries];

std::vector<query> queries;
std::vector<__m256i> rnd0_[4];
std::vector<__m256i> rnd1_[4];

 void keep_polling(boost::asio::io_context& io_context)
 {
      while(progress[sanity_step::dp_out] < nqueries)
      {
        io_context.reset();
        io_context.poll();
      }
 }

void read_seed_from_P2(AES_KEY& prgkey, tcp::socket& sin)
{
  boost::asio::read(sin, boost::asio::buffer(seeds, 2 * sizeof(__m128i)));
  auto [rnd0, rnd1] = gen_rands(prgkey, seeds, nitems);
  rnd0_[0] = rnd0; rnd0_[1] = rot(rnd0,1); rnd0_[2] = rot(rnd0,2); rnd0_[3] = rot(rnd0,3);
  rnd1_[0] = rnd1; rnd1_[1] = rot(rnd1,1); rnd1_[2] = rot(rnd1,2); rnd1_[3] = rot(rnd1,3); 

  progress[sanity_step::seed_in] = 1;
}
 
void write_dp_to_P2(size_t j, boost::asio::io_context& io_context, tcp::socket& sout)
{
  // for(size_t j = 0; j < nqueries; ++j)
  // {
  //  boost::asio::write(sout, boost::asio::buffer(&dp0[j], sizeof(uint64_t)));
  // }

    while(progress[sanity_step::dp_gen] < j + 1)
    {
      std::this_thread::yield();
    }

   async_write(sout, boost::asio::buffer(&dp0[j], sizeof(uint64_t)),
    [j, &io_context, &sout](boost::system::error_code ec, std::size_t) 
    
    { 
        if(!ec)
        {
           if(j + 1 < nqueries){ 
            write_dp_to_P2(j + 1, io_context, sout);
          }
        }          
        else
        {
          write_dp_to_P2(j , io_context, sout);
        }
    
    }); 

   progress[sanity_step::dp_out] = j + 1;
}

void read_shifts(tcp::socket& sin)
{
  for(size_t j = 0; j < nqueries; ++j)
  {
    boost::asio::read(sin, boost::asio::buffer(shift[j], 2 * sizeof(uint64_t)));
    progress[sanity_step::shifts_in] = j + 1;
  }
}

 void generate_dotproducts()
{ 
    
    uint8_t * q0 = reinterpret_cast<uint8_t*>(std::aligned_alloc(alignof(__m128i), nitems/8)); 
    uint8_t * t  = reinterpret_cast<uint8_t*>(std::aligned_alloc(alignof(__m128i), nitems));
    
    for(size_t j = 0; j < nqueries; ++j)
    { 
      while(progress[sanity_step::seed_in] < 1 || progress[sanity_step::query_in] < nqueries || progress[sanity_step::shifts_in] < j + 1)
      {
       std::this_thread::yield();
      }
      queries[j].dpfkey.evalfull(reinterpret_cast<bool*>(q0), t);
      dp0[j] = dot_prod(rnd0_, shift[j][0], rnd1_, shift[j][1], q0);

      progress[sanity_step::dp_gen] = j + 1;
    }
}


void read_queries(AES_KEY& prgkey)
{    
  std::string qfile = std::string("./queries.") + std::to_string(PARTY);
  std::fstream fin(qfile, std::fstream::in); 
  for(size_t j = 0; j < nqueries; ++j)
  {
    auto q = query::create(prgkey, fin);
    queries.emplace_back(std::move(q));

    progress[sanity_step::query_in] = j + 1;
  }
}

int main(int argc, char * argv[])
{ 
  AES_KEY prgkey;
  AES_set_encrypt_key(_mm_set_epi64x(597349, 121379), &prgkey);

  try
  {
    const std::string host1 = (argc < 2) ? "127.0.0.1" : argv[1];
    const std::string host2 = (argc < 3) ? "127.0.0.1" : argv[2];
    const std::string host3 = (argc < 4) ? "127.0.0.1" : argv[3];

    #include "connections.h"
     

    std::thread poller(keep_polling, std::ref(io_context));
    
    std::thread seed_reader(read_seed_from_P2, std::ref(prgkey), std::ref(s2));
  
    std::thread query_reader(read_queries, std::ref(prgkey)); 
    
    std::thread shift_reader(read_shifts, std::ref(s3));
   
    std::thread dotprod_generator(generate_dotproducts);
    
    std::thread dp_writer(write_dp_to_P2, 0, std::ref(io_context), std::ref(s2_a));


    poller.join();
    
    seed_reader.join();

    query_reader.join();
    
    shift_reader.join();
    
    dotprod_generator.join();
    
    dp_writer.join();
  }

  catch (std::exception & e)
  {
    std::cerr << "Exception: " << e.what() << "\n";
  }

  

  return 0;
}