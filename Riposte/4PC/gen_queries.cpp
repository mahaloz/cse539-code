#include <unistd.h>
#include <fcntl.h>
#include <iostream>
#include <tuple>
#include <vector>
#include <fstream>
#include "common.h"
#include "aes.h"
#include "dpf++/dpf.h"

using namespace dpf;

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

int main(int argc, char ** argv)
{

  AES_KEY prgkey;
  AES_set_encrypt_key(_mm_set_epi64x(597349, 121379), &prgkey);

  // const size_t nitems = 1ULL << 10;
  // const size_t nqueries = 1ULL << 20; 
 
  ssize_t bytes;
  int fd = open("./queries", O_RDONLY);
  
  size_t * q = new size_t[2 * nqueries];
  bytes = read(fd, q, 2 * nqueries * sizeof(size_t));
  close(fd);

  // query * q0 = new query<nitems>[nqueries];
  // query * q1 = new query<nitems>[nqueries];
 std::vector<query> q0;
 std::vector<query> q1;
 q0.reserve(nqueries);
 q1.reserve(nqueries);

 std::fstream fout0("./queries.0", std::fstream::out);
 std::fstream fout1("./queries.1", std::fstream::out);
  for (size_t i = 0; i < nqueries; ++i)
  {
    size_t target = 10; 
    auto [dpfkey0, dpfkey1] = dpf_key<bool >::gen(prgkey, nitems, target);

    fout0 << query(q[i], std::move(dpfkey0));

    fout1 << query(q[i], std::move(dpfkey1));

  }

 
  
 

  return 0;
}