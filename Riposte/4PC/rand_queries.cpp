#include <bsd/stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include "common.h"
using namespace std;

int main(int argc, char ** argv)
{
    size_t * queries = new size_t[2 * nqueries];
 
  for (size_t i = 0; i < nqueries; ++i)
  {
    queries[2*i]   =  arc4random_uniform(nusers);  //rand() % nusers; 
    queries[2*i+1] =  arc4random_uniform(nitems);  //rand() % nitems;   
    std::cout << queries[2*i] << " " <<  queries[2*i+1] << std::endl;
  }

  ssize_t bytes;
  int fd = open("./queries", O_RDWR, O_CREAT);
  //bytes = write(fd, &nqueries, sizeof(size_t));  
  bytes = write(fd, queries, 2 * nqueries * sizeof(uint64_t));
  close(fd);

  delete [] queries;

  return 0;
}
