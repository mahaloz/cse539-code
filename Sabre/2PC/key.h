#include <bitset>
#include <vector>
#include <string>
#include<iostream>
#include <x86intrin.h>

static constexpr unsigned numofboxes = 63; // Number of Sboxes
static constexpr unsigned blocksize = 256; // Block size in bits
static constexpr unsigned keysize = 128; // Key size in bits
static constexpr unsigned rounds = 14; // Number of rounds
static constexpr unsigned identitysize = blocksize - 3*numofboxes;
                  // Size of the identity part in the Sbox layer

//typedef std::bitset<blocksize> block; // Store messages and states

union keyblock
{
    __m256i a;
    std::bitset<keysize> b;
    // keyblock() { }
    // keyblock(long input) 
    // {
    //  b = input;
    // }

   keyblock(unsigned long long input = 0ULL) : b(input) { } 
   inline operator __m256i() const { return a; }
   inline keyblock & operator=(const __m256i val) { a = val; return *this; }

 public:

    //  bool operator[] (size_t idx)
    // {
    //  return b[idx];
    // }
    std::bitset<keysize>::reference operator[](size_t pos) { return b[pos]; }

    const bool operator[] (const size_t idx) const
    {
    return b[idx];
    }

    long to_ulong()
    {
        return b.to_ulong();
    }

    size_t count()
    {
        return b.count();
    }

    size_t size()
    {
        return b.size();
    }

};


inline keyblock operator & (const keyblock& a1, const keyblock & a2)
{
  keyblock result;
  result.b = a1.b & a2.b;

  return result;
}


inline keyblock operator^(const keyblock& a1, const keyblock & a2)
{
  keyblock result;
  result.b = a1.b ^ a2.b;
  return result;
}

inline keyblock & operator^=(keyblock & result, const keyblock& a2)
{
  result.b ^= a2.b;
  return result;
}


inline keyblock operator<<(const keyblock& a1, const long & a2)
{
  keyblock result;
  result.b = a1.b << a2;
  return result;
}

inline keyblock operator>>(const keyblock& a1, const long & a2)
{
  keyblock result;
  result.b = a1.b >> a2;
  return result;
}

inline keyblock & operator>>=(keyblock & result, const long & a2)
{
  result.b >>= a2;
  return result;
}

inline keyblock & operator<<=(keyblock & result, const long & a2)
{
  result.b <<= a2;
  return result;
}
inline std::ostream &  operator<<(std::ostream &out, keyblock & result)
{
    out << result.b;

    return out;
}

 
