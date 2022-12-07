class MPCrandomness
{
  
  public: 
    size_t amt = 0;
    MPCrandomness(const randomness_prgkey_t & key, blockT seed, size_t len) :
    buf((unsigned char *)malloc(len * sizeof(blockT))),
    cur(buf)
    {
     // PRG_array_aes(aeskey, seed, (__m128i *)buf, len, 0);
      PRG_parallel(key, seed, (__m128i *)buf, len, 0);
    } 
    ~MPCrandomness()
    {
    free(buf);
    }
  



  inline bool next_bool()
  {
    int val;
    memcpy(&val, cur, sizeof(int));
    
    val &= 1;
    cur += sizeof(int);

    bool val_b = val;
 
    return val_b;
  }

  inline __m128i next_node_blind()
  {
    __m128i  val;
    
    memcpy(&val, cur, sizeof(__m128i));
    cur += sizeof(__m128i);
    amt+=sizeof(__m128i);
    __m128i val_b = val;
 
    return val_b;
  }

   inline uint64_t next_node_blind_64(const uint64_t challenge[])
  {
    __m128i  val;
    
    memcpy(&val, cur, sizeof(__m128i));
    cur += sizeof(__m128i);
    __m128i val_b = val;

    return __m128i_to_uint64_t(val_b, challenge);
  }
  
  inline blockT next_block()
  {
    blockT val;
    memcpy(&val, cur, sizeof(blockT));
    cur += sizeof(blockT);
    amt+=sizeof(blockT);
 
    return val;
  }

  inline block64_T next_block_64(const uint64_t challenge[])
  {
    blockT val;
    memcpy(&val, cur, sizeof(blockT));
    cur += sizeof(blockT);
    return blockT_to_block64_T(val, challenge);
  }

    inline blindT next_blind()
  {
    blindT val;
    memcpy(&val, cur, sizeof(blindT));
    cur += sizeof(blindT);
    amt+=sizeof(blindT);
 
    return val;
  }

  inline blind64_T next_blind_64(const uint64_t challenge[2])
  {
    blindT val;
    memcpy(&val, cur, sizeof(blindT));
    cur += sizeof(blindT);
    return blindT_to_blind64_T(val, challenge);
  }

  template<typename T>
  inline T && next()
  {
    T val;
    memcpy(&val, cur, sizeof(T));
    cur += sizeof(T);
    return val;
  }


  private:
  unsigned char * buf;
  unsigned char * cur;
};