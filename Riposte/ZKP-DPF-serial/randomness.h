class MPCrandomness
{
  
  public:
  
    MPCrandomness(AES_KEY& aeskey, __m128i seed, size_t len) :
    buf((unsigned char *)malloc(len * sizeof(seed))),
    cur(buf)
    {
      PRG(aeskey, seed, (__m128i *)buf, len);
    } 
    ~MPCrandomness()
    {
    free(buf);
    }
  



  inline bool next(int & val)
  {
    memcpy(&val, cur, sizeof(int));
    val &= 1;
    cur += sizeof(int);
    bool val_b = val;

    //std::cout << "val_b = " << val_b << std::endl;

    return val_b;
  }

  inline bool next_bool()
  {
    int  val;
    memcpy(&val, cur, sizeof(int));
    val &= 1;
    cur += sizeof(int);
    bool val_b = val;

    //std::cout << "val_b = " << val_b << std::endl;

    return val_b;
  }

  template<typename T>
  inline T& next(T & val)
  {
    memcpy(&val, cur, sizeof(T));
    cur += sizeof(T);
    return val;
  }
  
  inline block_t next_block()
  {
    block_t val;
    memcpy(&val, cur, sizeof(block_t));
    cur += sizeof(block_t);
    return val;
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