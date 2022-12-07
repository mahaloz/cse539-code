#define blocksize 256

typedef unsigned char byte_t;
typedef uint16_t leaf_t;
typedef __m256i node_t;
typedef LowMC<node_t> prgkey_t;
typedef block<node_t> block_t;