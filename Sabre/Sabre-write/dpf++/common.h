
const size_t nitems =  1ULL << 16; 
constexpr size_t rounds = ROUNDS;
constexpr size_t sboxes = SBOXES;
constexpr size_t blocklen = BLOCK_LEN;
constexpr size_t ndpfs = NDPFS;

const size_t ncores = 16;
uint64_t progress[ncores] = {0};
