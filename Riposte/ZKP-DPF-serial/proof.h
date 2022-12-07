struct Proof_leaves_P2
 {
   byte_t PB_hash[picosha2::k_digest_size];
 }; 

struct Proof_leaves_PB
{
   PB_transcript PB_view;
   P2_transcript P2_view;
   byte_t P2_hash[picosha2::k_digest_size];
}; 

struct Proof
{
  byte_t root[picosha2::k_digest_size];
};
    