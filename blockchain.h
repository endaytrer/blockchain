#ifndef _BLOCKCHAIN_H
#define _BLOCKCHAIN_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <openssl/evp.h>
#include <pthread.h>

#define PK_SIZE 32 
#define SIGNATURE_SIZE 64
#define POW_LOT_SIZE 8
#define DIGEST_SIZE 32
#define PREFIX_ZEROS 16
#define MAX_TRIALS (1UL << (2 * PREFIX_ZEROS))

typedef struct __attribute__((packed)) {
    uint8_t sender[PK_SIZE];
    uint8_t recipient[PK_SIZE];
    uint64_t amount;
    uint32_t fee;
    uint32_t index;
    uint8_t signature[SIGNATURE_SIZE];
} Transaction;


#define BLOCK_HEADER_SIZE (sizeof(Block))
#define BLOCK_SIZE(block_p) (BLOCK_HEADER_SIZE + (block_p)->num_transactions * sizeof(Transaction))
#define BLOCK_TRANSACTIONS_P(block_p) ((Transaction *)((uint64_t)(block_p) + BLOCK_HEADER_SIZE))

/**
 * The following block only contains the header of a block, the following comprises a list of transactions;
 * to get transactions, use Transaction *BLOCK_TRANSACTIONS_P(Block *block)
*/
typedef struct {
    uint32_t index;
    uint32_t num_transactions;
    double timestamp;
    uint8_t proof[POW_LOT_SIZE];
    uint8_t previous_hash[DIGEST_SIZE];
} Block;

typedef struct chain_node_t {
    struct chain_node_t *prev;
    const Block block;
} ChainNode;


typedef struct {
    ChainNode *head;
    uint8_t last_hash[DIGEST_SIZE];
    pthread_mutex_t mutex;
} BlockChain;
// We test many bytes to be zero, so PREFIX_ZEROS should be divisible by 8.
_Static_assert((PREFIX_ZEROS & 0x7) == 0, "PREFIX_ZEROS should be divisible by 8");

bool Transaction_verify(const Transaction *t);

Block *Block_new(uint32_t num_transactions);
void Block_delete(Block *b);
void Block_init(Block *b, uint32_t index, double timestamp);
int Block_prove_of_work_trial(Block *b, const uint8_t *proof, uint8_t *digest);
// also support proof_start for parallel computing
int Block_mine(Block *b, size_t max_trials, const uint8_t *proof_start, uint8_t *digest);

BlockChain *BlockChain_new(void);
void BlockChain_delete(BlockChain *c);

// NO THREAD SAFETY, make sure to call it only in initialization.
int BlockChain_init(BlockChain *c, bool genesis);
void BlockChain_add_block(BlockChain *c, const Block *block);

/**
 * If invalid, return -1;
 * Else, return the length of block chain
*/
ssize_t BlockChain_verify(BlockChain *c);
extern EVP_MD_CTX *ctx;
extern EVP_MD *sha256;
#endif // _BLOCKCHAIN_H
