#ifndef _NODE_H
#define _NODE_H

#include "blockchain.h"
#define MAX_TRANSACTIONS 64

typedef struct {
    BlockChain *block_chain; // use pointer to allow multiple
    const uint8_t id[WALLET_ID_SIZE];
    pthread_mutex_t new_block_mutex;
    __attribute__((packed)) struct { // use packed to ensure transactions is follow compactly after header
        Block hdr; // embed num_transaction into block header.
        Transaction transactions[MAX_TRANSACTIONS];
    } new_block;
} Node;

Node *Node_new(void);
void Node_delete(Node *m);
// if id is set, it works like initialization
// else, it changes the blockchain in m.
void Node_init(Node *m, BlockChain *block_chain, const uint8_t *id);

int Node_add_transaction(Node *m, const Transaction *transaction);

// No validation of whether hash is valid.
int Node_mine(Node *m, size_t max_trials, const uint8_t *proof_start);
int Node_add_block(Node *m, const uint8_t *hash);
#endif // _NODE_H
