#include <string.h>
#include <sys/time.h>
#include "node.h"


Node *Node_new(void) {
    return malloc(sizeof(Node));
}
void Node_delete(Node *m) {
    pthread_mutex_lock(&m->new_block_mutex);
    free(m);
}
void Node_init(Node *m, BlockChain *block_chain, const uint8_t *id) {
    m->block_chain = block_chain;
    if (id != NULL) {
        pthread_mutex_init(&m->new_block_mutex, NULL);
        memcpy((uint8_t *)m->id, id, sizeof(m->id));
    }

    struct timeval tv;
    gettimeofday(&tv, NULL);
    double timestamp = (double)tv.tv_sec + 1e-6 * (double)tv.tv_usec;
    pthread_mutex_lock(&m->new_block_mutex);
    pthread_mutex_lock(&block_chain->mutex);
    Block_init(&(m->new_block.hdr), block_chain->head ? (block_chain->head->block.index + 1) : 0, timestamp);
    memcpy(m->new_block.hdr.previous_hash, block_chain->last_hash, sizeof(m->new_block.hdr.previous_hash));
    pthread_mutex_unlock(&m->block_chain->mutex);
    Transaction block_reward = {
        .amount = 1,
        .sender = {0},
    };
    memcpy(block_reward.recipient, m->id, sizeof(block_reward.recipient));
    pthread_mutex_unlock(&m->new_block_mutex);
    // need to unlock before since adding transaction requires lock.
    Node_add_transaction(m, &block_reward);
}

int Node_add_transaction(Node *m, const Transaction *transaction) {
    pthread_mutex_lock(&m->new_block_mutex);
    if (m->new_block.hdr.num_transactions >= MAX_TRANSACTIONS) {
        pthread_mutex_unlock(&m->new_block_mutex);
        return -1;
    }
    m->new_block.transactions[m->new_block.hdr.num_transactions++] = *transaction;
    pthread_mutex_unlock(&m->new_block_mutex);
    return 0;
}

int Node_add_block(Node *m, const uint8_t *hash) {
    // copy block to heap
    pthread_mutex_lock(&m->new_block_mutex);
    size_t block_size = BLOCK_SIZE(&(m->new_block.hdr));
    Block *block = malloc(block_size);
    memcpy(block, &(m->new_block), block_size);
    BlockChain_add_block(m->block_chain, block);

    struct timeval tv;
    gettimeofday(&tv, NULL);
    double timestamp = (double)tv.tv_sec + 1e-6 * (double)tv.tv_usec;
    Block_init(&(m->new_block.hdr), block->index + 1, timestamp);

    memcpy(m->new_block.hdr.previous_hash, hash, sizeof(m->new_block.hdr.previous_hash));
    Transaction block_reward = {
        .amount = 1,
        .sender = {0},
    };
    memcpy(block_reward.recipient, m->id, sizeof(block_reward.recipient));
    // add reward, since the lock is not reentrant, release lock first that Node_add_transaction can have the lock.
    pthread_mutex_unlock(&m->new_block_mutex);
    Node_add_transaction(m, &block_reward);

    pthread_mutex_lock(&m->block_chain->mutex);
    memcpy(m->block_chain->last_hash, hash, sizeof(m->block_chain->last_hash));
    pthread_mutex_unlock(&m->block_chain->mutex);
    return 0;
}

int Node_mine(Node *m, size_t max_trials, const uint8_t *proof_start) {
    uint8_t digest[DIGEST_SIZE];
    if (Block_mine(&(m->new_block.hdr), max_trials, proof_start, digest)) {
        return -1;
    }
    if (Node_add_block(m, digest)) {
        return -1;
    }
    return 0;
}
