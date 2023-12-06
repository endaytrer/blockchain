#include <string.h>
#include <sys/time.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <assert.h>
#include "node.h"


Node *Node_new(void) {
    return malloc(sizeof(Node));
}
void Node_delete(Node *m) {
    pthread_mutex_lock(&m->new_block_mutex);
    free(m);
}

void Node_set_key(Node *m, const char *private_key_filename) {

    FILE *sk_file = fopen(private_key_filename, "r");
    
    if (!sk_file) {
        fprintf(stderr, "Unable to open file\n");
        exit(-1);
    }

    EVP_PKEY *private_key = PEM_read_PrivateKey(sk_file, NULL, NULL, NULL);
    if (!private_key || EVP_PKEY_get_id(private_key) != NID_ED25519) {
        fprintf(stderr, "Invalid key format\n");
        exit(-1);
    }
    size_t len = PK_SIZE;
    EVP_PKEY_get_raw_public_key(private_key, (uint8_t *)m->id, &len);
    EVP_PKEY_print_private_fp(stdout, private_key, 0, NULL);
    m->pkey = private_key;

    fclose(sk_file);

}

void Node_init(Node *m, BlockChain *block_chain, const char *key) {
    m->block_chain = block_chain;

    if (key != NULL) {
        pthread_mutex_init(&m->new_block_mutex, NULL);
        Node_set_key(m, key);
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

ssize_t Node_add_transaction(Node *m, const Transaction *transaction) {
    pthread_mutex_lock(&m->new_block_mutex);
    if (m->new_block.hdr.num_transactions >= MAX_TRANSACTIONS) {
        pthread_mutex_unlock(&m->new_block_mutex);
        return -1;
    }
    ssize_t tid = m->new_block.hdr.num_transactions;
    m->new_block.transactions[m->new_block.hdr.num_transactions++] = *transaction;
    m->new_block.transactions[tid].index = MAX_TRANSACTIONS * m->new_block.hdr.index + tid;
    memset(m->new_block.transactions[tid].signature, 0, SIGNATURE_SIZE);
    pthread_mutex_unlock(&m->new_block_mutex);
    return MAX_TRANSACTIONS * m->new_block.hdr.index + tid;
}

int Node_set_signature(Node *m, uint32_t id, const uint8_t *signature) {
    pthread_mutex_lock(&m->new_block_mutex);
    uint8_t prev_signature[SIGNATURE_SIZE];
    memcpy(prev_signature, m->new_block.transactions[id - MAX_TRANSACTIONS * m->new_block.hdr.index].signature, SIGNATURE_SIZE);
    memcpy(m->new_block.transactions[id - MAX_TRANSACTIONS * m->new_block.hdr.index].signature, signature, SIGNATURE_SIZE);
    if (!Transaction_verify(&m->new_block.transactions[id - MAX_TRANSACTIONS * m->new_block.hdr.index])) {
        memcpy(m->new_block.transactions[id - MAX_TRANSACTIONS * m->new_block.hdr.index].signature, prev_signature, SIGNATURE_SIZE);
        pthread_mutex_unlock(&m->new_block_mutex);
        return -1;
    }
    pthread_mutex_unlock(&m->new_block_mutex);
    return 0;
}

void Node_sign(const Node *m, Transaction *transaction) {
    EVP_PKEY *pkey = m->pkey;

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!EVP_DigestSignInit_ex(md_ctx, NULL, NULL, NULL, NULL, pkey, NULL)) {
        fprintf(stderr, "cannot init\n");
    }
    size_t len = SIGNATURE_SIZE;
    if (!EVP_DigestSign(md_ctx, (uint8_t *)transaction->signature, &len, (const uint8_t *)transaction, sizeof(Transaction) - SIGNATURE_SIZE)) {
        fprintf(stderr, "cannot sign\n");
    }

    EVP_MD_CTX_free(md_ctx);

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
