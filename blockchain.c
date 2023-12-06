#include <openssl/evp.h>
#include <sys/time.h>
#include <stdio.h>
#include <string.h>
#include "blockchain.h"

bool Transaction_verify(const Transaction *t) {
    // assume block reward has been filtered out.
    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, t->sender, PK_SIZE);

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!EVP_DigestVerifyInit_ex(md_ctx, NULL, NULL, NULL, NULL, pkey, NULL)) {
        fprintf(stderr, "cannot init\n");
    }
    int ans = EVP_DigestVerify(md_ctx, (const uint8_t *)t->signature, SIGNATURE_SIZE, (const uint8_t *)t, sizeof(Transaction) - SIGNATURE_SIZE);

    EVP_MD_CTX_free(md_ctx);
    return (bool)ans;
}

void Block_sha256_hash(const Block *b, uint8_t *dst) {

    if (!EVP_DigestInit_ex(ctx, sha256, NULL)) {
        fprintf(stderr, "EVP_DigestInit_ex()");
        exit(1);
    }
    if (!EVP_DigestUpdate(ctx, b, BLOCK_SIZE(b))) {
        fprintf(stderr, "EVP_DigestUpdate()");
        exit(1);
    }
    unsigned int len = 0;
    if (!EVP_DigestFinal_ex(ctx, (unsigned char *)dst, &len)) {
        fprintf(stderr, "EVP_DigestFinal_ex()");
        exit(1);
    }
}

Block *Block_new(uint32_t num_transactions) {
    Block *ans = malloc(BLOCK_HEADER_SIZE + num_transactions * sizeof(Transaction));
    ans->num_transactions = num_transactions;
    return ans;
}
void Block_delete(Block *b) {
    free(b);
}
void Block_init(Block *b, uint32_t index, double timestamp) {
    b->index = index;
    b->timestamp = timestamp;
    b->num_transactions = 0;
    memset(b->proof, 0, sizeof(b->proof));
    memset(b->previous_hash, 0, sizeof(b->previous_hash));
}


int Block_prove_of_work_trial(Block* b, const uint8_t* proof, uint8_t* digest) {
    memcpy(b->proof, proof, sizeof(b->proof));
    Block_sha256_hash(b, digest);
    for (int i = 0; i < (PREFIX_ZEROS >> 3); i++)
        if (digest[i] != 0) return -1;
    return 0;
}

int Block_mine(Block *b, size_t max_trials, const uint8_t *proof_start, uint8_t *digest) {
    uint8_t proof[POW_LOT_SIZE];
    if (proof_start != NULL) {
        memcpy(proof, proof_start, sizeof(proof));
    } else {
        memset(proof, 0, sizeof(proof));
    }
    for (size_t i = 0; i < max_trials; i++) {
        if (Block_prove_of_work_trial(b, proof, digest) == 0) {
            printf("Successfully done PoW in %zu trials\n", i);
            return 0; 
        }

        // increment proof
        for (int i = 0; i < POW_LOT_SIZE; i++) {
            if (proof[i] == 255) {
                proof[i] = 0;
                continue;
            }
            proof[i] += 1;
            break;
        }
    }
    return -1;
}


BlockChain *BlockChain_new(void) {
    BlockChain *p = malloc(sizeof(BlockChain));
    return p;
}
void BlockChain_delete(BlockChain *b) {
    pthread_mutex_lock(&b->mutex);
    while (b->head != NULL) {
        ChainNode *temp = b->head;
        b->head = b->head->prev;
        free(temp);
    }
    pthread_mutex_unlock(&b->mutex);
    free(b);
}
// NO THREAD SAFETY, make sure to call it only in initialization.
int BlockChain_init(BlockChain *c, bool genesis) {
    pthread_mutex_init(&c->mutex, NULL);

    if (!genesis) {
        memset(c->last_hash, 0, sizeof(c->last_hash));
        return 0;
    }
    c->head = malloc(sizeof(ChainNode));
    c->head->prev = NULL;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    double timestamp = (double)tv.tv_sec + 1e-6 * (double)tv.tv_usec;
    Block_init((Block *)&c->head->block, 0, timestamp);

    if (Block_mine((Block *)&c->head->block, MAX_TRIALS, NULL, c->last_hash) < 0)
        return -1;

    return 0;
}

void BlockChain_add_block(BlockChain *c, const Block *block) {
    pthread_mutex_lock(&c->mutex);

    ChainNode *temp = c->head;
    c->head = malloc(sizeof(ChainNode *) + BLOCK_SIZE(block));
    c->head->prev = temp;
    
    memcpy((Block *)&c->head->block, block, BLOCK_SIZE(block));
    pthread_mutex_unlock(&c->mutex);
}

ssize_t BlockChain_verify(BlockChain *c) {
    pthread_mutex_lock(&c->mutex);
    ssize_t len = 0;
    ChainNode *ptr = c->head;
    const uint8_t *hash_ptr = c->last_hash;
    while (ptr != NULL) {
        // Test if proof of work done
        for (int i = 0; i < (PREFIX_ZEROS >> 3); i++) 
            if (hash_ptr[i] != 0) 
                goto failed;
            

        // Test if hash correct
        uint8_t digest[DIGEST_SIZE];
        Block_sha256_hash(&(ptr->block), digest);
        // compare hash
        for (size_t i = 0; i < sizeof(digest); i++)
            if (digest[i] != hash_ptr[i])
                goto failed;

        // Test if the transactions has at most 1 record of node reward, and the reward is 1.
        bool node_rewarded = false;
        for (size_t i = 0; i < ptr->block.num_transactions; i++) {
            bool is_reward = true;
            Transaction *tr = BLOCK_TRANSACTIONS_P(&ptr->block) + i;
            for (int j = 0; j < PK_SIZE; j++) {
                if (tr->sender[j] != 0) {
                    is_reward = false;
                    break;
                }
            }
            if (!is_reward) {
                if (!Transaction_verify(tr)) goto failed;
                continue;
            }
            if (tr->amount != 1) goto failed;
            if (node_rewarded) goto failed;
            node_rewarded = true;
        }
        hash_ptr = ptr->block.previous_hash;
        ptr = ptr->prev;
        len++;
    }
    pthread_mutex_unlock(&c->mutex);
    return len;
failed:
    pthread_mutex_unlock(&c->mutex);
    return -1;
}
