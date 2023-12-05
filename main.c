#include <openssl/evp.h>
#include "blockchain.h"
#include "node.h"

EVP_MD_CTX *ctx = NULL;
EVP_MD *sha256 = NULL;

static void __attribute__((constructor)) init(void) {

    if ((ctx = EVP_MD_CTX_new()) == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new()");
        exit(1);
    }

    if ((sha256 = EVP_MD_fetch(NULL, "SHA256", NULL)) == NULL) {
        fprintf(stderr, "EVP_MD_fetch()");
        exit(1);
    }

} 

static void __attribute__((destructor)) fini(void) {
    EVP_MD_free(sha256);
    EVP_MD_CTX_free(ctx);
}
