#include <stdio.h>  /* printf, fopen, fread, fclose... */
#include <stdlib.h> /* exit */
#include <string.h> /* strlen */
#include <unistd.h> /* getopt */

#include "sha256.h"

#define SHA224_DIGEST_SIZE  28
#define SHA256_DIGEST_SIZE  32

#define HASH_DIGEST_SIZE    SHA256_DIGEST_SIZE      /* sha256 digest size */
#define FILE_BLOCK_SIZE     1024

/* Hash Algorithm List */
typedef enum {
    HASH_MD2,
    HASH_MD4,
    HASH_MD5,
    HASH_SHA1,
    HASH_SHA224,
    HASH_SHA256,
    HASH_SHA384,
    HASH_SHA512,
    HASH_SHA512_224,
    HASH_SHA512_256,
    HASH_SHA3_224,
    HASH_SHA3_256,
    HASH_SHA3_384,
    HASH_SHA3_512,
} HASH_ALG;

typedef struct {
    SHA256_CTX impl;
    HASH_ALG alg;
    unsigned char md[HASH_DIGEST_SIZE];
    uint32_t md_size;
    int (* init)(SHA256_CTX *c);
    int (* update)(SHA256_CTX *c, const void *data, size_t len);
    int (* final)(unsigned char *md, SHA256_CTX *c);
    unsigned char * (* hash)(const unsigned char *d, size_t n, unsigned char *md);
} HASH_CTX;

/*
 * Print a usage message
 */
void usage(const char *argv0)
{
    fprintf(stderr,
        "Usage:\n"
        "Common options: [-x|-f file|-s string| -a sha224|sha256 | -h]\n"
        "Hash a string:\n"
            "\t%s -a sha224|sha256 -s string\n"
        "Hash a file:\n"
            "\t%s -a sha224|sha256 -f file [-k key]\n"
        "-a\tSecure hash algorithm: \"sha224\", \"sha256\"\n"
        "-x\tInternal string hash test\n"
        "-h\tDisplay this message\n"
        , argv0, argv0);
    exit(1);
}

/*
 * Print a message digest in hexadecimal
 */
static int print_digest(unsigned char *digest, uint32_t len)
{
    uint32_t i;

    for (i = 0; i < len; i++)
    {
        printf ("%02x", digest[i]);
    }

    return 0;
}

struct HASH_ITEM {
    char        *str;
    uint32_t    len;
    unsigned char md[HASH_DIGEST_SIZE*2];
    // unsigned char *md;
};

/*
 * $ for alg in "sha224" "sha256"; \
 *   do \
 *     echo "Algorithm: $alg"; \
 *     for str in "" "a" "abc" "message digest" "abcdefghijklmnopqrstuvwxyz" "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" "12345678901234567890123456789012345678901234567890123456789012345678901234567890"; \
 *     do \
 *       echo "echo -n \"$str\" | openssl dgst -$alg"; \
 *       echo -n $str | openssl dgst -$alg; \
 *     done; \
 *     echo; \
 * done;
 *
 * Algorithm: sha224
 * echo -n "" | openssl dgst -sha224
 * (stdin)= d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f
 * echo -n "a" | openssl dgst -sha224
 * (stdin)= abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5
 * echo -n "abc" | openssl dgst -sha224
 * (stdin)= 23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7
 * echo -n "message digest" | openssl dgst -sha224
 * (stdin)= 2cb21c83ae2f004de7e81c3c7019cbcb65b71ab656b22d6d0c39b8eb
 * echo -n "abcdefghijklmnopqrstuvwxyz" | openssl dgst -sha224
 * (stdin)= 45a5f72c39c5cff2522eb3429799e49e5f44b356ef926bcf390dccc2
 * echo -n "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" | openssl dgst -sha224
 * (stdin)= bff72b4fcb7d75e5632900ac5f90d219e05e97a7bde72e740db393d9
 * echo -n "12345678901234567890123456789012345678901234567890123456789012345678901234567890" | openssl dgst -sha224
 * (stdin)= b50aecbe4e9bb0b57bc5f3ae760a8e01db24f203fb3cdcd13148046e
 *
 * Algorithm: sha256
 * echo -n "" | openssl dgst -sha256
 * (stdin)= e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
 * echo -n "a" | openssl dgst -sha256
 * (stdin)= ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb
 * echo -n "abc" | openssl dgst -sha256
 * (stdin)= ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
 * echo -n "message digest" | openssl dgst -sha256
 * (stdin)= f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650
 * echo -n "abcdefghijklmnopqrstuvwxyz" | openssl dgst -sha256
 * (stdin)= 71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73
 * echo -n "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" | openssl dgst -sha256
 * (stdin)= db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0
 * echo -n "12345678901234567890123456789012345678901234567890123456789012345678901234567890" | openssl dgst -sha256
 * (stdin)= f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e
 *
 */

struct HASH_ITEM sha224_hashes[] =
{
    { /* 0 */
        "",
        0,
        "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    },
    { /* 1 */
        "a",
        1,
        "abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5"
    },
    { /* 2 */
        "abc",
        3,
        "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
    },
    { /* 3 */
        "message digest",
        14,
        "2cb21c83ae2f004de7e81c3c7019cbcb65b71ab656b22d6d0c39b8eb"
    },
    { /* 4 */
        "abcdefghijklmnopqrstuvwxyz",
        26,
        "45a5f72c39c5cff2522eb3429799e49e5f44b356ef926bcf390dccc2"
    },
    { /* 5 */
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        62,
        "bff72b4fcb7d75e5632900ac5f90d219e05e97a7bde72e740db393d9"
    },
    { /* 6 */
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        80,
        "b50aecbe4e9bb0b57bc5f3ae760a8e01db24f203fb3cdcd13148046e"
    },
    {   /* End */
        NULL, 0, ""
    }
};

struct HASH_ITEM sha256_hashes[] =
{
    { /* 0 */
        "",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    },
    { /* 1 */
        "a",
        1,
        "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
    },
    { /* 2 */
        "abc",
        3,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    },
    { /* 3 */
        "message digest",
        14,
        "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650"
    },
    { /* 4 */
        "abcdefghijklmnopqrstuvwxyz",
        26,
        "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73"
    },
    { /* 5 */
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        62,
        "db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0"
    },
    { /* 6 */
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        80,
        "f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e"
    },
    {   /* End */
        NULL, 0, ""
    }
};

/*
 * Internal digest tests
 */
static int internal_digest_tests(const char *argv0, HASH_CTX *ctx)
{
    struct HASH_ITEM *tests, *item;

    if (ctx->alg == HASH_SHA224)
    {
        printf("Internal hash tests for %s(SHA224):\n", argv0);
        tests = sha224_hashes;
    }
    else /* if (ctx->alg == HASH_SHA256) */
    {
        printf("Internal hash tests for %s(SHA256):\n", argv0);
        tests = sha256_hashes;
    }

    for (item=tests; item->str != NULL; item++)
    {
        printf("%s(\"%s\")\n", argv0, item->str);
        ctx->hash((unsigned char*)item->str, item->len, ctx->md);
        printf("  Expect: %s\n", item->md);
        printf("  Result: ");
        print_digest(ctx->md, ctx->md_size);
        printf("\n\n");
    }

    return 0;
}

/*
 * Hash a string and print the digest
 */
static int digest_string(const char *argv0, HASH_CTX *ctx, const unsigned char *string, uint32_t len)
{
    printf("%s(\"%s\") = ", argv0, string);

    ctx->hash(string, len, ctx->md);

    print_digest(ctx->md, ctx->md_size);
    printf("\n");

    return 0;
}

/*
 * Hash a file and print the digest
 */
static int digest_file(const char *argv0, HASH_CTX *ctx, const char *filename)
{
    FILE *f;

    unsigned char buf[FILE_BLOCK_SIZE];

    int len = 0;
    int rc = 0;

    f = fopen(filename, "rb");
    if (NULL == f)
    {
        printf("Can't open file %s\n", filename);
        rc = -1;
    }
    else
    {
        printf("%s(%s) = ", argv0, filename);
        ctx->init(&ctx->impl);
        while ((len = fread(buf, 1, FILE_BLOCK_SIZE, f)))
        {
            ctx->update(&ctx->impl, buf, len);
        }
        ctx->final(ctx->md, &ctx->impl);

        fclose(f);

        print_digest(ctx->md, ctx->md_size);
        printf("\n");

        rc = 0;
    }

    return rc;
}

/*
 * Hash the standard input and prints the digest
 */
static void digest_stdin(const char *argv0, HASH_CTX *ctx)
{
    int len;
    unsigned char buf[HASH_DIGEST_SIZE];

    ctx->init(&ctx->impl);
    while ((len = fread(buf, 1, HASH_DIGEST_SIZE, stdin)))
    {
        ctx->update(&ctx->impl, buf, len);
    }
    ctx->final(ctx->md, &ctx->impl);

    printf("%s(stdin) = ", argv0);
    print_digest(ctx->md, ctx->md_size);
    printf("\n");
}

/*
 * $ sha256 -h
 * Usage:
 * Common options: [-x|-f file|-s string|-h]
 * Hash a string:
 *         sha256 -s string
 * Hash a file:
 *         sha256 -f file [-k key]
 * -x      Internal string hash test
 * -h      Display this message
 */
int main(int argc, char *argv[])
{
    int ch;
    int hash_internal = 0;
    int hash_str = 0;
    int hash_file = 0;
    int hash_stdin = 0;

    char *alg = NULL;

    char *str = NULL;
    uint32_t len = 0;

    char *filename = NULL;

    HASH_CTX ctx;
    memset(&ctx, 0, sizeof(HASH_CTX));

    while ((ch = getopt(argc, argv, "a:s:f:xh")) != -1)
    {
        switch(ch)
        {
            case 'a':
                alg = optarg;
                break;
            case 'x':
                hash_internal = 1;
                break;
            case 's':
                hash_str = 1;
                str = optarg;
                len = strlen(str);
                break;
            case 'f':
                hash_file = 1;
                filename = optarg;
                break;
            case 'h':
            default: /* '?' */
                usage(argv[0]);
                break;
        }
    }

    if (argc == 1)
    {
        hash_stdin = 1;
    }

    /*
     * Setup ctx according to algorithm
     */
    if ((NULL == alg) || (strncmp(alg, "sha256", 6) == 0))
    {
        ctx.alg = HASH_SHA256;
        ctx.md_size = SHA256_DIGEST_SIZE;
        ctx.init = SHA256_Init;
        ctx.update = SHA256_Update;
        ctx.final = SHA256_Final;
        ctx.hash = SHA256;
    }
    else if (strncmp(alg, "sha224", 6) == 0)
    {
        ctx.alg = HASH_SHA224;
        ctx.md_size = SHA224_DIGEST_SIZE;
        ctx.init = SHA224_Init;
        ctx.update = SHA224_Update;
        ctx.final = SHA224_Final;
        ctx.hash = SHA224;
    }
    else
    {
        usage(argv[0]);
    }

    if (hash_internal)
    {
        internal_digest_tests(argv[0], &ctx);
    }

    if (hash_str)
    {
        digest_string(argv[0], &ctx, (unsigned char *)str, len);
    }

    if (hash_file)
    {
        digest_file(argv[0], &ctx, filename);
    }

    if (hash_stdin)
    {
        digest_stdin(argv[0], &ctx);
    }

    return 0;
}
