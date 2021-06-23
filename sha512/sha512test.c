#include <stdio.h>  /* printf, fopen, fread, fclose... */
#include <stdlib.h> /* exit */
#include <string.h> /* strlen */
#include <unistd.h> /* getopt */

#include "sha512.h"

#define SHA512_224_DIGEST_SIZE  	28
#define SHA512_256_DIGEST_SIZE  	32
#define SHA384_DIGEST_SIZE  		48
#define SHA512_DIGEST_SIZE  		64

#define HASH_DIGEST_SIZE    		SHA512_DIGEST_SIZE  /* sha512 digest size */
#define HASH_NAME_SIZE              10                  /* hash name size, like "sha512-224" is 10 bytes */
#define FILE_BLOCK_SIZE             1024

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
    HASH_SHA512_T,
    HASH_SHA3_224,
    HASH_SHA3_256,
    HASH_SHA3_384,
    HASH_SHA3_512,
} HASH_ALG;

typedef struct {
    SHA512_CTX impl;
    HASH_ALG alg;
    unsigned char md[HASH_DIGEST_SIZE];
    uint32_t md_size;
    int (* init)(SHA512_CTX *c);
    int (* update)(SHA512_CTX *c, const void *data, size_t len);
    int (* final)(unsigned char *md, SHA512_CTX *c);
    unsigned char * (* hash)(const unsigned char *d, size_t n, unsigned char *md);

    /* SHA512t */
    uint32_t ext;
    int (* init_ex)(SHA512_CTX *c, unsigned int t);
    unsigned char * (* hash_ex)(const unsigned char *d, size_t n, unsigned char *md, unsigned int t);
} HASH_CTX;

/*
 * Print a usage message
 */
void usage(const char *argv0)
{
    fprintf(stderr,
        "Usage:\n"
        "Common options: [-x|-f file|-s string| -a sha384|sha512|sha512-224|sha512-256|sha512t | -t num | -h]\n"
        "Hash a string:\n"
            "\t%s -a sha384|sha512|sha512-224|sha512-256|sha512t -s string\n"
        "Hash a file:\n"
            "\t%s -a sha384|sha512|sha512-224|sha512-256|sha512t -f file\n"
        "-a\tSecure hash algorithm: \"sha384\", \"sha512\", \"sha512-224\", \"sha512-256\"\n"
        "-t\tt value for SHA512/t, positive integer without a leading zero, (0<t<512, t/8=0, t!=384)\n"
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
 * $ for alg in "sha384" "sha512" "sha512-224" "sha512-256"; \
 * > do \
 * >   echo "Algorithm: $alg"; \
 * >   for str in "" "a" "abc" "message digest" "abcdefghijklmnopqrstuvwxyz" "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" "12345678901234567890123456789012345678901234567890123456789012345678901234567890"; \
 * >     do \
 * >       echo "echo -n \"$str\" | openssl dgst -$alg"; \
 * >       echo -n $str | openssl dgst -$alg; \
 * >   done; \
 * >   echo; \
 * > done;
 * Algorithm: sha384
 * echo -n "" | openssl dgst -sha384
 * (stdin)= 38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b
 * echo -n "a" | openssl dgst -sha384
 * (stdin)= 54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31
 * echo -n "abc" | openssl dgst -sha384
 * (stdin)= cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7
 * echo -n "message digest" | openssl dgst -sha384
 * (stdin)= 473ed35167ec1f5d8e550368a3db39be54639f828868e9454c239fc8b52e3c61dbd0d8b4de1390c256dcbb5d5fd99cd5
 * echo -n "abcdefghijklmnopqrstuvwxyz" | openssl dgst -sha384
 * (stdin)= feb67349df3db6f5924815d6c3dc133f091809213731fe5c7b5f4999e463479ff2877f5f2936fa63bb43784b12f3ebb4
 * echo -n "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" | openssl dgst -sha384
 * (stdin)= 1761336e3f7cbfe51deb137f026f89e01a448e3b1fafa64039c1464ee8732f11a5341a6f41e0c202294736ed64db1a84
 * echo -n "12345678901234567890123456789012345678901234567890123456789012345678901234567890" | openssl dgst -sha384
 * (stdin)= b12932b0627d1c060942f5447764155655bd4da0c9afa6dd9b9ef53129af1b8fb0195996d2de9ca0df9d821ffee67026
 *
 * Algorithm: sha512
 * echo -n "" | openssl dgst -sha512
 * (stdin)= cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e
 * echo -n "a" | openssl dgst -sha512
 * (stdin)= 1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75
 * echo -n "abc" | openssl dgst -sha512
 * (stdin)= ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f
 * echo -n "message digest" | openssl dgst -sha512
 * (stdin)= 107dbf389d9e9f71a3a95f6c055b9251bc5268c2be16d6c13492ea45b0199f3309e16455ab1e96118e8a905d5597b72038ddb372a89826046de66687bb420e7c
 * echo -n "abcdefghijklmnopqrstuvwxyz" | openssl dgst -sha512
 * (stdin)= 4dbff86cc2ca1bae1e16468a05cb9881c97f1753bce3619034898faa1aabe429955a1bf8ec483d7421fe3c1646613a59ed5441fb0f321389f77f48a879c7b1f1
 * echo -n "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" | openssl dgst -sha512
 * (stdin)= 1e07be23c26a86ea37ea810c8ec7809352515a970e9253c26f536cfc7a9996c45c8370583e0a78fa4a90041d71a4ceab7423f19c71b9d5a3e01249f0bebd5894
 * echo -n "12345678901234567890123456789012345678901234567890123456789012345678901234567890" | openssl dgst -sha512
 * (stdin)= 72ec1ef1124a45b047e8b7c75a932195135bb61de24ec0d1914042246e0aec3a2354e093d76f3048b456764346900cb130d2a4fd5dd16abb5e30bcb850dee843
 *
 * Algorithm: sha512-224
 * echo -n "" | openssl dgst -sha512-224
 * (stdin)= 6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4
 * echo -n "a" | openssl dgst -sha512-224
 * (stdin)= d5cdb9ccc769a5121d4175f2bfdd13d6310e0d3d361ea75d82108327
 * echo -n "abc" | openssl dgst -sha512-224
 * (stdin)= 4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa
 * echo -n "message digest" | openssl dgst -sha512-224
 * (stdin)= ad1a4db188fe57064f4f24609d2a83cd0afb9b398eb2fcaeaae2c564
 * echo -n "abcdefghijklmnopqrstuvwxyz" | openssl dgst -sha512-224
 * (stdin)= ff83148aa07ec30655c1b40aff86141c0215fe2a54f767d3f38743d8
 * echo -n "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" | openssl dgst -sha512-224
 * (stdin)= a8b4b9174b99ffc67d6f49be9981587b96441051e16e6dd036b140d3
 * echo -n "12345678901234567890123456789012345678901234567890123456789012345678901234567890" | openssl dgst -sha512-224
 * (stdin)= ae988faaa47e401a45f704d1272d99702458fea2ddc6582827556dd2
 *
 * Algorithm: sha512-256
 * echo -n "" | openssl dgst -sha512-256
 * (stdin)= c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a
 * echo -n "a" | openssl dgst -sha512-256
 * (stdin)= 455e518824bc0601f9fb858ff5c37d417d67c2f8e0df2babe4808858aea830f8
 * echo -n "abc" | openssl dgst -sha512-256
 * (stdin)= 53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23
 * echo -n "message digest" | openssl dgst -sha512-256
 * (stdin)= 0cf471fd17ed69d990daf3433c89b16d63dec1bb9cb42a6094604ee5d7b4e9fb
 * echo -n "abcdefghijklmnopqrstuvwxyz" | openssl dgst -sha512-256
 * (stdin)= fc3189443f9c268f626aea08a756abe7b726b05f701cb08222312ccfd6710a26
 * echo -n "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" | openssl dgst -sha512-256
 * (stdin)= cdf1cc0effe26ecc0c13758f7b4a48e000615df241284185c39eb05d355bb9c8
 * echo -n "12345678901234567890123456789012345678901234567890123456789012345678901234567890" | openssl dgst -sha512-256
 * (stdin)= 2c9fdbc0c90bdd87612ee8455474f9044850241dc105b1e8b94b8ddf5fac9148
 */

struct HASH_ITEM sha384_hashes[] =
{
    { /* 0 */
        "",
        0,
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    },
    { /* 1 */
        "a",
        1,
        "54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31"
    },
    { /* 2 */
        "abc",
        3,
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
    },
    { /* 3 */
        "message digest",
        14,
        "473ed35167ec1f5d8e550368a3db39be54639f828868e9454c239fc8b52e3c61dbd0d8b4de1390c256dcbb5d5fd99cd5"
    },
    { /* 4 */
        "abcdefghijklmnopqrstuvwxyz",
        26,
        "feb67349df3db6f5924815d6c3dc133f091809213731fe5c7b5f4999e463479ff2877f5f2936fa63bb43784b12f3ebb4"
    },
    { /* 5 */
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        62,
        "1761336e3f7cbfe51deb137f026f89e01a448e3b1fafa64039c1464ee8732f11a5341a6f41e0c202294736ed64db1a84"
    },
    { /* 6 */
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        80,
        "b12932b0627d1c060942f5447764155655bd4da0c9afa6dd9b9ef53129af1b8fb0195996d2de9ca0df9d821ffee67026"
    },
    {   /* End */
        NULL, 0, ""
    }
};

struct HASH_ITEM sha512_hashes[] =
{
    { /* 0 */
        "",
        0,
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    },
    { /* 1 */
        "a",
        1,
        "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75"
    },
    { /* 2 */
        "abc",
        3,
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    },
    { /* 3 */
        "message digest",
        14,
        "107dbf389d9e9f71a3a95f6c055b9251bc5268c2be16d6c13492ea45b0199f3309e16455ab1e96118e8a905d5597b72038ddb372a89826046de66687bb420e7c"
    },
    { /* 4 */
        "abcdefghijklmnopqrstuvwxyz",
        26,
        "4dbff86cc2ca1bae1e16468a05cb9881c97f1753bce3619034898faa1aabe429955a1bf8ec483d7421fe3c1646613a59ed5441fb0f321389f77f48a879c7b1f1"
    },
    { /* 5 */
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        62,
        "1e07be23c26a86ea37ea810c8ec7809352515a970e9253c26f536cfc7a9996c45c8370583e0a78fa4a90041d71a4ceab7423f19c71b9d5a3e01249f0bebd5894"
    },
    { /* 6 */
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        80,
        "72ec1ef1124a45b047e8b7c75a932195135bb61de24ec0d1914042246e0aec3a2354e093d76f3048b456764346900cb130d2a4fd5dd16abb5e30bcb850dee843"
    },
    {   /* End */
        NULL, 0, ""
    }
};

struct HASH_ITEM sha512_224_hashes[] =
{
    { /* 0 */
        "",
        0,
        "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4"
    },
    { /* 1 */
        "a",
        1,
        "d5cdb9ccc769a5121d4175f2bfdd13d6310e0d3d361ea75d82108327"
    },
    { /* 2 */
        "abc",
        3,
        "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"
    },
    { /* 3 */
        "message digest",
        14,
        "ad1a4db188fe57064f4f24609d2a83cd0afb9b398eb2fcaeaae2c564"
    },
    { /* 4 */
        "abcdefghijklmnopqrstuvwxyz",
        26,
        "ff83148aa07ec30655c1b40aff86141c0215fe2a54f767d3f38743d8"
    },
    { /* 5 */
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        62,
        "a8b4b9174b99ffc67d6f49be9981587b96441051e16e6dd036b140d3"
    },
    { /* 6 */
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        80,
        "ae988faaa47e401a45f704d1272d99702458fea2ddc6582827556dd2"
    },
    {   /* End */
        NULL, 0, ""
    }
};

struct HASH_ITEM sha512_256_hashes[] =
{
    { /* 0 */
        "",
        0,
        "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"
    },
    { /* 1 */
        "a",
        1,
        "455e518824bc0601f9fb858ff5c37d417d67c2f8e0df2babe4808858aea830f8"
    },
    { /* 2 */
        "abc",
        3,
        "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"
    },
    { /* 3 */
        "message digest",
        14,
        "0cf471fd17ed69d990daf3433c89b16d63dec1bb9cb42a6094604ee5d7b4e9fb"
    },
    { /* 4 */
        "abcdefghijklmnopqrstuvwxyz",
        26,
        "fc3189443f9c268f626aea08a756abe7b726b05f701cb08222312ccfd6710a26"
    },
    { /* 5 */
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        62,
        "cdf1cc0effe26ecc0c13758f7b4a48e000615df241284185c39eb05d355bb9c8"
    },
    { /* 6 */
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        80,
        "2c9fdbc0c90bdd87612ee8455474f9044850241dc105b1e8b94b8ddf5fac9148"
    },
    {   /* End */
        NULL, 0, ""
    }
};

/* SHA512/t tests, result is for SHA512/224, and same as SHA512-224 */
struct HASH_ITEM sha512t_hashes[] =
{
    { /* 0 */
        "",
        0,
        "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4"
    },
    { /* 1 */
        "a",
        1,
        "d5cdb9ccc769a5121d4175f2bfdd13d6310e0d3d361ea75d82108327"
    },
    { /* 2 */
        "abc",
        3,
        "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"
    },
    { /* 3 */
        "message digest",
        14,
        "ad1a4db188fe57064f4f24609d2a83cd0afb9b398eb2fcaeaae2c564"
    },
    { /* 4 */
        "abcdefghijklmnopqrstuvwxyz",
        26,
        "ff83148aa07ec30655c1b40aff86141c0215fe2a54f767d3f38743d8"
    },
    { /* 5 */
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        62,
        "a8b4b9174b99ffc67d6f49be9981587b96441051e16e6dd036b140d3"
    },
    { /* 6 */
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        80,
        "ae988faaa47e401a45f704d1272d99702458fea2ddc6582827556dd2"
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

    switch (ctx->alg)
    {
        case HASH_SHA384:
            printf("Internal hash tests for %s(SHA384):\n", argv0);
            tests = sha384_hashes;
            break;
        case HASH_SHA512_224:
            printf("Internal hash tests for %s(SHA512/224):\n", argv0);
            tests = sha512_224_hashes;
            break;
        case HASH_SHA512_256:
            printf("Internal hash tests for %s(SHA512/256):\n", argv0);
            tests = sha512_256_hashes;
            break;
        case HASH_SHA512_T:
            printf("Internal hash tests for %s(SHA512/t):\n", argv0);
            tests = sha512t_hashes;
            break;
        case HASH_SHA512:
        default:
            printf("Internal hash tests for %s(SHA512):\n", argv0);
            tests = sha512_hashes;
            break;
    }

    for (item=tests; item->str != NULL; item++)
    {
        printf("%s(\"%s\")\n", argv0, item->str);
        if (ctx->alg == HASH_SHA512_T)
        {
            ctx->hash_ex((unsigned char *)item->str, item->len, ctx->md, ctx->ext);
        }
        else
        {
            ctx->hash((unsigned char*)item->str, item->len, ctx->md);
        }

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

    if (ctx->alg == HASH_SHA512_T)
    {
        ctx->hash_ex(string, len, ctx->md, ctx->ext);
    }
    else
    {
        ctx->hash(string, len, ctx->md);
    }

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
        if (ctx->alg == HASH_SHA512_T)
        {
            ctx->init_ex(&ctx->impl, ctx->ext);
        }
        else
        {
            ctx->init(&ctx->impl);
        }

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

    if (ctx->alg == HASH_SHA512_T)
    {
        ctx->init_ex(&ctx->impl, ctx->ext);
    }
    else
    {
        ctx->init(&ctx->impl);
    }

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
 * $ sha512 -h
 * Usage:
 * Common options: [-x|-f file|-s string| -a sha384|sha512|sha512-224|sha512-256|sha512t | -t num | -h]
 * Hash a string:
 *         sha512 -a sha384|sha512|sha512-224|sha512-256|sha512t -s string
 * Hash a file:
 *         sha512 -a sha384|sha512|sha512-224|sha512-256|sha512t -f file
 * -a      Secure hash algorithm: "sha384", "sha512", "sha512-224", "sha512-256"
 * -t      t value for SHA512/t, positive integer without a leading zero, (0<t<512, t/8=0, t!=384)
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
    int hash_ext = 0;

    /* SHA512t */
    uint32_t ext = 0;

    char alg[HASH_NAME_SIZE];
    uint32_t alg_len = 0;

    char *str = NULL;
    uint32_t len = 0;

    char *filename = NULL;

    HASH_CTX ctx;
    memset(&ctx, 0, sizeof(HASH_CTX));

    while ((ch = getopt(argc, argv, "a:s:f:t:xh")) != -1)
    {
        switch(ch)
        {
            case 'a':
                alg_len = strlen(optarg);
                alg_len = alg_len < HASH_NAME_SIZE ? alg_len : HASH_NAME_SIZE;
                memset(alg, 0, sizeof(alg));
                strncpy(alg, optarg, alg_len);
                alg[alg_len] = '\0';
                break;
            case 'x':
                hash_internal = 1;
                break;
            case 's':
                hash_str = 1;
                str = optarg;
                len = strlen(str);
                break;
            case 't':
                hash_ext = 1;
                ext = atoi(optarg);
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
    if ((NULL == alg) || (strncmp(alg, "sha512", alg_len) == 0))
    {
        ctx.alg = HASH_SHA512;
        ctx.md_size = SHA512_DIGEST_SIZE;
        ctx.init = SHA512_Init;
        ctx.update = SHA512_Update;
        ctx.final = SHA512_Final;
        ctx.hash = SHA512;
    }
    else if (strncmp(alg, "sha384", alg_len) == 0)
    {
        ctx.alg = HASH_SHA384;
        ctx.md_size = SHA384_DIGEST_SIZE;
        ctx.init = SHA384_Init;
        ctx.update = SHA384_Update;
        ctx.final = SHA384_Final;
        ctx.hash = SHA384;
    }
    else if (strncmp(alg, "sha512-224", alg_len) == 0)
    {
        ctx.alg = HASH_SHA512_224;
        ctx.md_size = SHA512_224_DIGEST_SIZE;
        ctx.init = SHA512_224_Init;
        ctx.update = SHA512_224_Update;
        ctx.final = SHA512_224_Final;
        ctx.hash = SHA512_224;
    }
    else if (strncmp(alg, "sha512-256", alg_len) == 0)
    {
        ctx.alg = HASH_SHA512_256;
        ctx.md_size = SHA512_256_DIGEST_SIZE;
        ctx.init = SHA512_256_Init;
        ctx.update = SHA512_256_Update;
        ctx.final = SHA512_256_Final;
        ctx.hash = SHA512_256;
    }
    else if (strncmp(alg, "sha512t", alg_len) == 0)
    {
        /* 't' is not set, or set not as expected */
        if ((hash_ext == 0) || (ext >= 512) || (ext%8 != 0) || (ext == 384))
        {
            usage(argv[0]);
        }

        ctx.alg = HASH_SHA512_T;
        ctx.ext = ext;
        ctx.md_size = ext / 8;
        ctx.init = NULL;
        ctx.update = SHA512t_Update;
        ctx.final = SHA512t_Final;

        ctx.init_ex = SHA512t_Init;
        ctx.hash_ex = SHA512t;
    }
    else
    {
        usage(argv[0]);
    }

    if (hash_internal)
    {
        /* Only support SHA512/224 for SHA512/t internal test */
        if ((ctx.alg == HASH_SHA512_T) && (ctx.ext != 224))
        {
            printf("SHA512/t internal tests: %s -a sha512t -t 224 -x\n", argv[0]);
            usage(argv[0]);
        }
        internal_digest_tests(alg, &ctx);
    }

    if (hash_str)
    {
        digest_string(alg, &ctx, (unsigned char *)str, len);
    }

    if (hash_file)
    {
        digest_file(alg, &ctx, filename);
    }

    if (hash_stdin)
    {
        digest_stdin(alg, &ctx);
    }

    return 0;
}
