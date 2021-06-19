/*
 * @        file: sm3test.c
 * @ description: test tool for sm3
 * @      author: Gu Yongqiang
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#include <stdio.h>  /* printf, fopen, fread, fclose... */
#include <stdlib.h> /* exit */
#include <string.h> /* strlen */
#include <unistd.h> /* getopt */

#include "sm3.h"

#define HASH_DIGEST_SIZE    32      /* sm3 digest size */
#define FILE_BLOCK_SIZE     1024

/*
 * Print a usage message
 */
void usage(const char *argv0)
{
    fprintf(stderr,
        "Usage:\n"
        "Common options: [-x|-f file|-s string|-h]\n"
        "Hash a string:\n"
            "\t%s -s string\n"
        "Hash a file:\n"
            "\t%s -f file [-k key]\n"
        "-x\tInternal string hash test\n"
        "-h\tDisplay this message\n"
        , argv0, argv0);
    exit(1);
}

/*
 * Print a message digest in hexadecimal
 */
static int print_digest(unsigned char *digest)
{
    uint32_t i;

    for (i = 0; i < HASH_DIGEST_SIZE; i++)
    {
        printf ("%02x", digest[i]);
    }

    return 0;
}

struct HASH_ITEM {
    char        *str;
    uint32_t    len;
    unsigned char md[HASH_DIGEST_SIZE*2];
} hashes[] =
{
    { /* 0 */
        "",
        0,
        "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"
    },
    { /* 1 */
        "a",
        1,
        "623476ac18f65a2909e43c7fec61b49c7e764a91a18ccb82f1917a29c86c5e88"
    },
    { /* 2 */
        "abc",
        3,
        "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
    },
    { /* 3 */
        "message digest",
        14,
        "c522a942e89bd80d97dd666e7a5531b36188c9817149e9b258dfe51ece98ed77"
    },
    { /* 4 */
        "abcdefghijklmnopqrstuvwxyz",
        26,
        "b80fe97a4da24afc277564f66a359ef440462ad28dcc6d63adb24d5c20a61595"
    },
    { /* 5 */
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        62,
        "2971d10c8842b70c979e55063480c50bacffd90e98e2e60d2512ab8abfdfcec5"
    },
    { /* 6 */
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        80,
        "ad81805321f3e69d251235bf886a564844873b56dd7dde400f055b7dde39307a"
    },
    { /* 7 */
        "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
        64,
        "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"
    },
};

/*
 * Internal digest tests
 */
static int internal_digest_tests(const char *argv0)
{
    unsigned char digest[HASH_DIGEST_SIZE];
    struct HASH_ITEM *item;

    printf ("Internal hash tests for %s:\n", argv0);

    for (item=&hashes[0]; item<(&hashes[0]+sizeof(hashes)/sizeof(hashes[0])); item++)
    {
        printf("%s(\"%s\")\n", argv0, item->str);
        SM3((unsigned char*)item->str, item->len, digest);
        printf("  Expect: %s\n", item->md);
        printf("  Result: ");
        print_digest(digest);
        printf("\n\n");
    }

    return 0;
}

/*
 * Hash a string and print the digest
 */
static int digest_string(const char *argv0, const unsigned char *string, uint32_t len)
{
    unsigned char digest[HASH_DIGEST_SIZE];

    printf("%s(\"%s\") = ", argv0, string);

    SM3(string, len, digest);

    print_digest(digest);
    printf("\n");

    return 0;
}

/*
 * Hash a file and print the digest
 */
static int digest_file(const char *argv0, const char *filename)
{
    SM3_CTX c;
    FILE *f;

    unsigned char digest[HASH_DIGEST_SIZE];
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

        SM3_Init(&c);
        while ((len = fread(buf, 1, FILE_BLOCK_SIZE, f)))
        {
            SM3_Update(&c, buf, len);
        }
        SM3_Final(digest, &c);

        fclose(f);

        print_digest(digest);
        printf("\n");

        rc = 0;
    }

    return rc;
}

/*
 * Hash the standard input and prints the digest
 */
static void digest_stdin(const char *argv0)
{
    SM3_CTX c;

    int len;
    unsigned char digest[HASH_DIGEST_SIZE];
    unsigned char buf[HASH_DIGEST_SIZE];

    SM3_Init(&c);
    while ((len = fread(buf, 1, HASH_DIGEST_SIZE, stdin)))
    {
        SM3_Update(&c, buf, len);
    }
    SM3_Final(digest, &c);

    printf("%s(stdin) = ", argv0);
    print_digest(digest);
    printf("\n");
}

/*
 * $ sm3 -h
 * Usage:
 * Common options: [-x|-f file|-s string|-h]
 * Hash a string:
 *         sm3 -s string
 * Hash a file:
 *         sm3 -f file [-k key]
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

    char *str = NULL;
    uint32_t len = 0;

    char *filename = NULL;

    while ((ch = getopt(argc, argv, "s:f:xh")) != -1)
    {
        switch(ch)
        {
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

    if (hash_internal)
    {
        internal_digest_tests(argv[0]);
    }

    if (hash_str)
    {
        digest_string(argv[0], (unsigned char *)str, len);
    }

    if (hash_file)
    {
        digest_file(argv[0], filename);
    }

    if (hash_stdin)
    {
        digest_stdin(argv[0]);
    }

    return 0;
}
