/*
 * @        file: md4test.c
 * @ description: test tool for md4
 * @      author: Gu Yongqiang
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#include <stdio.h>  /* printf, fopen, fread, fclose... */
#include <stdlib.h> /* exit */
#include <string.h> /* strlen */
#include <unistd.h> /* getopt */

#include "md4.h"

#define HASH_DIGEST_SIZE    16      /* md4 digest size */
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
        "31d6cfe0d16ae931b73c59d7e0c089c0"
    },
    { /* 1 */
        "a",
        1,
        "bde52cb31de33e46245e05fbdbd6fb24"
    },
    { /* 2 */
        "abc",
        3,
        "a448017aaf21d8525fc10ae87aa6729d"
    },
    { /* 3 */
        "message digest",
        14,
        "d9130a8164549fe818874806e1c7014b"
    },
    { /* 4 */
        "abcdefghijklmnopqrstuvwxyz",
        26,
        "d79e1c308aa5bbcdeea8ed63df412da9"
    },
    { /* 5 */
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        62,
        "043f8582f241db351ce627e153e7f0e4"
    },
    { /* 6 */
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        80,
        "e33b4ddc9c38f2199c3e7b164fcc0536"
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
        MD4((unsigned char*)item->str, item->len, digest);
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

    MD4(string, len, digest);

    print_digest(digest);
    printf("\n");

    return 0;
}

/*
 * Hash a file and print the digest
 */
static int digest_file(const char *argv0, const char *filename)
{
    MD4_CTX c;
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

        MD4_Init(&c);
        while ((len = fread(buf, 1, FILE_BLOCK_SIZE, f)))
        {
            MD4_Update(&c, buf, len);
        }
        MD4_Final(digest, &c);

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
    MD4_CTX c;

    int len;
    unsigned char digest[HASH_DIGEST_SIZE];
    unsigned char buf[HASH_DIGEST_SIZE];

    MD4_Init(&c);
    while ((len = fread(buf, 1, HASH_DIGEST_SIZE, stdin)))
    {
        MD4_Update(&c, buf, len);
    }
    MD4_Final(digest, &c);

    printf("%s(stdin) = ", argv0);
    print_digest(digest);
    printf("\n");
}

/*
 * $ md4 -h
 * Usage:
 * Common options: [-x|-f file|-s string|-h]
 * Hash a string:
 *         md4 -s string
 * Hash a file:
 *         md4 -f file [-k key]
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
