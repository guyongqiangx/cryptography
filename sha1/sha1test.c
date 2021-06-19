/*
 * @        file: sha1test.c
 * @ description: test tool for sha1
 * @      author: Gu Yongqiang
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#include <stdio.h>  /* printf, fopen, fread, fclose... */
#include <stdlib.h> /* exit */
#include <string.h> /* strlen */
#include <unistd.h> /* getopt */

#include "sha1.h"

#define HASH_DIGEST_SIZE    20      /* sha1 digest size */
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
        "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    },
    { /* 1 */
        "a",
        1,
        "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8"
    },
    { /* 2 */
        "abc",
        3,
        "a9993e364706816aba3e25717850c26c9cd0d89d"
    },
    { /* 3 */
        "message digest",
        14,
        "c12252ceda8be8994d5fa0290a47231c1d16aae3"
    },
    { /* 4 */
        "abcdefghijklmnopqrstuvwxyz",
        26,
        "32d10c7b8cf96570ca04ce37f2a19d84240d3a89"
    },
    { /* 5 */
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        62,
        "761c457bf73b14d27e9e9265c46f4b4dda11f940"
    },
    { /* 6 */
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        80,
        "50abf5706a150990a08b2c5ea40fa0e585554732"
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
        SHA1((unsigned char*)item->str, item->len, digest);
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

    SHA1(string, len, digest);

    print_digest(digest);
    printf("\n");

    return 0;
}

/*
 * Hash a file and print the digest
 */
static int digest_file(const char *argv0, const char *filename)
{
    SHA_CTX c;
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

        SHA1_Init(&c);
        while ((len = fread(buf, 1, FILE_BLOCK_SIZE, f)))
        {
            SHA1_Update(&c, buf, len);
        }
        SHA1_Final(digest, &c);

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
    SHA_CTX c;

    int len;
    unsigned char digest[HASH_DIGEST_SIZE];
    unsigned char buf[HASH_DIGEST_SIZE];

    SHA1_Init(&c);
    while ((len = fread(buf, 1, HASH_DIGEST_SIZE, stdin)))
    {
        SHA1_Update(&c, buf, len);
    }
    SHA1_Final(digest, &c);

    printf("%s(stdin) = ", argv0);
    print_digest(digest);
    printf("\n");
}

/*
 * $ sha1 -h
 * Usage:
 * Common options: [-x|-f file|-s string|-h]
 * Hash a string:
 *         sha1 -s string
 * Hash a file:
 *         sha1 -f file [-k key]
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
