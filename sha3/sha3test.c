/*
 * @        file: sha3test.c
 * @ description: test tool for sha3 (sha3-224, sha3-256, sha3-384, sha3-512, shake128, shake256)
 * @      author: Gu Yongqiang
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#include <stdio.h>  /* printf, fopen, fread, fclose... */
#include <stdlib.h> /* exit */
#include <string.h> /* strlen */
#include <unistd.h> /* getopt */

#include "sha3.h"

#define SHA3_224_DIGEST_SIZE        28
#define SHA3_256_DIGEST_SIZE        32
#define SHA3_384_DIGEST_SIZE        48
#define SHA3_512_DIGEST_SIZE        64

#define HASH_DIGEST_SIZE            SHA3_512_DIGEST_SIZE      /* sha3 digest size */
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
    HASH_SHAKE128,
    HASH_SHAKE256
} HASH_ALG;

typedef struct {
    SHA3_CTX impl;
    SHA3_ALG alg;

    unsigned char *md;
    uint32_t md_size;

    int (* init)(SHA3_CTX *c, SHA3_ALG alg);
    int (* update)(SHA3_CTX *c, const void *data, size_t len);
    int (* final)(unsigned char *md, SHA3_CTX *c);
    unsigned char * (* hash)(SHA3_ALG alg, const unsigned char *data, size_t n, unsigned char *md);

    /* SHAKE128/SHAKE256 */
    int (* init_ex)(SHA3_CTX *c, SHA3_ALG alg, unsigned int d);
    unsigned char * (* hash_ex)(SHA3_ALG alg, const unsigned char *data, size_t n, unsigned char *md, unsigned int d);

    unsigned int ext; /* d value for SHAKE128/SHAKE256 */
} HASH_CTX;

/*
 * Print a usage message
 */
void usage(const char *argv0)
{
    fprintf(stderr,
        "Usage:\n"
        "Common options: [-a sha3-224|sha3-256|sha3-384|sha3-512|shake128|shake256 [-d num]] [-x|-f file|-s string|-h]\n"
        "Hash a string:\n"
            "\t%s -a [sha3-224|sha3-256|sha3-384|sha3-512|shake128|shake256] [-d num] -s string\n"
        "Hash a file:\n"
            "\t%s -a [sha3-224|sha3-256|sha3-384|sha3-512|shake128|shake256] [-d num] -f file\n"
        "-a\tSecure hash algorithm: \"sha3-224|sha3-256|sha3-384|sha3-512|shake128|shake256\". Default: sha3-256\n"
        "-d\td value for shake128/shake256, default: shake128(num2=128), shake256(num=256)\n"
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
 * $ for alg in "sha3-224" "sha3-256" "sha3-384" "sha3-512" "shake128" "shake256"; \
 * > do \
 * >   echo "Algorithm: $alg"; \
 * >   for str in "" "a" "abc" "message digest" "abcdefghijklmnopqrstuvwxyz" "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" "12345678901234567890123456789012345678901234567890123456789012345678901234567890"; \
 * >     do \
 * >       echo "echo -n \"$str\" | openssl dgst -$alg"; \
 * >       echo -n $str | openssl dgst -$alg; \
 * >   done; \
 * >   echo; \
 * > done;
 * Algorithm: sha3-224
 * echo -n "" | openssl dgst -sha3-224
 * (stdin)= 6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7
 * echo -n "a" | openssl dgst -sha3-224
 * (stdin)= 9e86ff69557ca95f405f081269685b38e3a819b309ee942f482b6a8b
 * echo -n "abc" | openssl dgst -sha3-224
 * (stdin)= e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf
 * echo -n "message digest" | openssl dgst -sha3-224
 * (stdin)= 18768bb4c48eb7fc88e5ddb17efcf2964abd7798a39d86a4b4a1e4c8
 * echo -n "abcdefghijklmnopqrstuvwxyz" | openssl dgst -sha3-224
 * (stdin)= 5cdeca81e123f87cad96b9cba999f16f6d41549608d4e0f4681b8239
 * echo -n "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" | openssl dgst -sha3-224
 * (stdin)= a67c289b8250a6f437a20137985d605589a8c163d45261b15419556e
 * echo -n "12345678901234567890123456789012345678901234567890123456789012345678901234567890" | openssl dgst -sha3-224
 * (stdin)= 0526898e185869f91b3e2a76dd72a15dc6940a67c8164a044cd25cc8
 *
 * Algorithm: sha3-256
 * echo -n "" | openssl dgst -sha3-256
 * (stdin)= a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
 * echo -n "a" | openssl dgst -sha3-256
 * (stdin)= 80084bf2fba02475726feb2cab2d8215eab14bc6bdd8bfb2c8151257032ecd8b
 * echo -n "abc" | openssl dgst -sha3-256
 * (stdin)= 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
 * echo -n "message digest" | openssl dgst -sha3-256
 * (stdin)= edcdb2069366e75243860c18c3a11465eca34bce6143d30c8665cefcfd32bffd
 * echo -n "abcdefghijklmnopqrstuvwxyz" | openssl dgst -sha3-256
 * (stdin)= 7cab2dc765e21b241dbc1c255ce620b29f527c6d5e7f5f843e56288f0d707521
 * echo -n "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" | openssl dgst -sha3-256
 * (stdin)= a79d6a9da47f04a3b9a9323ec9991f2105d4c78a7bc7beeb103855a7a11dfb9f
 * echo -n "12345678901234567890123456789012345678901234567890123456789012345678901234567890" | openssl dgst -sha3-256
 * (stdin)= 293e5ce4ce54ee71990ab06e511b7ccd62722b1beb414f5ff65c8274e0f5be1d
 *
 * Algorithm: sha3-384
 * echo -n "" | openssl dgst -sha3-384
 * (stdin)= 0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004
 * echo -n "a" | openssl dgst -sha3-384
 * (stdin)= 1815f774f320491b48569efec794d249eeb59aae46d22bf77dafe25c5edc28d7ea44f93ee1234aa88f61c91912a4ccd9
 * echo -n "abc" | openssl dgst -sha3-384
 * (stdin)= ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25
 * echo -n "message digest" | openssl dgst -sha3-384
 * (stdin)= d9519709f44af73e2c8e291109a979de3d61dc02bf69def7fbffdfffe662751513f19ad57e17d4b93ba1e484fc1980d5
 * echo -n "abcdefghijklmnopqrstuvwxyz" | openssl dgst -sha3-384
 * (stdin)= fed399d2217aaf4c717ad0c5102c15589e1c990cc2b9a5029056a7f7485888d6ab65db2370077a5cadb53fc9280d278f
 * echo -n "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" | openssl dgst -sha3-384
 * (stdin)= d5b972302f5080d0830e0de7b6b2cf383665a008f4c4f386a61112652c742d20cb45aa51bd4f542fc733e2719e999291
 * echo -n "12345678901234567890123456789012345678901234567890123456789012345678901234567890" | openssl dgst -sha3-384
 * (stdin)= 3c213a17f514638acb3bf17f109f3e24c16f9f14f085b52a2f2b81adc0db83df1a58db2ce013191b8ba72d8fae7e2a5e
 *
 * Algorithm: sha3-512
 * echo -n "" | openssl dgst -sha3-512
 * (stdin)= a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26
 * echo -n "a" | openssl dgst -sha3-512
 * (stdin)= 697f2d856172cb8309d6b8b97dac4de344b549d4dee61edfb4962d8698b7fa803f4f93ff24393586e28b5b957ac3d1d369420ce53332712f997bd336d09ab02a
 * echo -n "abc" | openssl dgst -sha3-512
 * (stdin)= b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0
 * echo -n "message digest" | openssl dgst -sha3-512
 * (stdin)= 3444e155881fa15511f57726c7d7cfe80302a7433067b29d59a71415ca9dd141ac892d310bc4d78128c98fda839d18d7f0556f2fe7acb3c0cda4bff3a25f5f59
 * echo -n "abcdefghijklmnopqrstuvwxyz" | openssl dgst -sha3-512
 * (stdin)= af328d17fa28753a3c9f5cb72e376b90440b96f0289e5703b729324a975ab384eda565fc92aaded143669900d761861687acdc0a5ffa358bd0571aaad80aca68
 * echo -n "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" | openssl dgst -sha3-512
 * (stdin)= d1db17b4745b255e5eb159f66593cc9c143850979fc7a3951796aba80165aab536b46174ce19e3f707f0e5c6487f5f03084bc0ec9461691ef20113e42ad28163
 * echo -n "12345678901234567890123456789012345678901234567890123456789012345678901234567890" | openssl dgst -sha3-512
 * (stdin)= 9524b9a5536b91069526b4f6196b7e9475b4da69e01f0c855797f224cd7335ddb286fd99b9b32ffe33b59ad424cc1744f6eb59137f5fb8601932e8a8af0ae930
 *
 * Algorithm: shake128
 * echo -n "" | openssl dgst -shake128
 * (stdin)= 7f9c2ba4e88f827d616045507605853e
 * echo -n "a" | openssl dgst -shake128
 * (stdin)= 85c8de88d28866bf0868090b3961162b
 * echo -n "abc" | openssl dgst -shake128
 * (stdin)= 5881092dd818bf5cf8a3ddb793fbcba7
 * echo -n "message digest" | openssl dgst -shake128
 * (stdin)= cbef732961b55b4c31396796577df491
 * echo -n "abcdefghijklmnopqrstuvwxyz" | openssl dgst -shake128
 * (stdin)= 961c919c0854576e561320e81514bf37
 * echo -n "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" | openssl dgst -shake128
 * (stdin)= 54dd201e53249910db3c7d366574fbb6
 * echo -n "12345678901234567890123456789012345678901234567890123456789012345678901234567890" | openssl dgst -shake128
 * (stdin)= 7bf451c92fdc77b9771e6c9056445894
 *
 * Algorithm: shake256
 * echo -n "" | openssl dgst -shake256
 * (stdin)= 46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f
 * echo -n "a" | openssl dgst -shake256
 * (stdin)= 867e2cb04f5a04dcbd592501a5e8fe9ceaafca50255626ca736c138042530ba4
 * echo -n "abc" | openssl dgst -shake256
 * (stdin)= 483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739
 * echo -n "message digest" | openssl dgst -shake256
 * (stdin)= 718e224088856840ade4dc73487e15826a07ecb8ed5e2bda526cc1acddb99d00
 * echo -n "abcdefghijklmnopqrstuvwxyz" | openssl dgst -shake256
 * (stdin)= b7b78b04a3dd30a265c8886c33fda94799853de5d3d10541fd4e9f4613701c61
 * echo -n "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" | openssl dgst -shake256
 * (stdin)= 31f19a097c723e91fa59b0998dd8523c2a9e7e13b4025d6b48fcbc328973a108
 * echo -n "12345678901234567890123456789012345678901234567890123456789012345678901234567890" | openssl dgst -shake256
 * (stdin)= 24c508adefdf5e3f2596e8b5a888fe10eb7b5b22e1f35d858e6eff3025c4cc18
 */

struct HASH_ITEM sha3_224_hashes[] =
{
    { /* 0 */
        "",
        0,
        "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
    },
    { /* 1 */
        "a",
        1,
        "9e86ff69557ca95f405f081269685b38e3a819b309ee942f482b6a8b"
    },
    { /* 2 */
        "abc",
        3,
        "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"
    },
    { /* 3 */
        "message digest",
        14,
        "18768bb4c48eb7fc88e5ddb17efcf2964abd7798a39d86a4b4a1e4c8"
    },
    { /* 4 */
        "abcdefghijklmnopqrstuvwxyz",
        26,
        "5cdeca81e123f87cad96b9cba999f16f6d41549608d4e0f4681b8239"
    },
    { /* 5 */
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        62,
        "a67c289b8250a6f437a20137985d605589a8c163d45261b15419556e"
    },
    { /* 6 */
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        80,
        "0526898e185869f91b3e2a76dd72a15dc6940a67c8164a044cd25cc8"
    },
    {   /* End */
        NULL, 0, ""
    }
};

struct HASH_ITEM sha3_256_hashes[] =
{
    { /* 0 */
        "",
        0,
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    },
    { /* 1 */
        "a",
        1,
        "80084bf2fba02475726feb2cab2d8215eab14bc6bdd8bfb2c8151257032ecd8b"
    },
    { /* 2 */
        "abc",
        3,
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    },
    { /* 3 */
        "message digest",
        14,
        "edcdb2069366e75243860c18c3a11465eca34bce6143d30c8665cefcfd32bffd"
    },
    { /* 4 */
        "abcdefghijklmnopqrstuvwxyz",
        26,
        "7cab2dc765e21b241dbc1c255ce620b29f527c6d5e7f5f843e56288f0d707521"
    },
    { /* 5 */
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        62,
        "a79d6a9da47f04a3b9a9323ec9991f2105d4c78a7bc7beeb103855a7a11dfb9f"
    },
    { /* 6 */
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        80,
        "293e5ce4ce54ee71990ab06e511b7ccd62722b1beb414f5ff65c8274e0f5be1d"
    },
    {   /* End */
        NULL, 0, ""
    }
};

struct HASH_ITEM sha3_384_hashes[] =
{
    { /* 0 */
        "",
        0,
        "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    },
    { /* 1 */
        "a",
        1,
        "1815f774f320491b48569efec794d249eeb59aae46d22bf77dafe25c5edc28d7ea44f93ee1234aa88f61c91912a4ccd9"
    },
    { /* 2 */
        "abc",
        3,
        "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"
    },
    { /* 3 */
        "message digest",
        14,
        "d9519709f44af73e2c8e291109a979de3d61dc02bf69def7fbffdfffe662751513f19ad57e17d4b93ba1e484fc1980d5"
    },
    { /* 4 */
        "abcdefghijklmnopqrstuvwxyz",
        26,
        "fed399d2217aaf4c717ad0c5102c15589e1c990cc2b9a5029056a7f7485888d6ab65db2370077a5cadb53fc9280d278f"
    },
    { /* 5 */
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        62,
        "d5b972302f5080d0830e0de7b6b2cf383665a008f4c4f386a61112652c742d20cb45aa51bd4f542fc733e2719e999291"
    },
    { /* 6 */
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        80,
        "3c213a17f514638acb3bf17f109f3e24c16f9f14f085b52a2f2b81adc0db83df1a58db2ce013191b8ba72d8fae7e2a5e"
    },
    {   /* End */
        NULL, 0, ""
    }
};

struct HASH_ITEM sha3_512_hashes[] =
{
    { /* 0 */
        "",
        0,
        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    },
    { /* 1 */
        "a",
        1,
        "697f2d856172cb8309d6b8b97dac4de344b549d4dee61edfb4962d8698b7fa803f4f93ff24393586e28b5b957ac3d1d369420ce53332712f997bd336d09ab02a"
    },
    { /* 2 */
        "abc",
        3,
        "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
    },
    { /* 3 */
        "message digest",
        14,
        "3444e155881fa15511f57726c7d7cfe80302a7433067b29d59a71415ca9dd141ac892d310bc4d78128c98fda839d18d7f0556f2fe7acb3c0cda4bff3a25f5f59"
    },
    { /* 4 */
        "abcdefghijklmnopqrstuvwxyz",
        26,
        "af328d17fa28753a3c9f5cb72e376b90440b96f0289e5703b729324a975ab384eda565fc92aaded143669900d761861687acdc0a5ffa358bd0571aaad80aca68"
    },
    { /* 5 */
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        62,
        "d1db17b4745b255e5eb159f66593cc9c143850979fc7a3951796aba80165aab536b46174ce19e3f707f0e5c6487f5f03084bc0ec9461691ef20113e42ad28163"
    },
    { /* 6 */
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        80,
        "9524b9a5536b91069526b4f6196b7e9475b4da69e01f0c855797f224cd7335ddb286fd99b9b32ffe33b59ad424cc1744f6eb59137f5fb8601932e8a8af0ae930"
    },
    {   /* End */
        NULL, 0, ""
    }
};

struct HASH_ITEM shake128_hashes[] =
{
    { /* 0 */
        "",
        0,
        "7f9c2ba4e88f827d616045507605853e"
    },
    { /* 1 */
        "a",
        1,
        "85c8de88d28866bf0868090b3961162b"
    },
    { /* 2 */
        "abc",
        3,
        "5881092dd818bf5cf8a3ddb793fbcba7"
    },
    { /* 3 */
        "message digest",
        14,
        "cbef732961b55b4c31396796577df491"
    },
    { /* 4 */
        "abcdefghijklmnopqrstuvwxyz",
        26,
        "961c919c0854576e561320e81514bf37"
    },
    { /* 5 */
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        62,
        "54dd201e53249910db3c7d366574fbb6"
    },
    { /* 6 */
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        80,
        "7bf451c92fdc77b9771e6c9056445894"
    },
    {   /* End */
        NULL, 0, ""
    }
};

struct HASH_ITEM shake256_hashes[] =
{
    { /* 0 */
        "",
        0,
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
    },
    { /* 1 */
        "a",
        1,
        "867e2cb04f5a04dcbd592501a5e8fe9ceaafca50255626ca736c138042530ba4"
    },
    { /* 2 */
        "abc",
        3,
        "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
    },
    { /* 3 */
        "message digest",
        14,
        "718e224088856840ade4dc73487e15826a07ecb8ed5e2bda526cc1acddb99d00"
    },
    { /* 4 */
        "abcdefghijklmnopqrstuvwxyz",
        26,
        "b7b78b04a3dd30a265c8886c33fda94799853de5d3d10541fd4e9f4613701c61"
    },
    { /* 5 */
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        62,
        "31f19a097c723e91fa59b0998dd8523c2a9e7e13b4025d6b48fcbc328973a108"
    },
    { /* 6 */
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        80,
        "24c508adefdf5e3f2596e8b5a888fe10eb7b5b22e1f35d858e6eff3025c4cc18"
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
        case SHA3_224:
            printf("Internal hash tests for %s(SHA3-224):\n", argv0);
            tests = sha3_224_hashes;
            break;
        case SHA3_256:
            printf("Internal hash tests for %s(SHA3-256):\n", argv0);
            tests = sha3_256_hashes;
            break;
        case SHA3_384:
            printf("Internal hash tests for %s(SHA3-384):\n", argv0);
            tests = sha3_384_hashes;
            break;
        case SHA3_512:
            printf("Internal hash tests for %s(SHA3-512):\n", argv0);
            tests = sha3_512_hashes;
            break;
        case SHAKE128:
            printf("Internal hash tests for %s(SHAKE128):\n", argv0);
            tests = shake128_hashes;
            break;
        case SHAKE256:
            printf("Internal hash tests for %s(SHAKE256):\n", argv0);
            tests = shake256_hashes;
            break;
        default:
            printf("Internal hash tests for %s(SHA3-512):\n", argv0);
            tests = sha3_512_hashes;
            break;
    }

    for (item=tests; item->str != NULL; item++)
    {
        printf("%s(\"%s\")\n", argv0, item->str);
        if ((ctx->alg == SHAKE128) || (ctx->alg == SHAKE256))
        {
            ctx->hash_ex(ctx->alg, (unsigned char *)item->str, item->len, ctx->md, ctx->ext);
        }
        else
        {
            ctx->hash(ctx->alg, (unsigned char*)item->str, item->len, ctx->md);
        }

        printf("     Expect: %s\n", item->md);
        printf("     Result: ");
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

    if ((ctx->alg == SHAKE128) || (ctx->alg == SHAKE256))
    {
        ctx->hash_ex(ctx->alg, string, len, ctx->md, ctx->ext);
    }
    else
    {
        ctx->hash(ctx->alg, string, len, ctx->md);
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
        if ((ctx->alg == SHAKE128) || (ctx->alg == SHAKE256))
        {
            ctx->init_ex(&ctx->impl, ctx->alg, ctx->ext);
        }
        else
        {
            ctx->init(&ctx->impl, ctx->alg);
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
    unsigned char buf[FILE_BLOCK_SIZE];

    if ((ctx->alg == SHAKE128) || (ctx->alg == SHAKE256))
    {
        ctx->init_ex(&ctx->impl, ctx->alg, ctx->ext);
    }
    else
    {
        ctx->init(&ctx->impl, ctx->alg);
    }

    while ((len = fread(buf, 1, FILE_BLOCK_SIZE, stdin)))
    {
        ctx->update(&ctx->impl, buf, len);
    }
    ctx->final(ctx->md, &ctx->impl);

    printf("%s(stdin) = ", argv0);
    print_digest(ctx->md, ctx->md_size);
    printf("\n");
}

/*
 * $ sha3 -h
 * Usage:
 * Common options: [-a sha3-224|sha3-256|sha3-384|sha3-512|shake128|shake256 [-d num]] [-x|-f file|-s string|-h]
 * Hash a string:
 *         sha3 -a [sha3-224|sha3-256|sha3-384|sha3-512|shake128|shake256] [-d num] -s string
 * Hash a file:
 *         sha3 -a [sha3-224|sha3-256|sha3-384|sha3-512|shake128|shake256] [-d num] -f file
 * -a      Secure hash algorithm: "sha3-224|sha3-256|sha3-384|sha3-512|shake128|shake256". Default: sha3-256
 * -d      Digest length for shake128/shake256, required. Default: num=128[shake128], num=256[shake256]
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

    /* d value for SHAKE128/SHAKE256 */
    uint32_t d = 0;

    char alg[HASH_NAME_SIZE];
    uint32_t alg_len = 0;

    char *str = NULL;
    uint32_t len = 0;

    char *filename = NULL;

    HASH_CTX ctx;
    memset(&ctx, 0, sizeof(HASH_CTX));

    while ((ch = getopt(argc, argv, "a:s:f:d:xh")) != -1)
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
            case 'd':
                d = atoi(optarg);
                if (d%8)
                {
                    usage(argv[0]);
                }
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
    ctx.init = SHA3_Init;
    ctx.update = SHA3_Update;
    ctx.final = SHA3_Final;
    ctx.hash = SHA3;
    ctx.ext = 0;
    if ((strncmp(alg, "sha3-224", alg_len) == 0))
    {
        ctx.alg = SHA3_224;
        ctx.md_size = SHA3_224_DIGEST_SIZE;
    }
    else if ((NULL == alg) || (strncmp(alg, "sha3-256", alg_len) == 0))
    {
        ctx.alg = SHA3_256;
        ctx.md_size = SHA3_256_DIGEST_SIZE;
    }
    else if (strncmp(alg, "sha3-384", alg_len) == 0)
    {
        ctx.alg = SHA3_384;
        ctx.md_size = SHA3_384_DIGEST_SIZE;
    }
    else if (strncmp(alg, "sha3-512", alg_len) == 0)
    {
        ctx.alg = SHA3_512;
        ctx.md_size = SHA3_512_DIGEST_SIZE;
    }
    else if ((strncmp(alg, "shake128", alg_len) == 0) ||
            (strncmp(alg, "shake256", alg_len) == 0))
    {
        if (strncmp(alg, "shake128", alg_len) == 0)
        {
            ctx.alg = SHAKE128;
            if (d == 0)  /* 't' is not set, set to 128 bits, same as 'openssl dgst -shake128' */
                d = 128;
        }
        else
        {
            ctx.alg = SHAKE256;
            if (d == 0)  /* 't' is not set, set to 256 bits, same as 'openssl dgst -shake256' */
                d = 256;
        }

        ctx.ext = d;
        ctx.md_size = d / 8;
        ctx.init = NULL;
        ctx.update = SHA3_XOF_Update;
        ctx.final = SHA3_XOF_Final;
        ctx.hash = NULL;

        ctx.init_ex = SHA3_XOF_Init;
        ctx.hash_ex = SHA3_XOF;
    }
    else
    {
        usage(argv[0]);
    }

    /* allocate buffer for message digest */
    ctx.md = (unsigned char *)malloc(ctx.md_size);
    memset(ctx.md, 0, ctx.md_size);

    if (hash_internal)
    {
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

    free(ctx.md);
    ctx.md = NULL;

    return 0;
}
