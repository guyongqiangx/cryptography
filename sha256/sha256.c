/*
 * @        file: sha256.c
 * @ description: implementation for the SHA224/SHA256 Secure Hash Algorithm
 * @      author: Gu Yongqiang
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#include <stdio.h>
#include <string.h>

#include "utils.h"
#include "sha256.h"

//#define DEBUG

#ifdef DEBUG
#define DBG(...) printf(__VA_ARGS__)
#define DUMP_BLOCK_DATA 1
#define DUMP_BLOCK_HASH 1
#define DUMP_ROUND_DATA 1
#else
#define DBG(...)
#define DUMP_BLOCK_DATA 0
#define DUMP_BLOCK_HASH 0
#define DUMP_ROUND_DATA 0
#endif

#define SHA256_BLOCK_SIZE           64  /* 512 bits = 64 Bytes */
#define SHA256_LEN_SIZE             8   /* 64 bits = 8 bytes */
#define SHA256_LEN_OFFSET           (SHA256_BLOCK_SIZE - SHA256_LEN_SIZE)

#define SHA256_DIGEST_SIZE          32 /* 256 bits = 32 bytes */
#define SHA224_DIGEST_SIZE          28 /* 224 bits = 28 bytes */

#define SHA256_PADDING_PATTERN      0x80
#define SHA256_ROUND_NUM            64

#define HASH_BLOCK_SIZE             SHA256_BLOCK_SIZE
#define HASH_LEN_SIZE               SHA256_LEN_SIZE
#define HASH_LEN_OFFSET             SHA256_LEN_OFFSET

#define HASH_DIGEST_SIZE            SHA256_DIGEST_SIZE      /* use sha256 digest size */

#define HASH_PADDING_PATTERN        SHA256_PADDING_PATTERN
#define HASH_ROUND_NUM              SHA256_ROUND_NUM

/* SHA256 Constants */
static const uint32_t K256[HASH_ROUND_NUM] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* ROTate Right (cirular right shift) */
static uint32_t ROTR(uint32_t x, uint8_t shift)
{
    return (x >> shift) | (x << (32 - shift));
}

/* Right SHift */
static uint32_t SHR(uint32_t x, uint8_t shift)
{
    return (x >> shift);
}

/* Ch ... choose */
static uint32_t Ch(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (~x & z) ;
}

/* Maj ... majority */
static uint32_t Maj(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

/* SIGMA0 */
static uint32_t SIGMA0(uint32_t x)
{
    return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
}

/* SIGMA1 */
static uint32_t SIGMA1(uint32_t x)
{
    return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
}

/* sigma0, different from SIGMA0 */
static uint32_t sigma0(uint32_t x)
{
    return ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3);
}

/* sigma1, different from SIGMA1 */
static uint32_t sigma1(uint32_t x)
{
    return ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10);
}

int SHA256_Init(SHA256_CTX *c)
{
    if (NULL == c)
    {
        return ERR_INV_PARAM;
    }

    memset(c, 0, sizeof(SHA256_CTX));

    /* Initial Value for SHA256 */
    c->hash.a = 0x6a09e667;
    c->hash.b = 0xbb67ae85;
    c->hash.c = 0x3c6ef372;
    c->hash.d = 0xa54ff53a;
    c->hash.e = 0x510e527f;
    c->hash.f = 0x9b05688c;
    c->hash.g = 0x1f83d9ab;
    c->hash.h = 0x5be0cd19;

    return ERR_OK;
}

static int SHA256_PrepareScheduleWord(const uint32_t *block, uint32_t *W)
{
    uint32_t t;

    if ((NULL == block) || (NULL == W))
    {
        return ERR_INV_PARAM;
    }

    for (t=0; t<HASH_ROUND_NUM; t++)
    {
        if (t<=15)  /*  0 <= t <= 15 */
            W[t] = be32toh(block[t]);
        else        /* 16 <= t <= 79 */
            W[t] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16];
    }

    return ERR_OK;
}

static int SHA256_ProcessBlock(SHA256_CTX *ctx, const void *block)
{
    uint32_t t;
    uint32_t W[HASH_ROUND_NUM];
    uint32_t T1, T2;
    uint32_t a, b, c, d, e, f, g, h;

    if ((NULL == ctx) || (NULL == block))
    {
        return ERR_INV_PARAM;
    }

#if (DUMP_BLOCK_DATA == 1)
    DBG("---------------------------------------------------------\n");
    DBG("   BLOCK: %llu\n", ctx->total/HASH_BLOCK_SIZE);
    DBG("    DATA:\n");
    print_buffer(block, HASH_BLOCK_SIZE, "    ");
#endif

    /* prepare schedule word */
    SHA256_PrepareScheduleWord(block, W);

    a = ctx->hash.a;
    b = ctx->hash.b;
    c = ctx->hash.c;
    d = ctx->hash.d;
    e = ctx->hash.e;
    f = ctx->hash.f;
    g = ctx->hash.g;
    h = ctx->hash.h;

#if (DUMP_BLOCK_HASH == 1)
    DBG("      IV: %08x %08x %08x %08x %08x %08x %08x %08x\n",
        ctx->hash.a, ctx->hash.b, ctx->hash.c, ctx->hash.d, ctx->hash.e, ctx->hash.f, ctx->hash.g, ctx->hash.h);
#endif

    for (t=0; t<HASH_ROUND_NUM; t++)
    {
        T1 = h + SIGMA1(e) + Ch(e, f, g) + K256[t] + W[t];
        T2 = SIGMA0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;

#if (DUMP_ROUND_DATA == 1)
        DBG("      %02d: T1=0x%08x, T2=0x%08x, W=0x%08x, \n"\
            "           a=0x%08x,  b=0x%08x, c=0x%08x, d=0x%08x, e=0x%08x, f=0x%08x, g=0x%08x, h=0x%08x\n", \
                t, T1, T2, W[t], a, b, c, d, e, f, g, h);
#endif
    }

    ctx->hash.a += a;
    ctx->hash.b += b;
    ctx->hash.c += c;
    ctx->hash.d += d;
    ctx->hash.e += e;
    ctx->hash.f += f;
    ctx->hash.g += g;
    ctx->hash.h += h;

#if (DUMP_BLOCK_HASH == 1)
    DBG("    HASH: %08x %08x %08x %08x %08x %08x %08x %08x\n",
        ctx->hash.a, ctx->hash.b, ctx->hash.c, ctx->hash.d, ctx->hash.e, ctx->hash.f, ctx->hash.g, ctx->hash.h);
#endif

    return ERR_OK;
}


int SHA256_Update(SHA256_CTX *c, const void *data, size_t len)
{
    uint32_t copy_len = 0;

    if ((NULL == c) || (NULL == data))
    {
        return ERR_INV_PARAM;
    }

    /* has used data */
    if (c->last.used != 0)
    {
        /* less than 1 block in total, combine data */
        if (c->last.used + len < HASH_BLOCK_SIZE)
        {
            memcpy(&c->last.buf[c->last.used], data, len);
            c->last.used += len;

            return ERR_OK;
        }
        else /* more than 1 block */
        {
            /* process the block in context buffer */
            copy_len = HASH_BLOCK_SIZE - c->last.used;
            memcpy(&c->last.buf[c->last.used], data, copy_len);
            SHA256_ProcessBlock(c, &c->last.buf);
            c->total += HASH_BLOCK_SIZE;

            data = (uint8_t *)data + copy_len;
            len -= copy_len;

            /* reset context buffer */
            memset(&c->last.buf[0], 0, HASH_BLOCK_SIZE);
            c->last.used = 0;
        }
    }

    /* less than 1 block, copy to context buffer */
    if (len < HASH_BLOCK_SIZE)
    {
        memcpy(&c->last.buf[c->last.used], data, len);
        c->last.used += len;

        return ERR_OK;
    }
    else
    {
        /* process data blocks */
        while (len >= HASH_BLOCK_SIZE)
        {
            SHA256_ProcessBlock(c, data);
            c->total += HASH_BLOCK_SIZE;

            data = (uint8_t *)data + HASH_BLOCK_SIZE;
            len -= HASH_BLOCK_SIZE;
        }

        /* copy rest data to context buffer */
        memcpy(&c->last.buf[0], data, len);
        c->last.used = len;
    }

    return ERR_OK;
}

int SHA256_Final(unsigned char *md, SHA256_CTX *c)
{
    uint32_t *temp;
    //uint64_t *buf;

    if ((NULL == c) || (NULL == md))
    {
        return ERR_INV_PARAM;
    }

    /* Last block should be less thant HASH_BLOCK_SIZE - HASH_LEN_SIZE */
    if (c->last.used >= (HASH_BLOCK_SIZE - HASH_LEN_SIZE))
    {
        c->total += c->last.used;

        /* one more block */
        c->last.buf[c->last.used] = HASH_PADDING_PATTERN;
        c->last.used++;

        memset(&c->last.buf[c->last.used], 0, HASH_BLOCK_SIZE - c->last.used);
        SHA256_ProcessBlock(c, &c->last.buf);

        memset(&c->last.buf[0], 0, HASH_BLOCK_SIZE - HASH_LEN_SIZE);
        c->last.used = 0;

        /* save length */
        //buf = (uint64_t *)&(c->last.buf[HASH_LEN_OFFSET]);
        //*buf = htobe64(c->total << 3);
        temp = (uint32_t *)&(c->last.buf[HASH_LEN_OFFSET]);
        temp[0] = htobe32((c->total << 3) >> 32 & 0xFFFFFFFF);
        temp[1] = htobe32((c->total << 3) & 0xFFFFFFFF);

        SHA256_ProcessBlock(c, &c->last.buf);
    }
    else /* 0 <= last.used < HASH_BLOCK_SIZE - HASH_LEN_SIZE */
    {
        c->total += c->last.used;

        /* one more block */
        c->last.buf[c->last.used] = HASH_PADDING_PATTERN;
        c->last.used++;

        /* padding 0s */
        memset(&c->last.buf[c->last.used], 0, HASH_BLOCK_SIZE - HASH_LEN_SIZE - c->last.used);

        /* save length */
        //buf = (uint64_t *)&(c->last.buf[HASH_LEN_OFFSET]);
        //*buf = htobe64(c->total << 3);
        temp = (uint32_t *)&(c->last.buf[HASH_LEN_OFFSET]);
        temp[0] = htobe32((c->total << 3) >> 32 & 0xFFFFFFFF);
        temp[1] = htobe32((c->total << 3) & 0xFFFFFFFF);

        SHA256_ProcessBlock(c, &c->last.buf);
    }

    temp = (uint32_t *)md;
    temp[0] = htobe32(c->hash.a);
    temp[1] = htobe32(c->hash.b);
    temp[2] = htobe32(c->hash.c);
    temp[3] = htobe32(c->hash.d);
    temp[4] = htobe32(c->hash.e);
    temp[5] = htobe32(c->hash.f);
    temp[6] = htobe32(c->hash.g);
    temp[7] = htobe32(c->hash.h);

    return ERR_OK;
}

unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md)
{
    SHA256_CTX c;

    if ((NULL == d) || (NULL == md))
    {
        return NULL;
    }

    SHA256_Init(&c);
    SHA256_Update(&c, d, n);
    SHA256_Final(md, &c);

    return md;
}

int SHA224_Init(SHA256_CTX *c)
{
    if (NULL == c)
    {
        return ERR_INV_PARAM;
    }

    memset(c, 0, sizeof(SHA256_CTX));

    c->hash.a = 0xc1059ed8;
    c->hash.b = 0x367cd507;
    c->hash.c = 0x3070dd17;
    c->hash.d = 0xf70e5939;
    c->hash.e = 0xffc00b31;
    c->hash.f = 0x68581511;
    c->hash.g = 0x64f98fa7;
    c->hash.h = 0xbefa4fa4;

    return ERR_OK;
}

int SHA224_Update(SHA256_CTX *c, const void *data, size_t len)
{
    return SHA256_Update(c, data, len);
}

int SHA224_Final(unsigned char *md, SHA256_CTX *c)
{
    int rc = ERR_OK;
    unsigned char sha256_md[SHA256_DIGEST_SIZE];

    memset(&sha256_md, 0, sizeof(sha256_md));

    rc = SHA256_Final(sha256_md, c);

    memcpy(md, sha256_md, SHA224_DIGEST_SIZE);

    return rc;
}

unsigned char *SHA224(const unsigned char *d, size_t n, unsigned char *md)
{
    SHA256_CTX c;

    if ((NULL == d) || (NULL == md))
    {
        return NULL;
    }

    SHA224_Init(&c);
    SHA224_Update(&c, d, n);
    SHA224_Final(md, &c);

    return md;
}

