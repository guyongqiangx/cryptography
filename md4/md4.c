/*
 * @        file: md4.c
 * @ description: implementation for the MD4 Message-Digest Algorithm
 * @      author: Gu Yongqiang
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#include <stdio.h>
#include <string.h>

#include "utils.h"
#include "md4.h"

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

#define MD4_BLOCK_SIZE          64  /* 512 bits = 64 bytes */
#define MD4_LEN_SIZE            8   /*  64 bits =  8 bytes */
#define MD4_LEN_OFFSET          (MD4_BLOCK_SIZE - MD4_LEN_SIZE)
#define MD4_DIGEST_SIZE 16  /* 128 bits = 16 bytes */

#define MD4_PADDING_PATTERN     0x80
#define MD4_ROUND_NUM           64

#define HASH_BLOCK_SIZE         MD4_BLOCK_SIZE
#define HASH_LEN_SIZE           MD4_LEN_SIZE
#define HASH_LEN_OFFSET         MD4_LEN_OFFSET
#define HASH_DIGEST_SIZE        MD4_DIGEST_SIZE

#define HASH_PADDING_PATTERN    MD4_PADDING_PATTERN
#define HASH_ROUND_NUM          MD4_ROUND_NUM

typedef uint32_t (*md4_func)(uint32_t x, uint32_t y, uint32_t z);

/* MD4 Round Constants, refer rfc1320, section 3.4 */
static uint32_t T[3] =
{
    0x00000000, /* Round 1( 0 ~ 15), placeholder of T[idx/16] in MD4_OP */
    0x5A827999, /* Round 2(16 ~ 31), square root of 2 */
    0x6ED9EBA1, /* Round 3(32 ~ 47), square root of 3 */
};

/* ROTate Left (circular left shift) */
static uint32_t ROTL(uint32_t x, uint8_t shift)
{
    return (x << shift) | (x >> (32 - shift));
}

/*
 * F/G/H definition, refer rfc1320, section 3.4
 */

/*
 * Condition
 * In each bit position, F acts as a conditional:
 *   if X then Y else Z.
 */
static uint32_t F(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) | ((~x) & z);
}

/*
 * Majority
 * In each bit position, G acts as a majority function:
 *   if at least two of X, Y, Z are on, then G has a "1" bit in that bit position, else G has a "0" bit.
 */
static uint32_t G(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) | (x & z) | (y & z);
}

/*
 * Parity
 * H is the bit-wise XOR or "parity" function
 */
static uint32_t H(uint32_t x, uint32_t y, uint32_t z)
{
    return x ^ y ^ z;
}

/* MD4 Functions */
static md4_func g[3] =
{
    F,  /*  0 ~ 15 operations */
    G,  /* 16 ~ 31 operations */
    H   /* 32 ~ 47 operations */
};

int MD4_Init(MD4_CTX *c)
{
    if (NULL == c)
    {
        return ERR_INV_PARAM;
    }

    memset(c, 0, sizeof(MD4_CTX));

    /* MD4 Initial Value, refer rfc1320, section 3.3 */
    c->hash.a = 0x67452301; /* little endian */
    c->hash.b = 0xEFCDAB89;
    c->hash.c = 0x98BADCFE;
    c->hash.d = 0x10325476;

    c->total = 0;
    c->last.used = 0;

    return ERR_OK;
}

static int MD4_PrepareScheduleWord(const uint32_t *block, uint32_t *X)
{
    uint32_t i;

    if ((NULL == block) || (NULL == X))
    {
        return ERR_INV_PARAM;
    }

    for (i=0; i<HASH_BLOCK_SIZE/4; i++)
    {
        X[i] = le32toh(block[i]);
    }

    return ERR_OK;
}

#if (DUMP_ROUND_DATA == 1)
#define MD4_OP(a,b,c,d,k,s) \
    a = ROTL(a + (g[idx/16])(b, c, d) + X[k] + T[idx/16], s); \
    DBG("      %02d: a=0x%08x, b=0x%08x, c=0x%08x, d=0x%08x, X=0x%08x, T=0x%08x\n", idx, a, b, c, d, X[k], T[idx/16]); \
    idx ++;
#else
#define MD4_OP(a,b,c,d,k,s) \
    a = ROTL(a + (g[idx/16])(b, c, d) + X[k] + T[idx/16], s); \
    idx ++;
#endif

/* Process Message in 16-Word Blocks, refer rfc1320, section 3.4 */
static int MD4_ProcessBlock(MD4_CTX *ctx, const void *block)
{
    uint32_t X[HASH_BLOCK_SIZE/4];
    uint32_t A, B, C, D;
    uint32_t idx;

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

#if (DUMP_BLOCK_HASH == 1)
    DBG("  (LE)IV: %08x %08x %08x %08x\n",
        ctx->hash.a, ctx->hash.b, ctx->hash.c, ctx->hash.d);
#endif

    /* Copy block into X */
    MD4_PrepareScheduleWord(block, X);

    A = ctx->hash.a;
    B = ctx->hash.b;
    C = ctx->hash.c;
    D = ctx->hash.d;

    idx = 0;

    /* Round 1 */
    MD4_OP(A, B, C, D,  0,  3); MD4_OP(D, A, B, C,  1,  7); MD4_OP(C, D, A, B,  2, 11); MD4_OP(B, C, D, A,  3, 19);
    MD4_OP(A, B, C, D,  4,  3); MD4_OP(D, A, B, C,  5,  7); MD4_OP(C, D, A, B,  6, 11); MD4_OP(B, C, D, A,  7, 19);
    MD4_OP(A, B, C, D,  8,  3); MD4_OP(D, A, B, C,  9,  7); MD4_OP(C, D, A, B, 10, 11); MD4_OP(B, C, D, A, 11, 19);
    MD4_OP(A, B, C, D, 12,  3); MD4_OP(D, A, B, C, 13,  7); MD4_OP(C, D, A, B, 14, 11); MD4_OP(B, C, D, A, 15, 19);

    /* Round 2 */
    MD4_OP(A, B, C, D,  0,  3); MD4_OP(D, A, B, C,  4,  5); MD4_OP(C, D, A, B,  8,  9); MD4_OP(B, C, D, A, 12, 13);
    MD4_OP(A, B, C, D,  1,  3); MD4_OP(D, A, B, C,  5,  5); MD4_OP(C, D, A, B,  9,  9); MD4_OP(B, C, D, A, 13, 13);
    MD4_OP(A, B, C, D,  2,  3); MD4_OP(D, A, B, C,  6,  5); MD4_OP(C, D, A, B, 10,  9); MD4_OP(B, C, D, A, 14, 13);
    MD4_OP(A, B, C, D,  3,  3); MD4_OP(D, A, B, C,  7,  5); MD4_OP(C, D, A, B, 11,  9); MD4_OP(B, C, D, A, 15, 13);

    /* Round 3 */
    MD4_OP(A, B, C, D,  0,  3); MD4_OP(D, A, B, C,  8,  9); MD4_OP(C, D, A, B,  4, 11); MD4_OP(B, C, D, A, 12, 15);
    MD4_OP(A, B, C, D,  2,  3); MD4_OP(D, A, B, C, 10,  9); MD4_OP(C, D, A, B,  6, 11); MD4_OP(B, C, D, A, 14, 15);
    MD4_OP(A, B, C, D,  1,  3); MD4_OP(D, A, B, C,  9,  9); MD4_OP(C, D, A, B,  5, 11); MD4_OP(B, C, D, A, 13, 15);
    MD4_OP(A, B, C, D,  3,  3); MD4_OP(D, A, B, C, 11,  9); MD4_OP(C, D, A, B,  7, 11); MD4_OP(B, C, D, A, 15, 15);

    ctx->hash.a += A;
    ctx->hash.b += B;
    ctx->hash.c += C;
    ctx->hash.d += D;

#if (DUMP_BLOCK_HASH == 1)
    DBG(" (LE)OUT: %08x %08x %08x %08x\n",
        ctx->hash.a, ctx->hash.b, ctx->hash.c, ctx->hash.d);
#endif

    return ERR_OK;
}

int MD4_Update(MD4_CTX *c, const void *data, unsigned long len)
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
            MD4_ProcessBlock(c, &c->last.buf);

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
            MD4_ProcessBlock(c, data);
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

int MD4_Final(unsigned char *md, MD4_CTX *c)
{
    uint32_t *temp;

    if ((NULL == c) || (NULL == md))
    {
        return ERR_INV_PARAM;
    }

    /* Last block should be less than HASH_BLOCK_SIZE - HASH_LEN_SIZE */
    if (c->last.used >= (HASH_BLOCK_SIZE - HASH_LEN_SIZE))
    {
        c->total += c->last.used;

        /* one more block */
        c->last.buf[c->last.used] = HASH_PADDING_PATTERN;
        c->last.used++;

        memset(&c->last.buf[c->last.used], 0, HASH_BLOCK_SIZE - c->last.used);
        MD4_ProcessBlock(c, &c->last.buf);

        memset(&c->last.buf[0], 0, HASH_BLOCK_SIZE - HASH_LEN_SIZE);
        c->last.used = 0;

        /* save length */
        temp = (uint32_t *)&(c->last.buf[HASH_LEN_OFFSET]);
        temp[0] = htole32((c->total << 3) & 0xFFFFFFFF);
        temp[1] = htole32(((c->total << 3) >> 32) & 0xFFFFFFFF);

        MD4_ProcessBlock(c, &c->last.buf);
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
        temp = (uint32_t *)&(c->last.buf[HASH_LEN_OFFSET]);
        temp[0] = htole32((c->total << 3) & 0xFFFFFFFF);
        temp[1] = htole32(((c->total << 3) >> 32) & 0xFFFFFFFF);

        MD4_ProcessBlock(c, &c->last.buf);
    }

    /* LE for MD4/MD5, different from SHA family(Big Endian) */
    temp = (uint32_t *)md;
    temp[0] = htole32(c->hash.a);
    temp[1] = htole32(c->hash.b);
    temp[2] = htole32(c->hash.c);
    temp[3] = htole32(c->hash.d);

    return ERR_OK;
}

unsigned char *MD4(const unsigned char *d, unsigned long n, unsigned char *md)
{
    MD4_CTX c;

    if ((NULL == d) || (NULL == md))
    {
        return NULL;
    }

    MD4_Init(&c);
    MD4_Update(&c, d, n);
    MD4_Final(md, &c);

    return md;
}
