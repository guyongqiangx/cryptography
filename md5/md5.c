/*
 * @        file: md5.c
 * @ description: implementation for the MD5 Message-Digest Algorithm
 * @      author: Gu Yongqiang
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#include <stdio.h>
#include <string.h>

#include "utils.h"
#include "md5.h"

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

#define MD5_BLOCK_SIZE          64  /* 512 bits = 64 bytes */
#define MD5_LEN_SIZE            8   /*  64 bits =  8 bytes */
#define MD5_LEN_OFFSET          (MD5_BLOCK_SIZE - MD5_LEN_SIZE)
#define MD5_DIGEST_SIZE         16  /* 128 bits = 16 bytes */

#define MD5_PADDING_PATTERN     0x80
#define MD5_ROUND_NUM           64

#define HASH_BLOCK_SIZE         MD5_BLOCK_SIZE
#define HASH_LEN_SIZE           MD5_LEN_SIZE
#define HASH_LEN_OFFSET         MD5_LEN_OFFSET
#define HASH_DIGEST_SIZE        MD5_DIGEST_SIZE

#define HASH_PADDING_PATTERN    MD5_PADDING_PATTERN
#define HASH_ROUND_NUM          MD5_ROUND_NUM

typedef uint32_t (*md5_func)(uint32_t x, uint32_t y, uint32_t z);

/* MD5 Constants */
static uint32_t T[64] = 
{
    /* Round 1 */
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 

    /* Round 2 */
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 

    /* Round 3 */
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 

    /* Round 4 */
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391, 
};

/* ROTate Left (circular left shift) */
static uint32_t ROTL(uint32_t x, uint8_t shift)
{
    return (x << shift) | (x >> (32 - shift));
}

static uint32_t F(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) | ((~x) & z);
}

static uint32_t G(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & z) | (y & (~z));
}

static uint32_t H(uint32_t x, uint32_t y, uint32_t z)
{
    return x ^ y ^ z;
}

static uint32_t I(uint32_t x, uint32_t y, uint32_t z)
{
    return y ^ (x | (~z));;
}

/* MD5 Functions */
static md5_func g[4] =
{
    F, G, H, I
};

int MD5_Init(MD5_CTX *c)
{
    if (NULL == c)
    {
        return ERR_INV_PARAM;
    }

    memset(c, 0, sizeof(MD5_CTX));

    c->hash.a = 0x67452301; /* little endian */
    c->hash.b = 0xEFCDAB89;
    c->hash.c = 0x98BADCFE;
    c->hash.d = 0x10325476;

    c->total = 0;
    c->last.used = 0;

    return ERR_OK;
}

static int MD5_PrepareScheduleWord(const uint32_t *block, uint32_t *W)
{
    uint32_t i;

    if ((NULL == block) || (NULL == W))
    {
        return ERR_INV_PARAM;
    }

    for (i=0; i<16; i++)
    {
        W[i] = le32toh(block[i]);
    }

    return ERR_OK;
}

#if (DUMP_ROUND_DATA == 1)
#define MD5_OP(a,b,c,d,k,s,i) \
    a = b + ROTL(a + (g[(i-1)/16])(b, c, d) + X[k] + T[i-1], s); \
    DBG("      %02d: a=0x%08x, b=0x%08x, c=0x%08x, d=0x%08x, X=0x%08x, T=0x%08x\n", i-1, a, b, c, d, X[k], T[i-1]);
#else
#define MD5_OP(a,b,c,d,k,s,i) \
    a = b + ROTL(a + (g[(i-1)/16])(b, c, d) + X[k] + T[i-1], s);
#endif

static int MD5_ProcessBlock(MD5_CTX *ctx, const void *block)
{
    uint32_t X[16];
    uint32_t a, b, c, d;

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

    /* prepare schedule word */
    MD5_PrepareScheduleWord(block, X);

    a = ctx->hash.a;
    b = ctx->hash.b;
    c = ctx->hash.c;
    d = ctx->hash.d;

    /* Round 1 */
    MD5_OP(a, b, c, d,  0,  7,  1); MD5_OP(d, a, b, c,  1, 12,  2); MD5_OP(c, d, a, b,  2, 17,  3); MD5_OP(b, c, d, a,  3, 22,  4);
    MD5_OP(a, b, c, d,  4,  7,  5); MD5_OP(d, a, b, c,  5, 12,  6); MD5_OP(c, d, a, b,  6, 17,  7); MD5_OP(b, c, d, a,  7, 22,  8);
    MD5_OP(a, b, c, d,  8,  7,  9); MD5_OP(d, a, b, c,  9, 12, 10); MD5_OP(c, d, a, b, 10, 17, 11); MD5_OP(b, c, d, a, 11, 22, 12);
    MD5_OP(a, b, c, d, 12,  7, 13); MD5_OP(d, a, b, c, 13, 12, 14); MD5_OP(c, d, a, b, 14, 17, 15); MD5_OP(b, c, d, a, 15, 22, 16);

    /* Round 2 */
    MD5_OP(a, b, c, d,  1,  5, 17); MD5_OP(d, a, b, c,  6,  9, 18); MD5_OP(c, d, a, b, 11, 14, 19); MD5_OP(b, c, d, a,  0, 20, 20);
    MD5_OP(a, b, c, d,  5,  5, 21); MD5_OP(d, a, b, c, 10,  9, 22); MD5_OP(c, d, a, b, 15, 14, 23); MD5_OP(b, c, d, a,  4, 20, 24);
    MD5_OP(a, b, c, d,  9,  5, 25); MD5_OP(d, a, b, c, 14,  9, 26); MD5_OP(c, d, a, b,  3, 14, 27); MD5_OP(b, c, d, a,  8, 20, 28);
    MD5_OP(a, b, c, d, 13,  5, 29); MD5_OP(d, a, b, c,  2,  9, 30); MD5_OP(c, d, a, b,  7, 14, 31); MD5_OP(b, c, d, a, 12, 20, 32);

    /* Round 3 */
    MD5_OP(a, b, c, d,  5,  4, 33); MD5_OP(d, a, b, c,  8, 11, 34); MD5_OP(c, d, a, b, 11, 16, 35); MD5_OP(b, c, d, a, 14, 23, 36);
    MD5_OP(a, b, c, d,  1,  4, 37); MD5_OP(d, a, b, c,  4, 11, 38); MD5_OP(c, d, a, b,  7, 16, 39); MD5_OP(b, c, d, a, 10, 23, 40);
    MD5_OP(a, b, c, d, 13,  4, 41); MD5_OP(d, a, b, c,  0, 11, 42); MD5_OP(c, d, a, b,  3, 16, 43); MD5_OP(b, c, d, a,  6, 23, 44);
    MD5_OP(a, b, c, d,  9,  4, 45); MD5_OP(d, a, b, c, 12, 11, 46); MD5_OP(c, d, a, b, 15, 16, 47); MD5_OP(b, c, d, a,  2, 23, 48);

    /* Round 4 */
    MD5_OP(a, b, c, d,  0,  6, 49); MD5_OP(d, a, b, c,  7, 10, 50); MD5_OP(c, d, a, b, 14, 15, 51); MD5_OP(b, c, d, a,  5, 21, 52);
    MD5_OP(a, b, c, d, 12,  6, 53); MD5_OP(d, a, b, c,  3, 10, 54); MD5_OP(c, d, a, b, 10, 15, 55); MD5_OP(b, c, d, a,  1, 21, 56);
    MD5_OP(a, b, c, d,  8,  6, 57); MD5_OP(d, a, b, c, 15, 10, 58); MD5_OP(c, d, a, b,  6, 15, 59); MD5_OP(b, c, d, a, 13, 21, 60);
    MD5_OP(a, b, c, d,  4,  6, 61); MD5_OP(d, a, b, c, 11, 10, 62); MD5_OP(c, d, a, b,  2, 15, 63); MD5_OP(b, c, d, a,  9, 21, 64);

#if 0
    for (t=0; t<HASH_ROUND_NUM; t++)
    {
        T= b + ((a + (g[t/16])(b, c, d) + X[k] + T[t])<<<s)
        //T = ROTL(a, 5) + (F[t/20])(b, c, d) + e + K[t/20] + W[t];
        d = c;
        c = b;
        b = T;
        a = d;

#if (DUMP_ROUND_DATA == 1)
        DBG("      %02d: T=0x%08x, W=0x%08x, a=0x%08x, b=0x%08x, c=0x%08x, d=0x%08x\n",
                t, T, W[t], a, b, c, d);
#endif
    }
#endif

    ctx->hash.a += a;
    ctx->hash.b += b;
    ctx->hash.c += c;
    ctx->hash.d += d;
#if (DUMP_BLOCK_HASH == 1)
    DBG(" (LE)OUT: %08x %08x %08x %08x\n",
        ctx->hash.a, ctx->hash.b, ctx->hash.c, ctx->hash.d);
#endif

    return ERR_OK;
}

int MD5_Update(MD5_CTX *c, const void *data, unsigned long len)
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
            MD5_ProcessBlock(c, &c->last.buf);

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
            MD5_ProcessBlock(c, data);
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

int MD5_Final(unsigned char *md, MD5_CTX *c)
{
    uint32_t *temp;

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
        MD5_ProcessBlock(c, &c->last.buf);

        memset(&c->last.buf[0], 0, HASH_BLOCK_SIZE - HASH_LEN_SIZE);
        c->last.used = 0;

        /* save length */
        temp = (uint32_t *)&(c->last.buf[HASH_LEN_OFFSET]);
        temp[0] = htole32((c->total << 3) & 0xFFFFFFFF);
        temp[1] = htole32(((c->total << 3) >> 32) & 0xFFFFFFFF);
        MD5_ProcessBlock(c, &c->last.buf);
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
        MD5_ProcessBlock(c, &c->last.buf);
    }

    /* LE format, different from SHA family(big endian) */
    temp = (uint32_t *)md;
    temp[0] = htole32(c->hash.a);
    temp[1] = htole32(c->hash.b);
    temp[2] = htole32(c->hash.c);
    temp[3] = htole32(c->hash.d);

    return ERR_OK;
}

unsigned char *MD5(const unsigned char *d, unsigned long n, unsigned char *md)
{
    MD5_CTX c;

    if ((NULL == d) || (NULL == md))
    {
        return NULL;
    }

    MD5_Init(&c);
    MD5_Update(&c, d, n);
    MD5_Final(md, &c);

    return md;
}
