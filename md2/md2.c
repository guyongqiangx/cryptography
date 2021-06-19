#include <stdio.h>
#include <string.h>

#include "utils.h"
#include "md2.h"

//#define DEBUG

#ifdef DEBUG
#define DBG(...) printf(__VA_ARGS__)
#define DUMP_BLOCK_DATA     1
#define DUMP_BLOCK_CHECKSUM 1
#define DUMP_BLOCK_HASH     1
#define DUMP_ROUND_DATA     1
#else
#define DBG(...)
#define DUMP_BLOCK_DATA     0
#define DUMP_BLOCK_CHECKSUM 0
#define DUMP_BLOCK_HASH     0
#define DUMP_ROUND_DATA     0
#endif

#define HASH_BLOCK_SIZE     16
#define HASH_DIGEST_SIZE    16
#define HASH_ROUND_NUM      18

#define MD2_CHECKSUM_SIZE   16

/*
 *
 * How the S Box of MD2 are generated from Pi digits?
 * Refere: https://blog.csdn.net/guyongqiangx/article/details/117856118
 *
 */
static const uint8_t S[256] =
{
    0x29, 0x2E, 0x43, 0xC9, 0xA2, 0xD8, 0x7C, 0x01,
    0x3D, 0x36, 0x54, 0xA1, 0xEC, 0xF0, 0x06, 0x13,
    0x62, 0xA7, 0x05, 0xF3, 0xC0, 0xC7, 0x73, 0x8C,
    0x98, 0x93, 0x2B, 0xD9, 0xBC, 0x4C, 0x82, 0xCA,
    0x1E, 0x9B, 0x57, 0x3C, 0xFD, 0xD4, 0xE0, 0x16,
    0x67, 0x42, 0x6F, 0x18, 0x8A, 0x17, 0xE5, 0x12,
    0xBE, 0x4E, 0xC4, 0xD6, 0xDA, 0x9E, 0xDE, 0x49,
    0xA0, 0xFB, 0xF5, 0x8E, 0xBB, 0x2F, 0xEE, 0x7A,
    0xA9, 0x68, 0x79, 0x91, 0x15, 0xB2, 0x07, 0x3F,
    0x94, 0xC2, 0x10, 0x89, 0x0B, 0x22, 0x5F, 0x21,
    0x80, 0x7F, 0x5D, 0x9A, 0x5A, 0x90, 0x32, 0x27,
    0x35, 0x3E, 0xCC, 0xE7, 0xBF, 0xF7, 0x97, 0x03,
    0xFF, 0x19, 0x30, 0xB3, 0x48, 0xA5, 0xB5, 0xD1,
    0xD7, 0x5E, 0x92, 0x2A, 0xAC, 0x56, 0xAA, 0xC6,
    0x4F, 0xB8, 0x38, 0xD2, 0x96, 0xA4, 0x7D, 0xB6,
    0x76, 0xFC, 0x6B, 0xE2, 0x9C, 0x74, 0x04, 0xF1,
    0x45, 0x9D, 0x70, 0x59, 0x64, 0x71, 0x87, 0x20,
    0x86, 0x5B, 0xCF, 0x65, 0xE6, 0x2D, 0xA8, 0x02,
    0x1B, 0x60, 0x25, 0xAD, 0xAE, 0xB0, 0xB9, 0xF6,
    0x1C, 0x46, 0x61, 0x69, 0x34, 0x40, 0x7E, 0x0F,
    0x55, 0x47, 0xA3, 0x23, 0xDD, 0x51, 0xAF, 0x3A,
    0xC3, 0x5C, 0xF9, 0xCE, 0xBA, 0xC5, 0xEA, 0x26,
    0x2C, 0x53, 0x0D, 0x6E, 0x85, 0x28, 0x84, 0x09,
    0xD3, 0xDF, 0xCD, 0xF4, 0x41, 0x81, 0x4D, 0x52,
    0x6A, 0xDC, 0x37, 0xC8, 0x6C, 0xC1, 0xAB, 0xFA,
    0x24, 0xE1, 0x7B, 0x08, 0x0C, 0xBD, 0xB1, 0x4A,
    0x78, 0x88, 0x95, 0x8B, 0xE3, 0x63, 0xE8, 0x6D,
    0xE9, 0xCB, 0xD5, 0xFE, 0x3B, 0x00, 0x1D, 0x39,
    0xF2, 0xEF, 0xB7, 0x0E, 0x66, 0x58, 0xD0, 0xE4,
    0xA6, 0x77, 0x72, 0xF8, 0xEB, 0x75, 0x4B, 0x0A,
    0x31, 0x44, 0x50, 0xB4, 0x8F, 0xED, 0x1F, 0x1A,
    0xDB, 0x99, 0x8D, 0x33, 0x9F, 0x11, 0x83, 0x14,
};

int MD2_Init(MD2_CTX *c)
{
    if (NULL == c)
    {
        return ERR_INV_PARAM;
    }

    memset(c, 0, sizeof(MD2_CTX));
    c->last.used = 0;

    /* Clear X */
    /* Clear last.buf */
    /* Clear checksum */

    return ERR_OK;
}

static int MD2_UpdateChecksum(MD2_CTX *ctx, const uint8_t *M)
{
    uint32_t j;
    uint8_t c, L;

    if ((NULL == ctx) || (NULL == M))
    {
        return ERR_INV_PARAM;
    }

    L = ctx->checksum[15];

    /* update checksum */
    for (j=0; j<HASH_BLOCK_SIZE; j++)
    {
        c = M[j];
        /*
         * ctx->checksum[j] = S[c ^ L];
         * Description error in rfc1319, see:
         *   https://www.rfc-editor.org/rfc/inline-errata/rfc1319.html#eid555
         */
        ctx->checksum[j] ^= S[c ^ L];
        L = ctx->checksum[j];
    }

#if (DUMP_BLOCK_CHECKSUM == 1)
    DBG("CHECKSUM:\n");
    print_buffer(ctx->checksum, HASH_BLOCK_SIZE, "    ");
#endif
    return ERR_OK;
}

static int MD2_PrepareScheduleWord(MD2_CTX *ctx, const void *block)
{
    uint32_t j;
    uint8_t *X, *M;

    X = (uint8_t *)ctx->X;
    M = (uint8_t *)block;

    for (j=0; j<HASH_BLOCK_SIZE; j++)
    {
        X[16+j] = M[j];
        X[32+j] = X[16+j] ^ X[j];
    }

    return ERR_OK;
}

static int MD2_ProcessBlock(MD2_CTX *ctx, const void *block)
{
    uint32_t j, k;
    uint32_t t;
    uint8_t *X, *M;

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

    X = (uint8_t *)ctx->X;
    M = (uint8_t *)block;

    MD2_UpdateChecksum(ctx, M);

    /* Copy block into X */
    MD2_PrepareScheduleWord(ctx, M);

    t = 0;

    /* Do 18 rounds */
    for (j=0; j<HASH_ROUND_NUM; j++)
    {
        /* Round j */
        for (k=0; k<48; k++)
        {
            t = X[k] = X[k] ^ S[t];
        }

        t = (t + j) % 256;
    }

#if (DUMP_BLOCK_HASH == 1)
    DBG("    HASH: ");
    for (j=0; j<HASH_DIGEST_SIZE; j++)
    {
        DBG("%02x", ctx->X[j]);
    }
    DBG("\n");
#endif

    return ERR_OK;
}

int MD2_Update(MD2_CTX *c, const void *data, unsigned long len)
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
            MD2_ProcessBlock(c, &c->last.buf);

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
            MD2_ProcessBlock(c, data);
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

int MD2_Final(unsigned char *md, MD2_CTX *c)
{
    uint8_t pat;
    uint32_t padding_len;

    if ((NULL == c) || (NULL == md))
    {
        return ERR_INV_PARAM;
    }

    /* Append Padding Bytes */
    padding_len = HASH_BLOCK_SIZE - c->last.used;
    pat = padding_len;
    memset(&c->last.buf[c->last.used], pat, padding_len);

    /* Process Padding Block */
    MD2_ProcessBlock(c, c->last.buf);
    c->total += HASH_BLOCK_SIZE;
    c->last.used = 0;

    /* Process Checksum Block */
    memcpy(&c->last.buf[c->last.used], c->checksum, HASH_BLOCK_SIZE);
    c->last.used = HASH_BLOCK_SIZE;
    MD2_ProcessBlock(c, c->last.buf);

    /* output message digest */
    memcpy(md, c->X, HASH_DIGEST_SIZE);

    return ERR_OK;
}

unsigned char *MD2(const unsigned char *d, unsigned long n, unsigned char *md)
{
    MD2_CTX c;

    if ((NULL == d) || (NULL == md))
    {
        return NULL;
    }

    MD2_Init(&c);
    MD2_Update(&c, d, n);
    MD2_Final(md, &c);

    return md;
}
