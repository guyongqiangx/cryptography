/*
 * @        file: sm3.h
 * @ description: header file for sm3.c
 * @      author: Gu Yongqiang
 * @        blog: https://blog.csdn.net/guyongqiangx
 */
#ifndef __ROCKY_SM3__H
#define __ROCKY_SM3__H

#define ERR_OK           0
#define ERR_ERR         -1  /* generic error */
#define ERR_INV_PARAM   -2  /* invalid parameter */
#define ERR_TOO_LONG    -3  /* too long */
#define ERR_STATE_ERR   -4  /* state error */

typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;

typedef struct sm3_context {
    /* message total length in bytes */
    uint64_t total;

    /* intermedia hash value for each block */
    struct {
        uint32_t a;
        uint32_t b;
        uint32_t c;
        uint32_t d;
        uint32_t e;
        uint32_t f;
        uint32_t g;
        uint32_t h;
    }hash;

    /* last block */
    struct {
        uint32_t used;     /* used bytes */
        uint8_t  buf[64];  /* block data buffer */
    }last;
}SM3_CTX;

/* https://www.openssl.org/docs/man1.1.1/man3/SHA256_Final.html */

int SM3_Init(SM3_CTX *c);
int SM3_Update(SM3_CTX *c, const void *data, size_t len);
int SM3_Final(unsigned char *md, SM3_CTX *c);
unsigned char *SM3(const unsigned char *d, size_t n, unsigned char *md);
#endif
