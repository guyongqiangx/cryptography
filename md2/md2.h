#ifndef __ROCKY_MD2__H
#define __ROCKY_MD2__H

#define ERR_OK           0
#define ERR_ERR         -1	/* generic error */
#define ERR_INV_PARAM   -2  /* invalid parameter */
#define ERR_TOO_LONG    -3  /* too long */
#define ERR_STATE_ERR   -4  /* state error */

typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;

typedef struct md2_context {
    /* message total length in bytes */
    uint64_t total;

    /* 48 bytes buffer */
    uint8_t X[48];

    /* last block */
    struct {
        uint32_t used;     /* used bytes */
        uint8_t  buf[16];  /* block data buffer */
    }last;

    uint8_t checksum[16]; /* checksum */
}MD2_CTX;

/* https://www.openssl.org/docs/man1.1.0/man3/MD5_Init.html */
int MD2_Init(MD2_CTX *c);
int MD2_Update(MD2_CTX *c, const void *data, unsigned long len);
/* int MD2_Update(MD2_CTX *c, const unsigned char *data, unsigned long len); */
int MD2_Final(unsigned char *md, MD2_CTX *c);
unsigned char *MD2(const unsigned char *d, unsigned long n, unsigned char *md);
#endif
