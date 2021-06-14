#ifndef __ROCKY_MD2__H
#define __ROCKY_MD2__H

#define ERR_OK			 0
#define ERR_ERR         -1	/* generic error */
#define ERR_INV_PARAM	-2  /* invalid parameter */
#define ERR_TOO_LONG	-3  /* too long */
#define ERR_STATE_ERR   -4  /* state error */

typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;

typedef struct md2_context {
    /*
     * 数据总长度
     * MD2和SHA3一样，都没有使用长度填充
     * 所以total没有什么用，这里保留total为了调试打印第几块数据而已
     */
    uint64_t total;

    /*
     * 48字节的buffer，
     * 前16字节用于处理时保存和传递每个block(16字节)数据的哈希值
     * 后32字节在处理每个block作为临时变量
     * 所以也可以只定义16字节用于存放哈希，然后在处理每一块时临时申请48字节的buffer
     */
    uint8_t X[48];

    /*
     * 一个block(16字节)大小的缓冲区，
     * 用于保存处理中不足一个block的数据，
     * 以及最后填充的数据块和附加的checksum用于压缩处理
     */
    /* last block */
    struct {
        uint32_t used;     /* used bytes */
        uint8_t  buf[16];  /* block data buffer */
    }last;

    /* 校验和 */
    uint8_t checksum[16]; /* checksum */
}MD2_CTX;

/* https://www.openssl.org/docs/man1.1.0/man3/MD5_Init.html */
int MD2_Init(MD2_CTX *c);
int MD2_Update(MD2_CTX *c, const void *data, unsigned long len);
/* int MD2_Update(MD2_CTX *c, const unsigned char *data, unsigned long len); */
int MD2_Final(unsigned char *md, MD2_CTX *c);
unsigned char *MD2(const unsigned char *d, unsigned long n, unsigned char *md);
#endif
