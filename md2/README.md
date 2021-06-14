# MD2哈希算法实现(附源码)

> 相关文章:
> - [MD2中用于随机置换的S盒是如何生成的？](https://blog.csdn.net/guyongqiangx/article/details/117856118)

学习MD2哈希算法第一手的参考资料是rfc1319文档，不过这个文档中有一处错误(关于Checksum计算)，由于没留意勘误说明，这让我在当初趟了个大坑，按照文档描述计算得到的哈希怎么都不对。

如果您打算学习MD2算法，强烈建议直接参考RFC1319，链接如下：

- RFC1319: The MD2 Message-Digest Algorithm
  - https://www.rfc-editor.org/rfc/rfc1319.html

虽然rfc1319一共有11页，但是除去第5页开始的参考代码，再除去前言，申明和各种说明，关于算法本身描述只有3页，所以整个MD2算法描述部分倒也简洁。


## 1. MD2算法描述

整个MD2哈希算法细节参考官方文档，以下对消息处理进行分层次的描述。

### 1.1 消息填充

- 填充长度

MD2处理消息时每个block大小为16个字节，通过填充，使其消息长度为16字节的整数倍。
如果原始消息的长度已经是16字节的整数倍了，则再额外填充一个16字节的数据块。

- 填充内容

那到底要填充什么内容呢？官方文档的原话是：
> ```
> Padding is performed as follows: "i" bytes of value "i" are appended
>  to the message so that the length in bytes of the padded message
>  becomes congruent to 0, modulo 16. At least one byte and at most 16
>  16 bytes are appended
> ```

简单来说，缺几个字节，就填几个字节的数值几。

例如，
- 缺1个字节，则填充1个字节的0x01；
- 缺2个字节，则填充2个自己的0x012；
- 缺16个字节，则填充16个字节的0x10；

### 1.2 追加校验和(Checksum)

对填充后的数据，逐块计算，最后得到16字节的校验和(刚好1个block)，然后将这个1 block大小的校验和追加到填充消息的后面。

校验和的具体算法，参考官方文档的3.2节(Append Checksum)。

在校验和计算的描述中，有一个错误:
```
  /* Process each 16-word block. */
  For i = 0 to N/16-1 do

     /* Checksum block i. */
     For j = 0 to 15 do
        Set c to M[i*16+j].
        Set C[j] to S[c xor L].  <-- 这里应该是 "Set C[j] to C[j] xor S[c xor L]."，即 C[j] = C[j] ^ S[c ^ L]
        Set L to C[j].
      end /* of loop on j */
   end /* of loop on i */
```

以下是勘误链接：
- https://www.rfc-editor.org/errata/eid555

### 1.3 数据分块处理

在整个消息层面对消息填充，并追加了校验和以后，将消息按照每个block 16字节进行分块处理。

对每一个块数据的处理又分为三步(实际上是两步)。

**第一步，数据预处理**

缓冲区的前16字节存放上一个block的哈希值。(第一个时为0)

将待处理的16字节数据扩展为32字节，并存放到48字节缓冲区的后32个字节中。

**第二步，处理缓冲区数据**

对48字节的缓冲区数据进行18轮替换处理

**第三步，保留缓冲区前16字节数据**

48字节缓冲区数据的前16字节实际上就是到当前block为止的哈希值，需要将这个哈希值作为下一个block的输入之一。

每一个block数据在处理时有两个输入数据：
1. 上一个block的哈希值(第一个block处理时，输入数据为0)
2. 当前block的数据

### 1.4 输出哈希

逐块处理数据时，最后一块的数据是整个消息的校验和。

在处理完这一块数据以后，输出缓冲区的前16字节作为整个消息的MD2哈希值。

## 2. C语言代码(附详细注释)

整个代码共5个文件: md2.h, md2.c, md2test.c, utils.h, utils.c, Makefile

- md2.h, md2.c
  - MD2算法实现的核心文件
- md2test.c
  - 测试文件，可以直接编译为可执行文件md2，计算计算任何字符串或输入文件的哈希。
- utils.h, utils.c, Makefile
  - 辅助文件

### 2.1 核心源码及注释

- md2.h
```
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
```

- md2.c

```
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

#define HASH_BLOCK_SIZE		16
#define HASH_DIGEST_SIZE	16
#define HASH_ROUND_NUM		18

/* 只有MD2才会计算一个block大小的CheckSum数据 */
#define MD2_CHECKSUM_SIZE   HASH_BLOCK_SIZE

/*
 * 参考:
 * md2中用于随机置换的S盒是如何生成的？
 * https://blog.csdn.net/guyongqiangx/article/details/117856118
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

/* 计算单个block的Checksum，下一个block的Checksum需要叠加上一个block的Checksum */
static int MD2_UpdateChecksum(MD2_CTX *ctx, const uint8_t *M)
{
    uint32_t j;
    uint8_t c, L;

    if ((NULL == ctx) || (NULL == M))
    {
        return ERR_INV_PARAM;
    }

    /*
     * rfc1319 3.2节处理Checksum时:
     * 1. 开始处理前，"Set L to 0"，而Checksum全部为0，所以相当于L=Checksum[15]
     * 2. 循环处理数据块的每一个bytes时有"Set L to C[j]"，数据块处理结束时L=Checksum[15]
     */
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

/* 打印每一块的Checksum数据 */
#if (DUMP_BLOCK_CHECKSUM == 1)
    DBG("CHECKSUM:\n");
    print_buffer(ctx->checksum, HASH_BLOCK_SIZE, "    ");
#endif
    return ERR_OK;
}

/* 预处理每个block输入数据 */
static int MD2_PrepareScheduleWord(MD2_CTX *ctx, const void *block)
{
    uint32_t j;
    uint8_t *X, *M;

    X = (uint8_t *)ctx->X;
    M = (uint8_t *)block;

    /*
     * 将单块数据的内容处理后放入缓冲区X的后32字节,
     * 前16字节为上一块数据处理后的内容)
     */
    for (j=0; j<HASH_BLOCK_SIZE; j++)
    {
        X[16+j] = M[j];
        X[32+j] = X[16+j] ^ X[j];
    }

    return ERR_OK;
}

/* 处理单个block数据 */
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

    /* 更新Checksum */
    MD2_UpdateChecksum(ctx, M);

    /* 预处理每个block输入数据 */
    /* Copy block i into X. */
    MD2_PrepareScheduleWord(ctx, M);

    t = 0;

    /* 对每个block数据进行18轮处理 */
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

/*
 * 管理输入数据
 * 1. 将每个完整block的数据提交MD2_ProcessBlock处理
 * 2. 将不足一个block的部分存放到last.buf缓冲区中
 */
int MD2_Update(MD2_CTX *c, const void *data, unsigned long len)
{
    uint32_t copy_len = 0;

    if ((NULL == c) || (NULL == data))
    {
        return ERR_INV_PARAM;
    }

    /*
     * 如果缓冲区还有上一次处理剩余的数据，先凑足一个block处理后，再逐个block处理本次的数据
     */
    if (c->last.used != 0)
    {
        /* 剩余数据和新数据一起还不够一个block，则复制到缓冲区 */
        if (c->last.used + len < HASH_BLOCK_SIZE)
        {
            memcpy(&c->last.buf[c->last.used], data, len);
            c->last.used += len;

            return ERR_OK;
        }
        else
        {
            /* 将缓冲区的数据凑够一个block处理 */
            copy_len = HASH_BLOCK_SIZE - c->last.used;
            memcpy(&c->last.buf[c->last.used], data, copy_len);
            MD2_ProcessBlock(c, &c->last.buf);

            c->total += HASH_BLOCK_SIZE;

            data = (uint8_t *)data + copy_len;
            len -= copy_len;

            memset(&c->last.buf[0], 0, HASH_BLOCK_SIZE);
            c->last.used = 0;
        }
    }

    /* 剩余数据不够一个block了，复制到缓冲区 */
    if (len < HASH_BLOCK_SIZE)
    {
        memcpy(&c->last.buf[c->last.used], data, len);
        c->last.used += len;

        return ERR_OK;
    }
    else
    {
        /* 逐块处理数据 */
        while (len >= HASH_BLOCK_SIZE)
        {
            MD2_ProcessBlock(c, data);
            c->total += HASH_BLOCK_SIZE;

            data = (uint8_t *)data + HASH_BLOCK_SIZE;
            len -= HASH_BLOCK_SIZE;
        }

        /* 将剩余数据复制到缓冲区 */
        memcpy(&c->last.buf[0], data, len);
        c->last.used = len;
    }

    return ERR_OK;
}

/*
 * 管理数据最后的填充，附加计算好的Checksum
 * 将剩余数据提交MD2_ProcessBlock处理
 * 返回最终的哈希值
 */
int MD2_Final(unsigned char *md, MD2_CTX *c)
{
    uint8_t pat;
    uint32_t padding_len;

    if ((NULL == c) || (NULL == md))
    {
        return ERR_INV_PARAM;
    }

    /* Append Padding Bytes */
    /* 剩余数据存放在last.buf缓冲区中，计算需要填充的长度
     * 如果原来的数据刚好是一整块，没有剩余，则再新增一整块
     */
    padding_len = HASH_BLOCK_SIZE - c->last.used;
    /* MD2填充时填充i个值为i的数据, "i" bytes of value "i" */
    pat = padding_len;
    memset(&c->last.buf[c->last.used], pat, padding_len);

    /* Process Padding Block */
    /* 处理填充的数据块 */
    MD2_ProcessBlock(c, c->last.buf);
    c->total += HASH_BLOCK_SIZE;
    c->last.used = 0;

    /* Process Checksum Block */
    /* 最后处理一个block的Checksum数据 */
    memcpy(&c->last.buf[c->last.used], c->checksum, HASH_BLOCK_SIZE);
    c->last.used = HASH_BLOCK_SIZE;
    MD2_ProcessBlock(c, c->last.buf);

    /* 所有数据处理完成后，48字节缓冲区的前16个字节就是哈希值 */
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
```

完整源码，包括测试代码和Makefile等位于：
- https://github.com/guyongqiangx/cryptography/

### 2.2 代码结构说明

#### API

代码一共封装了4个MD2操作的API:
```
int MD2_Init(MD2_CTX *c);
int MD2_Update(MD2_CTX *c, const void *data, unsigned long len);
int MD2_Final(unsigned char *md, MD2_CTX *c);
unsigned char *MD2(const unsigned char *d, unsigned long n, unsigned char *md);
```

和OpenSSL官方的MD2函数接口一样，功能也基本一致:
- https://www.openssl.org/docs/man1.1.0/man3/MD5_Init.html


#### 私有实现

所有哈希函数的操作基本一致，包括：

**1. 整个消息层面**
- 填充数据
- 对数据分块

**2. 数据块层面**
- 对数据块预处理
- 对预处理数据进行多轮处理
- 保存当前数据块的哈希值给下一块数据

**3. 最后**
- 返回最后一个数据块的哈希值作为整个消息的哈希

实际上，不会在一开始就会对整个数据进行填充，最好在处理到最后一块数据时再填充，原因主要是：
- 有些情况下一开始不知道数据大小，没法填充(如串口或网络数据)；
- 将全部数据放入内存，填充好以后才开始计算，开销太大

所以整个过程有点像流式操作:
```
MD2_INIT()
MD2_Update(message1)
  --> MD2_ProcessBlock(block1)
  --> MD2_ProcessBlock(block2)
  --> ...
  --> MD2_ProcessBlock(blockn)
MD2_Update(message2)
...
MD2_Update(messagen)
MD2_Final(&digest)
```

在每次收到数据时，"MD2_Update"将数据逐个分块，剩余不足一块的数据保存起来，和一下次到达的数据一起处理。

在处理每个数据块时，操作也比较模式化：
```
MD2_ProcessBlock(data)
{
    Preprocess1(data) // 预处理1, 如计算Checksum
    Preprocess2(data) // 预处理2, 如对数据进行扩展
    for (i=0; i<round; i++) // 逐轮对数据进行处理
    {
        action1()
        action2()
        ...
        actionn()
    }
    SaveHash() // 保存当前块数据的哈希
}
```

## 3. 编译测试

代码编译后会自动执行内置的MD2哈希测试:

```
$ make
gcc -Wall -g -O2 -c utils.c -o utils.o
gcc -Wall -g -O2 -c md2.c -o md2.o
gcc -Wall -g -O2 -c md2test.c -o md2test.o
gcc -Wall -g -O2 utils.o md2.o md2test.o -o md2

Run Test...
./md2 -x
Internal hash tests for ./md2:
./md2("")
Expect: 8350e5a3e24c153df2275c9f80692773
Result: 8350e5a3e24c153df2275c9f80692773

./md2("a")
Expect: 32ec01ec4a6dac72c0ab96fb34c0b5d1
Result: 32ec01ec4a6dac72c0ab96fb34c0b5d1

./md2("abc")
Expect: da853b0d3f88d99b30283a69e6ded6bb
Result: da853b0d3f88d99b30283a69e6ded6bb

./md2("message digest")
Expect: ab4f496bfb2a530b219ff33031fe06b0
Result: ab4f496bfb2a530b219ff33031fe06b0

./md2("abcdefghijklmnopqrstuvwxyz")
Expect: 4e8ddff3650292ab5a4108c3aa47940b
Result: 4e8ddff3650292ab5a4108c3aa47940b

./md2("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
Expect: da33def2a42df13975352846c30338cd
Result: da33def2a42df13975352846c30338cd

./md2("12345678901234567890123456789012345678901234567890123456789012345678901234567890")
Expect: d5976f79d83d3a0dc9806c3c66f3efd8
Result: d5976f79d83d3a0dc9806c3c66f3efd8
```

也可以将生成的md2可执行文件当做md2哈希工具，计算任意字符串或文件的md2哈希值：

```
# 将当前目录添加到PATH中
$ export PATH=.:$PATH

# 计算字符串"I love China!"的MD2哈希
$ md2 -s "I love China!"
md2("I love China!") = 87ccffeb214640064ad34a650b9ee121

# 计算Makefile文件的MD2哈希
$ md2 -f Makefile
md2(Makefile) = d625cd261a6066d2f70f7e3953fe8846
```

## 4. MD2为什么没有流行起来？

1. License

在rfc1319的第1节中，有专门针对MD2 license的描述:
> License to use MD2 is granted for non-commerical Internet Privacy-Enhanced Mail [1-3].

这里明确提出MD2的非商业用途。

2. 性能

从MD2的算法描述看，MD2中的所有操作都是基于单个字节的，但后续哈希算法都基于32或更多字节进行设计，性能上会比单个自己操作更强。

关于性能，还需要具体数据进行验证，MD2和同家族的MD4, MD5到底有多大区别。

## 5. 其它

洛奇工作中常常会遇到自己不熟悉的问题，这些问题可能并不难，但因为不了解，找不到人帮忙而瞎折腾，往往导致浪费几天甚至更久的时间。

所以我组建了几个微信讨论群(记得微信我说加哪个群，如何加微信见后面)，欢迎一起讨论:
- 一个密码编码学讨论组，主要讨论各种加解密，签名校验等算法，请说明加密码学讨论群。
- 一个Android OTA的讨论组，请说明加Android OTA群。
- 一个git和repo的讨论组，请说明加git和repo群。

在工作之余，洛奇尽量写一些对大家有用的东西，如果洛奇的这篇文章让您有所收获，解决了您一直以来未能解决的问题，不妨赞赏一下洛奇，这也是对洛奇付出的最大鼓励。扫下面的二维码赞赏洛奇，金额随意：

![收钱码](https://img-blog.csdnimg.cn/20190111150810383.png)

洛奇自己维护了一个公众号“洛奇看世界”，一个很佛系的公众号，不定期瞎逼逼。公号也提供个人联系方式，一些资源，说不定会有意外的收获，详细内容见公号提示。扫下方二维码关注公众号：

![公众号](https://img-blog.csdnimg.cn/20190111150824695.png)
