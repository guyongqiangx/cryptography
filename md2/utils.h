#ifndef __UTILS__H
#define __UTILS__H
#include <stdlib.h>

#define DWORD(b,i) (((uint32_t *)(b))[(i)])
#define QWORD(b,i) (((uint64_t *)(b))[(i)])

/* Only needed if htobexx is not defined */
#ifndef htobe32
/*
 * from: linux/arch/arm/kernel/setup.c
 */
static union { char c[4]; unsigned long l; } endian_test = { { 'l', '?', '?', 'b' } }; 

#define ENDIANNESS ((char)endian_test.l)
#define ENDIAN_LITTLE 'l'
#define ENDIAN_BIG    'b'
#endif

/*
 * from: linux/usr/include/x86_64-linux-gnu/bits/byteswap.h
 */
/* Swap bytes in 16 bit value.  */
#ifndef __bswap_constant_16
#define __bswap_constant_16(x) \
     ((unsigned short int)     \
      ((((x) >> 8) & 0xff)     \
     | (((x) & 0xff) << 8)))
#endif

/* Swap bytes in 32 bit value.  */
#ifndef __bswap_constant_32
#define __bswap_constant_32(x)    \
     ((((x) & 0xff000000) >> 24)  \
     | (((x) & 0x00ff0000) >>  8) \
     | (((x) & 0x0000ff00) <<  8) \
     | (((x) & 0x000000ff) << 24))
#endif

/* Swap bytes in 64 bit value.  */
#ifndef __bswap_constant_64
#define __bswap_constant_64(x)               \
     ((((x) & 0xff00000000000000ull) >> 56)  \
     | (((x) & 0x00ff000000000000ull) >> 40) \
     | (((x) & 0x0000ff0000000000ull) >> 24) \
     | (((x) & 0x000000ff00000000ull) >>  8) \
     | (((x) & 0x00000000ff000000ull) <<  8) \
     | (((x) & 0x0000000000ff0000ull) << 24) \
     | (((x) & 0x000000000000ff00ull) << 40) \
     | (((x) & 0x00000000000000ffull) << 56))
#endif

/*
 * host to big endian
 */
#ifndef htobe16
#define htobe16(x) \
    ((ENDIANNESS == ENDIAN_LITTLE) ? __bswap_constant_16(x) : (x))
#endif

#ifndef htobe32
#define htobe32(x) \
    ((ENDIANNESS == ENDIAN_LITTLE) ? __bswap_constant_32(x) : (x))
#endif

#ifndef htobe64
#define htobe64(x) \
    ((ENDIANNESS == ENDIAN_LITTLE) ? __bswap_constant_64(x) : (x))
#endif

/*
 * big endian to host
 */
#ifndef be16toh
#define be16toh(x) \
    ((ENDIANNESS == ENDIAN_LITTLE) ? __bswap_constant_16(x) : (x))
#endif

#ifndef be32toh
#define be32toh(x) \
    ((ENDIANNESS == ENDIAN_LITTLE) ? __bswap_constant_32(x) : (x))
#endif

#ifndef be64toh
#define be64toh(x) \
    ((ENDIANNESS == ENDIAN_LITTLE) ? __bswap_constant_64(x) : (x))
#endif

int htole32c(unsigned char *data, unsigned long x);
int htole64c(unsigned char *data, unsigned long long x);

int htobe32c(unsigned char *data, unsigned long x);
int htobe64c(unsigned char *data, unsigned long long x);

//int print_buffer(const void *buf, size_t len);
int print_buffer(const void *buf, size_t len, const char *indent);

#endif
