#ifndef __UTILS__H
#define __UTILS__H

#define ENDIAN_LITTLE  1234
#define ENDIAN_BIG     4321

#define ENDIANNESS ENDIAN_LITTLE

/* Swap bytes in 16 bit value. */
#define __bswap_16(x) \
     ((unsigned short int)     \
      ((((x) >> 8) & 0xff)     \
     | (((x) & 0xff) << 8)))

/* Swap bytes in 32 bit value. */
#define __bswap_32(x)    \
     ((((x) & 0xff000000) >> 24)  \
     | (((x) & 0x00ff0000) >>  8) \
     | (((x) & 0x0000ff00) <<  8) \
     | (((x) & 0x000000ff) << 24))

/* Swap bytes in 64 bit value. */
#define __bswap_64(x)               \
     ((((x) & 0xff00000000000000ull) >> 56)  \
     | (((x) & 0x00ff000000000000ull) >> 40) \
     | (((x) & 0x0000ff0000000000ull) >> 24) \
     | (((x) & 0x000000ff00000000ull) >>  8) \
     | (((x) & 0x00000000ff000000ull) <<  8) \
     | (((x) & 0x0000000000ff0000ull) << 24) \
     | (((x) & 0x000000000000ff00ull) << 40) \
     | (((x) & 0x00000000000000ffull) << 56))

#if (ENDIANNESS == ENDIAN_LITTLE)
#define htole16(x)      (x)
#define htole32(x)      (x)
#define htole64(x)      (x)

#define htobe16(x)      __bswap_16(x)
#define htobe32(x)      __bswap_32(x)
#define htobe64(x)      __bswap_64(x)
#else
#define htole16(x)      __bswap_16(x)
#define htole32(x)      __bswap_32(x)
#define htole64(x)      __bswap_64(x)

#define htobe16(x)      (x)
#define htobe32(x)      (x)
#define htobe64(x)      (x)
#endif

#define le16toh(x)      htole16(x)
#define le32toh(x)      htole32(x)
#define le64toh(x)      htole64(x)

#define be16toh(x)      htobe16(x)
#define be32toh(x)      htobe32(x)
#define be64toh(x)      htobe64(x)

int print_buffer(const void *buf, unsigned long len, const char *indent);

#endif