#include <stdio.h>
#include "utils.h"

/* unsigned long (32 bits) to little endian char buffer */
int htole32c(unsigned char *data, unsigned long x)
{
    *data ++ = (unsigned char)( x     &0xff);
    *data ++ = (unsigned char)((x>> 8)&0xff);
    *data ++ = (unsigned char)((x>>16)&0xff);
    *data    = (unsigned char)((x>>24)&0xff);

    return 0;
}

/* unsigned long long (64 bits) to little endian char buffer */
int htole64c(unsigned char *data, unsigned long long x)
{
    *data    = (unsigned char)( x	  &0xff);
    *data ++ = (unsigned char)((x>> 8)&0xff);
    *data ++ = (unsigned char)((x>>16)&0xff);
    *data ++ = (unsigned char)((x>>24)&0xff);
    *data ++ = (unsigned char)((x>>32)&0xff);
    *data ++ = (unsigned char)((x>>40)&0xff);
    *data ++ = (unsigned char)((x>>48)&0xff);
    *data    = (unsigned char)((x>>56)&0xff);

    return 0;
}

/* unsigned long (32 bits) to big endian char buffer */
int htobe32c(unsigned char *data, unsigned long x)
{
    *data ++ = (unsigned char)((x>>24)&0xff);
    *data ++ = (unsigned char)((x>>16)&0xff);
    *data ++ = (unsigned char)((x>> 8)&0xff);
    *data    = (unsigned char)( x     &0xff);

    return 0;
}

/* unsigned long long (64 bits) to big endian char buffer */
int htobe64c(unsigned char *data, unsigned long long x)
{
    *data ++ = (unsigned char)((x>>56)&0xff);
    *data ++ = (unsigned char)((x>>48)&0xff);
    *data ++ = (unsigned char)((x>>40)&0xff);
    *data ++ = (unsigned char)((x>>32)&0xff);
    *data ++ = (unsigned char)((x>>24)&0xff);
    *data ++ = (unsigned char)((x>>16)&0xff);
    *data ++ = (unsigned char)((x>> 8)&0xff);
    *data    = (unsigned char)( x	  &0xff);

    return 0;
}


#define DUMP_LINE_SIZE 16
int print_buffer(const void *buf, unsigned long len, const char *indent)
{
    unsigned long i = 0;
    for (i=0; i<len; i++)
    {
        if (i%DUMP_LINE_SIZE == 0)
        {
            printf("%s%04lX:", indent, i);
        }

        printf(" %02x", ((unsigned char *)buf)[i]);

        if (i%DUMP_LINE_SIZE == (DUMP_LINE_SIZE-1)) /* end of line */
        {
            printf("\n");
        }
        else if (i==(len-1)) /* last one */
        {
            printf("\n");
        }
    }

    return 0;
}
