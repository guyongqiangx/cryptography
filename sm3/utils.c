#include <stdio.h>
#include "utils.h"

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
