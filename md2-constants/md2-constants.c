#include <stdio.h>

/*
 * Refer: How is the MD2 hash function S-table constructed from Pi?
 * https://crypto.stackexchange.com/questions/11935/how-is-the-md2-hash-function-s-table-constructed-from-pi
 *
 * 算法描述:
 *
 * S = [0, 1, ..., 255]
 * digits_Pi = [3, 1, 4, 1, 5, 9, ...] # the digits of pi
 *
 * def rand(n):
 *   x = next(digits_Pi)
 *   y = 10
 *
 *   if n > 10:
 *     x = x*10 + next(digits_Pi)
 *     y = 100
 *   if n > 100:
 *     x  = x*10 + next(digits_Pi)
 *     y = 1000
 *
 *   if x < (n*(y/n)): # division here is integer division
 *     return x % n
 *   else:
 *     # x value is too large, don't use it
 *     return rand(n)
 *
 * for i in 2...256: #inclusive
 *   j = rand(i)
 *   tmp = S[j]
 *   S[j] = S[i-1]
 *   S[i-1] = tmp
 */

/*
 * 获取pi常量的下一个字符值(第一位是整数3)
 */
static unsigned int next_pi_digit(void)
{
    /*
     * Python使用 sympy 工具包可以轻松获得一些数学常量的高精度数值
     * 具体参考:
     * https://blog.csdn.net/zhuoqingjoking97298/article/details/106635679
     *
     */
    static char pi[731]="3"
        "1415926535897932384626433832795028841971693993751058209749445923078164062"
        "8620899862803482534211706798214808651328230664709384460955058223172535940"
        "8128481117450284102701938521105559644622948954930381964428810975665933446"
        "1284756482337867831652712019091456485669234603486104543266482133936072602"
        "4914127372458700660631558817488152092096282925409171536436789259036001133"
        "0530548820466521384146951941511609433057270365759591953092186117381932611"
        "7931051185480744623799627495673518857527248912279381830119491298336733624"
        "4065664308602139494639522473719070217986094370277053921717629317675238467"
        "4818467669405132000568127145263560827785771342757789609173637178721468440"
        "901224953430146549585371050792279689258923542019956112129021960864034418";
    static unsigned int pos = 0;

    /*
     * 危险：取到字符串的最后一位了！！！
     * 构造MD2的S盒，256个元素，实际会调用722次
     */
    if (pos == 730)
    {
        printf("WARNING!! pi string is not long enough, wrap around!\n");
        pos = 0;
    }

    return pi[pos++]-'0';
}

/*
 * 基于pi字符串数组构造rand函数用于生成0~n-1的随机数
 */
static unsigned int rand(unsigned int n)
{
    unsigned int x, y;

    /* 构造1位随机数x */
    x = next_pi_digit();
    y = 10;

    /* 构造2位随机数x */
    if (n > 10)
    {
        x = x * 10 + next_pi_digit();
        y = 100;
    }

    /* 构造3位随机数x */
    if (n > 100)
    {
        x = x * 10 + next_pi_digit();
        y = 1000;
    }

    /*
     * 这里使用n进行整除和取模，所以n不能为0
     * 由于基于n进行取模，所以返回值介于0~n
     */
    if (x < (n*(y/n))) /* division here is integer division */
    {
        return x % n;
    }
    else
    {
        /*
         * 走到这里，会发生rand(n)内递归调用rand(n), 真的不会产生无限循环吗？
         * 答案是不会，因为内部x的状态会随着next_pi_digit()值的不同而变化
         */
        /* x value is too large, don't use it */
        return rand(n);
    }
}

/*
 * 生成md2算法中的伪随机S盒
 */
static int generate_s_box(unsigned int *S, unsigned int size)
{
    unsigned int i;
    unsigned int j;
    unsigned int tmp;

    /* 初始化随机置换数组为S[0, 1, 2, ..., 255] */
    for (i=0; i<size; i++)
    {
        S[i] = i;
    }

    /* i = 2, 3, ..., 256 */
    for (i=2; i<size+1; i++)
    {
        /* 根据rand(i)产生的伪随机数j，对S[j]和S[i-1]进行交换 */
        j = rand(i);
        /* printf("S[%3d]=0x%02X <--> S[%3d]=0x%02X\n", j, S[j], i-1, S[i-1]); */
        tmp = S[j];
        S[j] = S[i-1];
        S[i-1] = tmp;
    }

    return 0;
}

int main(int argc, char* argv)
{
    unsigned int S[256];
    int i;

    generate_s_box(S, 256);

    printf("S Box:\n");
    for (i=0; i<256; i++)
    {
        printf("0x%02X, ", (unsigned char)S[i]);
        if (i%16 == 15)
            printf("\n");
        else if (i==255)
            printf("\n");
    }

    return 0;
}

/*
 * $ ./md2-constants
 * S Box:
 * 0x29, 0x2E, 0x43, 0xC9, 0xA2, 0xD8, 0x7C, 0x01, 0x3D, 0x36, 0x54, 0xA1, 0xEC, 0xF0, 0x06, 0x13,
 * 0x62, 0xA7, 0x05, 0xF3, 0xC0, 0xC7, 0x73, 0x8C, 0x98, 0x93, 0x2B, 0xD9, 0xBC, 0x4C, 0x82, 0xCA,
 * 0x1E, 0x9B, 0x57, 0x3C, 0xFD, 0xD4, 0xE0, 0x16, 0x67, 0x42, 0x6F, 0x18, 0x8A, 0x17, 0xE5, 0x12,
 * 0xBE, 0x4E, 0xC4, 0xD6, 0xDA, 0x9E, 0xDE, 0x49, 0xA0, 0xFB, 0xF5, 0x8E, 0xBB, 0x2F, 0xEE, 0x7A,
 * 0xA9, 0x68, 0x79, 0x91, 0x15, 0xB2, 0x07, 0x3F, 0x94, 0xC2, 0x10, 0x89, 0x0B, 0x22, 0x5F, 0x21,
 * 0x80, 0x7F, 0x5D, 0x9A, 0x5A, 0x90, 0x32, 0x27, 0x35, 0x3E, 0xCC, 0xE7, 0xBF, 0xF7, 0x97, 0x03,
 * 0xFF, 0x19, 0x30, 0xB3, 0x48, 0xA5, 0xB5, 0xD1, 0xD7, 0x5E, 0x92, 0x2A, 0xAC, 0x56, 0xAA, 0xC6,
 * 0x4F, 0xB8, 0x38, 0xD2, 0x96, 0xA4, 0x7D, 0xB6, 0x76, 0xFC, 0x6B, 0xE2, 0x9C, 0x74, 0x04, 0xF1,
 * 0x45, 0x9D, 0x70, 0x59, 0x64, 0x71, 0x87, 0x20, 0x86, 0x5B, 0xCF, 0x65, 0xE6, 0x2D, 0xA8, 0x02,
 * 0x1B, 0x60, 0x25, 0xAD, 0xAE, 0xB0, 0xB9, 0xF6, 0x1C, 0x46, 0x61, 0x69, 0x34, 0x40, 0x7E, 0x0F,
 * 0x55, 0x47, 0xA3, 0x23, 0xDD, 0x51, 0xAF, 0x3A, 0xC3, 0x5C, 0xF9, 0xCE, 0xBA, 0xC5, 0xEA, 0x26,
 * 0x2C, 0x53, 0x0D, 0x6E, 0x85, 0x28, 0x84, 0x09, 0xD3, 0xDF, 0xCD, 0xF4, 0x41, 0x81, 0x4D, 0x52,
 * 0x6A, 0xDC, 0x37, 0xC8, 0x6C, 0xC1, 0xAB, 0xFA, 0x24, 0xE1, 0x7B, 0x08, 0x0C, 0xBD, 0xB1, 0x4A,
 * 0x78, 0x88, 0x95, 0x8B, 0xE3, 0x63, 0xE8, 0x6D, 0xE9, 0xCB, 0xD5, 0xFE, 0x3B, 0x00, 0x1D, 0x39,
 * 0xF2, 0xEF, 0xB7, 0x0E, 0x66, 0x58, 0xD0, 0xE4, 0xA6, 0x77, 0x72, 0xF8, 0xEB, 0x75, 0x4B, 0x0A,
 * 0x31, 0x44, 0x50, 0xB4, 0x8F, 0xED, 0x1F, 0x1A, 0xDB, 0x99, 0x8D, 0x33, 0x9F, 0x11, 0x83, 0x14,
 */