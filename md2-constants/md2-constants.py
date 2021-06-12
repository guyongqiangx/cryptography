#!/usr/bin/env python3

import io

# We need 722 decimal digits of pi, including the integer part (3).
pi = io.StringIO('3'
    '1415926535897932384626433832795028841971693993751058209749445923078164062'
    '8620899862803482534211706798214808651328230664709384460955058223172535940'
    '8128481117450284102701938521105559644622948954930381964428810975665933446'
    '1284756482337867831652712019091456485669234603486104543266482133936072602'
    '4914127372458700660631558817488152092096282925409171536436789259036001133'
    '0530548820466521384146951941511609433057270365759591953092186117381932611'
    '7931051185480744623799627495673518857527248912279381830119491298336733624'
    '4065664308602139494639522473719070217986094370277053921717629317675238467'
    '4818467669405132000568127145263560827785771342757789609173637178721468440'
    '901224953430146549585371050792279689258923542019956112129021960864034418')

# Generate a pseudorandom integer in interval [0,n) using decimal
# digits of pi (including the leading 3) as a seed.
def pi_prng(n):
    while True:
        # based on n, decide how many of digits to work with
        if   n <=   10: x, y = int(pi.read(1)),   10
        elif n <=  100: x, y = int(pi.read(2)),  100
        elif n <= 1000: x, y = int(pi.read(3)), 1000
        else: raise ValueError(r'Given value of n ({n}) is too big!')

        # Compute the largest integer multiple of n not larger than y.
        # If x is smaller than that, we can safely return it modulo n,
        # otherwise we need to try again to avoid modulo bias.
        if x < (n * (y // n)): return x % n

# Fischer-Yates/Durstenfeld shuffling algorithm, except counting up
# XXX Does counting up bias the results?
S = list(range(256))
for i in range(1,256):
    # generate pseudorandom j such that 0 ≤ j ≤ i
    j = pi_prng(i+1)
    S[j], S[i] = S[i], S[j]

# Print the S-table as shown on Wikipedia.
for i in range(16):
    prefix = '{ ' if i ==  0 else '  '
    suffix = ' }' if i == 15 else ','
    row = S[i*16:i*16+16]
    print(prefix + ', '.join(map(lambda s: '0x%02X' % s, row)) + suffix)