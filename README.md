# 密码编码学实践

## 1. 目录介绍
- [md2-constants](./md2-constants)
  - 《MD2中用于随机置换的S盒是如何生成的？》源码
- [md2](./md2)
  - 《MD2哈希算法实现(附源码)》源码
- [md4](./md4)
  - MD4算法源码
- [md5](./md5)
  - MD5算法源码
- [sha1](./sha1)
  - SHA1算法源码
- [sha256](./sha256)
  - SHA256及SHA224算法源码
- [sha512](./sha512)
  - SHA512及SHA384, SHA512-224, SHA512-256, SHA512/t算法源码
- [sm3](./sm3)
  - 国密SM3算法源码

## 2. 如何使用

下载:
```shell
$ git clone https://github.com/guyongqiangx/cryptography.git
```

编译, 编译完会自动运行测试。:
```shell
$ cd cryptography
cryptography$ cd sha1
cryptography/sha1$
cryptography/sha1$ make
gcc -Wall -g -O2 -c utils.c -o utils.o
gcc -Wall -g -O2 -c sha1.c -o sha1.o
gcc -Wall -g -O2 -c sha1test.c -o sha1test.o
gcc -Wall -g -O2 utils.o sha1.o sha1test.o -o sha1

Run Test...
./sha1 -x
Internal hash tests for ./sha1:
./sha1("")
  Expect: da39a3ee5e6b4b0d3255bfef95601890afd80709
  Result: da39a3ee5e6b4b0d3255bfef95601890afd80709

./sha1("a")
  Expect: 86f7e437faa5a7fce15d1ddcb9eaeaea377667b8
  Result: 86f7e437faa5a7fce15d1ddcb9eaeaea377667b8

./sha1("abc")
  Expect: a9993e364706816aba3e25717850c26c9cd0d89d
  Result: a9993e364706816aba3e25717850c26c9cd0d89d

./sha1("message digest")
  Expect: c12252ceda8be8994d5fa0290a47231c1d16aae3
  Result: c12252ceda8be8994d5fa0290a47231c1d16aae3

./sha1("abcdefghijklmnopqrstuvwxyz")
  Expect: 32d10c7b8cf96570ca04ce37f2a19d84240d3a89
  Result: 32d10c7b8cf96570ca04ce37f2a19d84240d3a89

./sha1("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
  Expect: 761c457bf73b14d27e9e9265c46f4b4dda11f940
  Result: 761c457bf73b14d27e9e9265c46f4b4dda11f940

./sha1("12345678901234567890123456789012345678901234567890123456789012345678901234567890")
  Expect: 50abf5706a150990a08b2c5ea40fa0e585554732
  Result: 50abf5706a150990a08b2c5ea40fa0e585554732

cryptography/sha1$
```

测试例子不仅只是测试，还可以当做哈希工具使用:
```shell
cryptography/sha1$ ./sha1 -h
Usage:
Common options: [-x|-f file|-s string|-h]
Hash a string:
        ./sha1 -s string
Hash a file:
        ./sha1 -f file [-k key]
-x      Internal string hash test
-h      Display this message
```

计算字符串哈希：
```
cryptography/sha1$ ./sha1 -s "I like moon!"
./sha1("I like moon!") = 60580c84e774081d149596819fa8a2499c76f5d8
cryptography/sha1$ echo -n "I like moon!" | openssl dgst -sha1
(stdin)= 60580c84e774081d149596819fa8a2499c76f5d8
```

计算文件哈希:
```shell
cryptography/sha1$ ./sha1 -f sha1.o
./sha1(sha1.o) = fb70f3ceef0917427fc6eb795816826756132e15
cryptography/sha1$ openssl dgst -sha1 sha1.o
SHA1(sha1.o)= fb70f3ceef0917427fc6eb795816826756132e15
```
