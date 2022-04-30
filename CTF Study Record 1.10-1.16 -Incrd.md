# 学习记录1.10-1.16 -Incrd

## Feistel加密结构

Feistel 密码结构是用于分组密码中的一种对称结构，DES、RC5、FEAL、GOST、LOKI等均采用了Feistel结构。  

### 加密过程

LE代表Left Encryption，LD代表Right Encryption

令F 为轮函数；令K$_1$，K$_2$，……，K$_n$ 分别为第1，2，……，n 轮的子密钥。  
将明文分组，每一组明文分为两块：(LE$_0$, RE$_0$);  
在每一轮中进行如下运算：  
LE$_{i+1}$ = RE$_{i}$;  
RE$_{i+1}$ = LE$_{i}$ ⊕ F(RE$_{i}$，K$_{i}$)
所得的结果即为：(RE$_{i+1}$, LE$_{i+1}$)  
需要注意的是，最后一轮迭代后，有一个附加的左右置换过程。  

### 解密过程

对于密文(RD$_{i+1}$，LD$_{i+1}$)，只需对密文进行加密的逆向操作：  
LD$_{i+1}$ = RD$_{i}$;  
RD$_{i+1}$ = LD$_{i}$ ⊕ F(RD$_{i}$，K$_{n-i}$)

### 影响因素

1. 块的大小：大的块会提高加密的安全性，但是会降低加密、解密的速度。截止至2013年，比较流行的这种方案是 64 bit。而 128 bit 的使用也比较广泛。  
2. 密钥的大小：同上。而 128 bit 正逐渐取代 64 bit，成为主流。  
3. 循环次数（轮次数）：每多进行一轮循环，安全性就会有所提高。现阶段比较流行的是16轮。  
4. 子密钥的生成算法：生成算法越复杂，则会使得密码被破译的难度增强，即，信息会越安全。  
5. 轮函数 F 的复杂度：轮函数越复杂，则安全性越高。  

### 关于加解密互逆的证明

假设迭代轮数为16，LD$_{1}$ = RD$_{0}$ = LE$_{16}$ = RE$_{15}$  
RD$_{1}$ = LD$_{0}$ ⊕ F(RD$_{0}$, K$_{16}$) = RE$_{16}$ ⊕ F(RE$_{15}$, K$_{16}$) = LE$_{15}$ ⊕ F(RE$_{15}$, K$_{16}$) ⊕ F(RE$_{15}$, K$_{16}$) = LE$_{15}$  
可见解密时经过 1 次迭代的结果即为加密时第 15 次迭代的结果，  
剩下的迭代依此类推。可以得出的结论是：  
LD$_{i}$=RE$_{16-i}$  
RD$_{i}$=LE$_{16-i}$  

## RSA算法

RSA算法的具体描述如下：  

1. 任意选取两个不同的大素数p和q计算乘积 n = pq, φ(n) = (p - 1)(q - 1)；
2. 任意选取一个大整数e，满足 gcd(e, φ(n)) = 1，整数e用做加密钥；
3. 确定的解密钥d，满足 (de) mod φ(n) = 1；
4. 公开整数n和e，秘密保存d，公钥即为(n, e)，私钥即为(d, n)；
5. 将明文 m 加密为密文 s ：s = m ^ e mod n
6. 将密文 s 解密为明文 m ：m = s ^ d mod n

（更多具体原理不在此赘述，说实话理解这个花费了我很多时间）

## Bugku python(N1CTF) WP

题目给出两个文件  

```python

# challenge.py
from N1ES import N1ES
import base64
key = "wxy191iss00000000000cute"
n1es = N1ES(key)
flag = "N1CTF{*****************************************}"
cipher = n1es.encrypt(flag)
print base64.b64encode(cipher)  # HRlgC2ReHW1/WRk2DikfNBo1dl1XZBJrRR9qECMNOjNHDktBJSxcI1hZIz07YjVx
```

```python
# N1ES.py
# Add comments and prettify
# -*- coding: utf-8 -*-
import base64


def round_add(a, b):    # a 为 L，b 为 self.Kn[round_cnt]
    def f(x, y): return x + y - 2 * (x & y)  # 加密所用 f 函数
    res = ''
    for i in range(len(a)):
        res += chr(f(ord(a[i]), ord(b[i])))
    return res


def permutate(table, block):
    return list(map(lambda x: block[x], table))


def string_to_bits(data):
    data = [ord(c) for c in data]
    # data为原数据的ASCII列表
    l = len(data) * 8
    result = [0] * l
    pos = 0
    for ch in data:                 # ch 遍历 data 列表
        for i in range(0, 8):       # i ∈ [0, 7]
            result[(pos << 3)+i] = (ch >> i) & 1
            # result[(pos * 2^3) + i] = (ch // 2^i) & 1
        pos += 1
    # ASCII列表转为二进制列表
    return result


s_box = [54, 132, 138, 83, 16, 73, 187, 84, 146, 30, 95, 21, 148, 63, 65, 189, 188, 151, 72, 161, 116, 63, 161, 91, 37, 24, 126, 107, 87, 30, 117, 185, 98, 90, 0, 42, 140, 70, 86, 0, 42, 150, 54, 22, 144, 153, 36, 90, 149, 54, 156, 8, 59, 40, 110, 56, 1, 84, 103, 22, 65, 17, 190, 41, 99, 151, 119, 124, 68, 17, 166, 125, 95, 65, 105, 133, 49, 19, 138, 29, 110, 7, 81, 134, 70, 87, 180, 78, 175, 108, 26, 121, 74, 29, 68, 162, 142, 177, 143, 86, 129, 101, 117, 41, 57, 34, 177, 103, 61, 135, 191,
         74, 69, 147, 90, 49, 135, 124, 106, 19, 89, 38, 21, 41, 17, 155, 83, 38, 159, 179, 19, 157, 68, 105, 151, 166, 171, 122, 179, 114, 52, 183, 89, 107, 113, 65, 161, 141, 18, 121, 95, 4, 95, 101, 81, 156, 17, 190, 38, 84, 9, 171, 180, 59, 45, 15, 34, 89, 75, 164, 190, 140, 6, 41, 188, 77, 165, 105, 5, 107, 31, 183, 107, 141, 66, 63, 10, 9, 125, 50, 2, 153, 156, 162, 186, 76, 158, 153, 117, 9, 77, 156, 11, 145, 12, 169, 52, 57, 161, 7, 158, 110, 191, 43, 82, 186, 49, 102, 166, 31, 41, 5, 189, 27]
# len(s_box) = 224


def generate(o):    # o 为密钥字节串
    k = permutate(s_box, o)
    # k 为以 s_box 为下标从 o 中获得的列表
    # len(k) = 224
    b = []

    for i in range(0, len(k), 7):
        b.append(k[i:i+7] + [1])
    # b 将 k 以7个为一组分割并在最高位加上一个 [1]
    # b 中整数元素个数为 (224 / 7 = 32) * 8 = 256
    c = []
    for i in range(32):  # i ∈ [0, 32] 32 即为 b 中列表个数
        pos = 0
        x = 0
        for j in b[i]:  # j 遍历 b[i] 列表
            x += (j << pos)  # x 为 b[i] 中元素的组合
            pos += 1
        c.append((0x10001**x) % (0x7f))  # 0x10001 = 65537; 0x7f = 127
    return c


class N1ES:
    def __init__(self, key):
        # 原本为 isinstance(key, bytes) == False
        if (len(key) != 24 or isinstance(key, bytes) == True):
            raise Exception("key must be 24 bytes long")
        self.key = key
        # 接收密钥
        self.gen_subkey()
        # 调用函数生成子密钥

    def gen_subkey(self):
        o = string_to_bits(self.key)  # 密钥转化为字节串
        k = []

        for i in range(8):
            o = generate(o) # 生成 32 个元素均在 [0, 127]
            k.extend(o)     # 最后 k 中有 32 * 8 个元素
            o = string_to_bits([chr(c) for c in o[0:24]])
        self.Kn = []

        for i in range(32):
            self.Kn.append(list(map(chr, k[i * 8: i * 8 + 8])))  # 加上了list
            # k 中元素 8 个一组转为字符赋值至 self.Kn 中
        # self.Kn 即为子密钥，结构为 32 * 8 个元素
        return

    def encrypt(self, plaintext):
        # 原本为 isinstance(plaintext, bytes) == False
        if (len(plaintext) % 16 != 0 or isinstance(plaintext, bytes) == True):
            raise Exception("plaintext must be a multiple of 16 in length")
        res = ''
        for i in range(len(plaintext) // 16):       # 原本 // 为 / ，但单除号结果为float无法作为range参数
            # block 将明文分为长度为 16 的子串，进行分组加密
            block = plaintext[i * 16:(i + 1) * 16]
            L = block[:8]
            R = block[8:]
            # L,R 分别为 block 的左右两半
            for round_cnt in range(32):  # 进行 32 轮加密
                L, R = R, (round_add(L, self.Kn[round_cnt]))
            L, R = R, L
            res += L + R
        return res
```

首先研读代码，还是比较长的，花了一些时间，而且貌似脚本原本的环境是python2，故做了很多修改以在python3上运行。  
首先传入一个密钥，调用`gen_subkey(self)`函数生成子密钥，`string_to_bits`将字符串转化为二进制列表，再通过`generate(o)`函数生成32个 [0, 127] 的数，其中使用了`permutate(table, block)`函数通过`s_box`映射打乱二进制串的顺序，进入for循环，每7个后再加上一个1构成八位，第二个for循环中，b中32组元素，而每一组元素都有八位，每一个进行运算后在放到C中。o经过`generate(o)`后放入k列表中，取o的前24个变成字符后在转为二进制，重新赋值给o，这样重复八次，共产生32*8个数字，8个一组共32组作为子密钥。  
上述过程均为生成`self.Kn`子密钥以进行后续加密。  
接着进入`encrypt(self, plaintext)`函数进行加密，观察函数结构，实际为**Feistel加密结构**，Feistel解密只要将循环式改为：

```python

for round_cnt in range(32):
    L, R = R, (round_add(L, self.Kn[31-round_cnt]))
```

故解密函数为：

```python
def decrypt(self,plaintext):
    # if (len(plaintext) % 16 != 0 or isinstance(plaintext, bytes) == False):
    #     raise Exception("plaintext must be a multiple of 16 in length")
    res = ''
    for i in range(len(plaintext) // 16):
        block = plaintext[i * 16:(i + 1) * 16]
        L = block[:8]
        R = block[8:]
        for round_cnt in range(32):
            L, R = R, (round_add(L, self.Kn[31-round_cnt]))
        L, R = R, L
        res += L + R
    return res
```

challenge.py中最后执行了一步base64编码。
加入decrypt函数后再执行：

```python
key = "wxy191iss00000000000cute"
n1es = N1ES(key)
cipher = 'HRlgC2ReHW1/WRk2DikfNBo1dl1XZBJrRR9qECMNOjNHDktBJSxcI1hZIz07YjVx'

b64decodecipher = str(base64.b64decode(cipher), 'utf-8')
flag = n1es.decrypt(b64decodecipher)
print(flag)
# N1CTF{F3istel_n3tw0rk_c4n_b3_ea5i1y_s0lv3d_/--/}
```

但是后来经过分析，虽然结构类似Feistel加密结构，但加密过程中省去了异或运算，所以和Feistel加密结构有一定的区别，能用相同的解密方式破解可能是非预期的（仍未知晓为什么本题仍能用加密方式解密）。  
考虑到本题省去了 L 与 R 的异或运算，所以实际上上明文和密文是一一映射的，复杂度不是 100^48，而只是 100*48，因此可以直接爆破，以下为爆破脚本（加在N1ES.py文件末尾）。

```python
key = "wxy191iss00000000000cute"
n1es = N1ES(key)
cipher = 'HRlgC2ReHW1/WRk2DikfNBo1dl1XZBJrRR9qECMNOjNHDktBJSxcI1hZIz07YjVx'
b64decodecipher = base64.b64decode(cipher)
flag = ''
for i in range(3):
    for j in range(16):
        for m in string.printable:
            temp = 'x' * (i * 16 + j) + m + 'x' * (48 - (i * 16 + j) - 1)
            en_temp = bytes(n1es.encrypt(temp), 'ascii')
            if j < 8:
                if en_temp[i * 16 + j + 8] == b64decodecipher[i * 16 + j + 8]:
                    flag += m
                    break
            else:
                if en_temp[i * 16 + j - 8] == b64decodecipher[i * 16 + j - 8]:
                    flag += m
                    break
print(flag)
# N1CTF{F3istel_n3tw0rk_c4n_b3_ea5i1y_s0lv3d_/--/}
```

后来又思考了很久为什么能用Feistel的解密方式，经过大量尝试，不论修改加密轮次还是密钥生成函数，加密算法均能通过相同算法解密，最后发现问题出在加密所用的 f 函数，尝试和猜测后发现，f 函数实际就是执行了一个异或操作，即下面两个函数的操作效果是相同的。

```python
def f1(x, y): return x + y - 2 * (x & y)
def f2(x, y): return x ^ y
```

真值表
| x | y |f1 |f2 |
|---|---|---|---|
| 0 | 0 | 0 | 0 |
| 0 | 1 | 1 | 1 |
| 1 | 0 | 1 | 1 |
| 1 | 1 | 0 | 0 |

经过暴力循环测试和真值表分析发现 f1 和 f2 确实是等价的，而一个数异或同一个数两次，结果仍是那个数，该结论可以用穷举法证明，这里不再赘述。  
至此，该题能用Feistel的解密方式的原因已经明了。  

## Bugku 简单的rsa WP

题目给出了一个 .pyc 后缀的文件。

>pyc是一种二进制文件，是由Python文件经过编译后所生成的文件，是一种byte code。

原本想用 uncompyle6 反编译，但是这个不支持 python3.9 及以上版本，用 Anaconda 的虚拟环境也不行，识别不到其他版本的 python （不知道为啥），无奈只好用在线网站 <https://tool.lu/pyc>（这上面工具还真多）。  
反编译得到：

```python
#!/usr/bin/env python
import gmpy2
from Crypto.Util.number import *
from binascii import a2b_hex, b2a_hex
flag = '******************'
p = 0xED7FCFABD3C81C78E212323329DC1EE2BEB6945AB29AB51B9E3A2F9D8B0A22101E467
q = 0xAD85852F9964DA87880E48ADA5C4487480AA4023A4DE2C0321C170AD801C9
e = 65537
n = p * q
c = pow(int(b2a_hex(flag), 16), e, n)
print(c)
c = 0x75AB3202DE3E103B03C680F2BEBBD1EA689C8BF260963FE347B3533B99FB391F0A358FFAE5160D6DCB9FCD75CD3E46B2FE3CFFE9FA2E9508702FD6E4CE43486631

```

~~所谓“简单的rsa"居然没骗人，泪目~~
给出 p, q 了可以直接计算 d，修改后程序如下

```python
#!/usr/bin/env python
import gmpy2
import base64
from Crypto.Util.number import *
from binascii import a2b_hex, b2a_hex
flag = '******************'
p = 0xED7FCFABD3C81C78E212323329DC1EE2BEB6945AB29AB51B9E3A2F9D8B0A22101E467
q = 0xAD85852F9964DA87880E48ADA5C4487480AA4023A4DE2C0321C170AD801C9
e = 65537
n = p * q
d = gmpy2.invert(e, (p - 1) * (q - 1))
c = pow(int(b2a_hex(bytes(flag, 'utf-8')), 16), e, n)
c = 0x75AB3202DE3E103B03C680F2BEBBD1EA689C8BF260963FE347B3533B99FB391F0A358FFAE5160D6DCB9FCD75CD3E46B2FE3CFFE9FA2E9508702FD6E4CE43486631

res = hex(pow(c, d, n))
print(str(res))
print(bytes.fromhex(str(res)[2:]))
temp = bytes.fromhex(str(res)[2:])
finallyres = str(base64.b64decode(temp), 'utf-8')
print(finallyres)
# flag{IlikeCTFbutCTFdon'tlikeme}
```

## Bugku 给你私钥吧 WP

题目给出四个文件：  
flag.enc：加密后的flag  
privatekey.pem, pubkey.pem：分别为私钥和公钥文件  
resencrypt.py：加密程序  
resencrypt.py:

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
from flag import flag


f=open(r"pubkey.pem","r")
key=RSA.importKey(f.read())
cipher=PKCS1_OAEP.new(key)
cipher_txt=base64.b64encode(cipher.encrypt(flag))

with open(r"flag.enc","wb") as f:
    f.write(cipher_txt)
    f.close()
```

用 OpenSSL 提取公钥和私钥  
提取公钥  
`openssl rsa -pubin -in pubkey.pem -text -modulus`  
得到  
n = D12B639DF759A99C9ADB57500BBD635041AA70F8E73F6EA158B23B9AF575915CF68CF8E57B045BBEBCF78A9BCA72BF0E63CB6EC353D66142048CB69EB5F20CDC6BAF6C85E77E6F2AA906DC5868FCB0F0330DEB55076EDF1B226EF54926DD2AD3C943C8EB35CB8C85848E05EA8680988A182701B6A0DC54967760CAC28136AD5B3D9F1CF7952B898CFAAF863A90BFD58DF0FA3F358A7EB8BCBE1BFCF13872BBB9FCC2B330A38F3FD689467FEF22F027549F53D460E9FEBB48F1AE15F7BFBA93069641FD53C46FC971560F5955D8F6E419F5981A9BA393718D785F58659607F511F6CC4077834E059F368EB05BCA7964EA2DC8CD1B13F62A29EA244A3876FF5967  
e = 65537 (0x10001)  

提取私钥  
`openssl rsa -in privatekey.pem -text -modulus`  
发现提取不到 d，只有一个 p 的高位部分，如下  

```text
prime1: 0
prime2:
    00:ee:4e:18:98:45:cc:78:ef:ef:4a:c3:e8:1d:8a:
    ef:99:7f:73:5d:58:33:b5:c7:e8:49:4b:91:74:ae:
    21:1b:a8:82:31:e2:56:7e:e6:df:99:01:32:8e:0c:
    6d:bc:5e:24:b3:43:77:47:85:ae:7e:88:ec:40:9c:
    a1:d7:29:01:e3:2a:58:2f:29:12:60:eb:98:51:fc:
    bb:0f:ff:20:80:5d:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00
```

coppersmith的定理:  
对任意的a > 0，给定 N = PQR 及 P Q 的高位 (1/5)(logN,2) 比特，我们可以在多项式时间 logN 内得到N的分解式。  

尝试进行高位攻击，知道p的高位为p的位数的约1/2时即可  
已知e, n 爆破 1024 位的P，至少需要知道前576位二进制，即前144位16进制，已知前144位。  

```sage
n=26405201714915839490865227813246218372938736243516916108608439705738170543023112509150522274284238701776297205717958250714972924576706985074311737321016048409831557758205687745692399643151467933196930799657476449865271038382866908177517793954543176769652784274788769353482450910551831498252972857285424471782215525406445071432588374802623485148684255853068532820859835479998199886719945699488858505070686919320144576280217196858823521754407597888769668827432569034617434944912323704501156532854074083408527717809315663187405585840074689387865750105223058720511199252150772925124516509254841404742306560035497627834727
p4=0xee4e189845cc78efef4ac3e81d8aef997f735d5833b5c7e8494b9174ae211ba88231e2567ee6df9901328e0c6dbc5e24b343774785ae7e88ec409ca1d72901e32a582f291260eb9851fcbb0fff20805d     #已知P的高位
e=65537
pbits=1024          #P原本的位数

kbits=pbits - p4.nbits()
# print (p4.nbits())
p4 = p4 << kbits
PR.<x> = PolynomialRing(Zmod(n))
f = x + p4
roots = f.small_roots(X=2^kbits,beta=0.4)

if roots:
    p= p4 + int(roots[0])
    print ("n",n)
    print ("p",p)
    print ("q",n/p)
```

得到：

```text
n 26405201714915839490865227813246218372938736243516916108608439705738170543023112509150522274284238701776297205717958250714972924576706985074311737321016048409831557758205687745692399643151467933196930799657476449865271038382866908177517793954543176769652784274788769353482450910551831498252972857285424471782215525406445071432588374802623485148684255853068532820859835479998199886719945699488858505070686919320144576280217196858823521754407597888769668827432569034617434944912323704501156532854074083408527717809315663187405585840074689387865750105223058720511199252150772925124516509254841404742306560035497627834727
p 167343506005974003380506069679607737381940204686173214188860057004909006055220516074283090160430833007424970980655748310232878462615469792561310560310363430669700009093597847018287568821792168143170329382585883857083334915378884054389878477389765792275111293420203613159303898365894897865177093362621517279751
q 157790417717035275943197904823645145281147085252905247447260034051878691034747684303715336348507267921249655103263347914128144476912685213431110454636244692224328066884510063590700506729345331153483633231327359450199822698241355428609085077662488946173655043172957247264543259611018596088670385591091710018977
```

最后解密flag：

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import libnum


def decrypt_rsa():
    n = 26405201714915839490865227813246218372938736243516916108608439705738170543023112509150522274284238701776297205717958250714972924576706985074311737321016048409831557758205687745692399643151467933196930799657476449865271038382866908177517793954543176769652784274788769353482450910551831498252972857285424471782215525406445071432588374802623485148684255853068532820859835479998199886719945699488858505070686919320144576280217196858823521754407597888769668827432569034617434944912323704501156532854074083408527717809315663187405585840074689387865750105223058720511199252150772925124516509254841404742306560035497627834727
    e = 65537
    q = 157790417717035275943197904823645145281147085252905247447260034051878691034747684303715336348507267921249655103263347914128144476912685213431110454636244692224328066884510063590700506729345331153483633231327359450199822698241355428609085077662488946173655043172957247264543259611018596088670385591091710018977
    p = 167343506005974003380506069679607737381940204686173214188860057004909006055220516074283090160430833007424970980655748310232878462615469792561310560310363430669700009093597847018287568821792168143170329382585883857083334915378884054389878477389765792275111293420203613159303898365894897865177093362621517279751
    d = libnum.invmod(e, (p - 1) * (q - 1))
    u = libnum.invmod(p, q)
    private_key = RSA.construct((n, e, d, p, q, u))

    with open(r"D:\Operator\Download\Bugku\flag.enc", "rb") as f:
        cipher_txt = f.read()
    cipher_txt = base64.decodebytes(cipher_txt)
    decipher = PKCS1_OAEP.new(private_key)
    flag = decipher.decrypt(cipher_txt)
    print(flag)


if __name__ == "__main__":
    decrypt_rsa()
# bugku{tw0_Tig3rs_l0V3_d4nc1ng~ei!}
```

sage 在线网站 <https://sagecell.sagemath.org>  
更多参考 <https://www.jianshu.com/p/1a0e876d5929>  （这部分涉及太多还未涉及的高等数学知识，还没完全搞懂）  

## picoCTF Mod 26 WP

Description

```text
Cryptography can be easy, do you know what ROT13 is?
cvpbPGS{arkg_gvzr_V'yy_gel_2_ebhaqf_bs_ebg13_MAZyqFQj}
```

非常简单的 ROT13 加密

```python
import string
x = "cvpbPGS{arkg_gvzr_V'yy_gel_2_ebhaqf_bs_ebg13_MAZyqFQj}"
y = ''
for i in x:
    if i in string.ascii_lowercase:
        y += string.ascii_lowercase[(string.ascii_lowercase.find(i) + 13) % 26]
    elif i in string.ascii_uppercase:
        y += string.ascii_uppercase[(string.ascii_uppercase.find(i) + 13) % 26]
    else:
        y += i
print(y)
# picoCTF{next_time_I'll_try_2_rounds_of_rot13_ZNMldSDw}
```

## picoCTF Mind your Ps and Qs WP

Description:

```text
In RSA, a small e value can be problematic, but what about N? Can you decrypt this?
```

一个 values 文件

```text
Decrypt my super sick RSA:
c: 62324783949134119159408816513334912534343517300880137691662780895409992760262021
n: 1280678415822214057864524798453297819181910621573945477544758171055968245116423923
e: 65537
```

给出的 n 在 10$^{82}$ 数量级，即便如此拿较快的分解脚本爆破所需的时间也是比较恐怖的，而且把我电脑内存耗尽了也没爆出来。  
于是尝试 factordb 的网站工具 <http://www.factordb.com/>  
这网站原理貌似是一个数据库，存了很多已经质因数分解过的大数，一输入 n 很快就得到了结果，还能看见这条记录被创建的时间是`March 16, 2021, 5:35 pm`，很彳亍。  
除了 factordb，我还另外尝试了另一个工具 yafu，
>yafu 用于自动整数因式分解，在 RSA 中，当 p、q 的取值差异过大或过于相近的时候，使用 yafu 可以快速的把 n 值分解出 p、q 值，原理是使用 Fermat 方法与 Pollard rho 方法等。

估计是个优化过的算法，下载后在命令行调用

```text
.\yafu-x64.exe "factor(1280678415822214057864524798453297819181910621573945477544758171055968245116423923)"

fac: factoring 1280678415822214057864524798453297819181910621573945477544758171055968245116423923
fac: using pretesting plan: normal
fac: no tune info: using qs/gnfs crossover of 95 digits
div: primes less than 10000
fmt: 1000000 iterations
rho: x^2 + 3, starting 1000 iterations on C82
rho: x^2 + 2, starting 1000 iterations on C82
rho: x^2 + 1, starting 1000 iterations on C82
pm1: starting B1 = 150K, B2 = gmp-ecm default on C82
ecm: 30/30 curves on C82, B1=2K, B2=gmp-ecm default
ecm: 74/74 curves on C82, B1=11K, B2=gmp-ecm default
ecm: 205/205 curves on C82, B1=50K, B2=gmp-ecm default, ETA: 0 sec

starting SIQS on c82: 1280678415822214057864524798453297819181910621573945477544758171055968245116423923

==== sieving in progress (1 thread):   51440 relations needed ====
====           Press ctrl-c to abort and save state           ====
51587 rels found: 21191 full + 30396 from 352942 partial, (1924.28 rels/sec)

SIQS elapsed time = 197.1098 seconds.
Total factoring time = 214.5938 seconds


***factors found***

P40 = 1899107986527483535344517113948531328331
P42 = 674357869540600933870145899564746495319033

ans = 1
```

花费了 214 秒，成功分解，勉强能够接受的速度，毕竟这俩因子也不算太相近。

得出 p, q 解密就很简单了

```python
import libnum

def decrypt_rsa():
    c = 62324783949134119159408816513334912534343517300880137691662780895409992760262021
    n = 1280678415822214057864524798453297819181910621573945477544758171055968245116423923
    e = 65537
    q = 674357869540600933870145899564746495319033
    p = 1899107986527483535344517113948531328331
    d = libnum.invmod(e, (p - 1) * (q - 1))
    res = hex(pow(c, d, n))
    temp = bytes.fromhex(str(res)[2:])
    
    print(str(temp, 'utf-8'))

if __name__ == "__main__":
    decrypt_rsa()
# picoCTF{sma11_N_n0_g0od_05012767}
```
