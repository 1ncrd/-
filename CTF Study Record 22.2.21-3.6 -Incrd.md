# 学习记录22.2.21-2.27 -Incrd

## picoCTF New Vignere

new_vignere.py  

```python
import string

LOWERCASE_OFFSET = ord("a")
ALPHABET = string.ascii_lowercase[:16]

def b16_encode(plain):
    enc = ""
    for c in plain:
        binary = "{0:08b}".format(ord(c))
  enc += ALPHABET[int(binary[:4], 2)]
        enc += ALPHABET[int(binary[4:], 2)]
    return enc

def shift(c, k):
    t1 = ord(c) - LOWERCASE_OFFSET
    t2 = ord(k) - LOWERCASE_OFFSET
    return ALPHABET[(t1 + t2) % len(ALPHABET)]

flag = "redacted"
assert all([c in "abcdef0123456789" for c in flag])

key = "redacted"
assert all([k in ALPHABET for k in key]) and len(key) < 15

b16 = b16_encode(flag)
enc = ""
for i, c in enumerate(b16):
    enc += shift(c, key[i % len(key)])
print(enc)

```

crack.py

```python
import string
import copy
from tqdm import tqdm

LOWERCASE_OFFSET = ord("a")
ALPHABET = string.ascii_lowercase[:16]  # 'abcdefghijklmnop'
cipher = "bkglibgkhghkijphhhejggikgjkbhefgpienefjdioghhchffhmmhhbjgclpjfkp"

def b16_encode(plain):
    enc = ""
    for c in plain:
        binary = "{0:08b}".format(ord(c))
        enc += ALPHABET[int(binary[:4], 2)]
        enc += ALPHABET[int(binary[4:], 2)]
    return enc

def b16_decode(C):
    plain = ""
    for c in range(len(cipher) // 2):
        temp = 0
        temp += ALPHABET.find(C[c*2]) << 4
        temp += ALPHABET.find(C[c*2+1])
        plain += chr(temp)
    return plain

def unshift(c, k):
    t1 = ord(c) - LOWERCASE_OFFSET
    t2 = ord(k) - LOWERCASE_OFFSET
    return ALPHABET[(t1 - t2 + len(ALPHABET)) % len(ALPHABET)]

def generate(sample):
    '''Returns a combination of sequence neutron sequences'''
    result = []
    rec = []
    def choose(key, dep):
        for i in range(len(key[dep])):
            rec.insert(dep, key[dep][i])
            if dep < len(key) - 1:
                choose(key, dep + 1)
            else:
                result.append(copy.deepcopy(rec))
            rec.pop(dep)
    choose(sample, 0)
    return result


flag_alphabet = "abcdef0123456789"

flag_alphabet_b16 = []

for i in flag_alphabet:
    flag_alphabet_b16.append(b16_encode(i))
flag_alphabet_b16_0 = list(set(flag_alphabet_b16[i][0] for i in range(len(flag_alphabet_b16))))
flag_alphabet_b16_1 = list(set(flag_alphabet_b16[i][1] for i in range(len(flag_alphabet_b16))))

for key_length in tqdm(range(1, 15)):
    key = []
    for key_i in range(key_length):
        key_i_list = []
        for key_temp in ALPHABET:
            flag = True
            for i in range(key_i, len(cipher), key_length):
                temp_decrypt = unshift(cipher[i], key_temp)
                if i % 2 == 0:
                    if not temp_decrypt in flag_alphabet_b16_0:
                        flag = False
                        break
                if i % 2 == 1:
                    if not temp_decrypt in flag_alphabet_b16_1:
                        flag = False
                        break
            if flag == True:
                key_i_list.append(key_temp)
        if key_i_list != []:
            key.append(key_i_list)
        else:
            break
        if key_i == key_length-1:
            key_all_possibility = generate(key)
            for key_one in key_all_possibility:
                print("Possible key : %s "%"".join(key_one))
                key_str = "".join(key_one[i][0] for i in range(len(key_one)))
                plaintext = ""
                for i, c in enumerate(cipher):
                    plaintext += unshift(c, key_str[i % len(key_str)])
                plaintext = b16_decode(plaintext)
                print(f"Possibe plaintext: picoCTF{{plaintext}}")

```

明文先经过了 `b16_encode` 函数处理，再进行维吉尼亚加密，导致传统的对维吉尼亚密码的攻击方式失效了。
但是由于 `assert all([c in "abcdef0123456789" for c in flag])`，可见 flag 中出现的字符种类有限，则其 `b16_encode` 后的结果也是有限的，解题思路便建立在此处，先把 `"abcdef0123456789"` 中的所有字母经过 `b16_encode` 处理并记录在 `flag_alphabet_b16` 中，然后对 Vignere 密钥进行逐位爆破，通过观察密钥解密后的结果是否满足 `flag_alphabet_b16` 来进行密钥爆破。  
然后写脚本还是写了挺久的，一开始爆破是用的全排列，复杂度太高了根本爆不出来，然后优化发现只要逐位尝试即可，这样复杂度就只是 $O(n)$，然后又花了一点时间用递归写 `generate` 函数，不得不说算法这块还是太嫩了。

## picoCTF b00tl3gRSA2

Description  
In RSA d is a lot bigger than e, why don't we use d to encrypt instead of e?  
Connect with nc jupiter.challenges.picoctf.org 19566.  

nc

```text
c: 28470409436943640954517096639682967321364839067071184234511935629859176469424879338101198049737226909337576597854705454994012862945776103098472930525472381948811810674928905358640498977259183934050696966839945982211583263727360583080171707865020051920211133280252710531632909486183973128505841829329495732667
n: 81944913388552113935228956868511073570243664655175337895055990097654925203517319610503588477506098717668629709919644014071587408322247002569160856832040403857165565904698402928943863901751474958724103836103861400597911151837692630869834455581779434189848373645196260166074756164740993827278179490579843463429
e: 81827379448052489315397235521094499102147735569657439886875340036328047821746249405224321234316975424270078491634820989866592837066585449274968246237380700287129464460968801931076446244386672396854962672851354093023262009790975704581192762955992031605796669880761462741851204118460840183116671191519718746949
```

猜测一般加密时常用的 e = 65537，直接解密即可。

## picoCTF b00tl3gRSA3

Description  
Why use p and q when I can use more?  
Connect with nc jupiter.challenges.picoctf.org 4557.  

```text
nc jupiter.challenges.picoctf.org 4557.
c: 11162960302969489764512346319451075304526220158721147040435927799562445475940039706793618155837611676301389131701249524598774879506882953466418775428867914079675548493659349009455568191931217876165857242666735755429976235695751596132487644139775043197472746496198691036107064454922119277447004613271691991139351608518495643338280996285651891061
n: 56616626999850826109640705263523690435052562263284032816443532934631111684975034977726036810588922570374544339425687056880865438788569986087770408117728081120202524265688539959816910571358207671257766033470393488073902256483911659239840561994147506906946177726453079943928861683376274186220389546793947306869335419637219957433025182832067748359
e: 65537
```

根据描述得知，题中的 n 有超过两个的因数，因此大大降低了分解 n 的难度，直接分解 n 求解 phi(n) 即可获取私钥，贴一个新网站，可以在分解 n 后直接计算欧拉函数 <https://www.alpertron.com.ar/ECM.HTM>  

## TQLCTF Misc Wordle

赛题描述  
What is the best strategy for wordle?  

main.py

```python
import os
import random
from flag import award

random.seed(os.urandom(64))

with open('allowed_guesses.txt', 'r') as f:
    allowed_guesses = set([x.strip() for x in f.readlines()])

with open('valid_words.txt', 'r') as f:
    valid_words = [x.strip() for x in f.readlines()]


MAX_LEVEL = 512
GREEN = '\033[42m  \033[0m'
YELLOW = '\033[43m  \033[0m'
WHITE = '\033[47m  \033[0m'


def get_challenge():
    # id = random.getrandbits(32)
    # answer = valid_words[id % len(valid_words)]
    # return hex(id)[2:].zfill(8), answer

    # To prevent the disclosure of answer
    id = random.randrange(len(valid_words) * (2 ** 20))
    answer = valid_words[id % len(valid_words)]
    id = (id // len(valid_words)) ^ (id % len(valid_words))
    return hex(id)[2:].zfill(5), answer


def check(answer, guess):
    answer_chars = []
    for i in range(5):
        if guess[i] != answer[i]:
            answer_chars.append(answer[i])
    result = []
    for i in range(5):
        if guess[i] == answer[i]:
            result.append(GREEN)
        elif guess[i] in answer_chars:
            result.append(YELLOW)
            answer_chars.remove(guess[i])
        else:
            result.append(WHITE)
    return ' '.join(result)


def game(limit):
    round = 0
    while round < MAX_LEVEL:
        round += 1
        id, answer = get_challenge()
        print(f'Round {round}: #{id}')
        correct = False
        for _ in range(limit):
            while True:
                guess = input('> ')
                if len(guess) == 5 and guess in allowed_guesses:
                    break
                print('Invalid guess')
            result = check(answer, guess)
            if result == ' '.join([GREEN] * 5):
                print(f'Correct! {result}')
                correct = True
                break
            else:
                print(f'Wrong!   {result}')
        if not correct:
            print('You failed...')
            return round - 1

    return MAX_LEVEL


def choose_mode():
    print('Choose gamemode:')
    print('0: Easy mode')
    print('1: Normal mode')
    print('2: Hard mode')
    print('3: Insane mode')
    # print('4: Expert mode')
    # print('-1: Osu! mode')
    mode = int(input('> '))
    assert 0 <= mode <= 3
    return mode


if __name__ == '__main__':
    print('Guess the WORDLE in a few tries.')
    print('Each guess must be a valid 5 letter word.')
    print('After each guess, the color of the tiles will change to show how close your guess was to the word.')

    while True:
        mode = choose_mode()
        if mode == 0:
            limit = 999999999
        else:
            limit = 7 - mode
        final_level = game(limit)
        if final_level < MAX_LEVEL:
            pass
        else:
            print('You are the Master of WORDLE!')
        flag = award(mode, final_level)
        print(f'Here is you award: {flag}')

```

猜单词游戏，可选四个模式，Mode 0 最多可以尝试 999999999 次，Mode 1 - 3 只能尝试 7 - mode 次，即最高难度只能尝试 4 次，而猜词库有多达 4090 个单词，每次猜词会告知每一位的字母是否配对，或是否在次单词中出现过，想要获取 flag，需要在 Mode 3 下连续成功猜词 512 次，依靠纯算法答题是不合实际的，赛后复现注意到，在多次选择模式时，并没有更换随机数种子，语句 `random.seed(os.urandom(64))` 仅在程序刚开始时执行了一次，因此可以考虑进行 python 的伪随机预测，观察函数 `random.randrange()` 的定义：

```python
def __init_subclass__(cls, /, **kwargs):
    """Control how subclasses generate random integers.

    The algorithm a subclass can use depends on the random() and/or
    getrandbits() implementation available to it and determines
    whether it can generate random integers from arbitrarily large
    ranges.
    """

    for c in cls.__mro__:
        if '_randbelow' in c.__dict__:
            # just inherit it
            break
        if 'getrandbits' in c.__dict__:
            cls._randbelow = cls._randbelow_with_getrandbits
            break
        if 'random' in c.__dict__:
            cls._randbelow = cls._randbelow_without_getrandbits
            break

def _randbelow_with_getrandbits(self, n):
    "Return a random int in the range [0,n).  Returns 0 if n==0."

    if not n:
        return 0
    getrandbits = self.getrandbits
    k = n.bit_length()  # don't use (n-1) here because n can be 1
    r = getrandbits(k)  # 0 <= r < 2**k
    while r >= n:
        r = getrandbits(k)
    return r

def randrange(self, start, stop=None, step=1):
    """Choose a random item from range(start, stop[, step]).

    This fixes the problem with randint() which includes the
    endpoint; in Python this is usually not what you want.

    """

    # This code is a bit messy to make it fast for the
    # common case while still doing adequate error checking.
    istart = int(start)
    if istart != start:
        raise ValueError("non-integer arg 1 for randrange()")
    if stop is None:
        if istart > 0:
            return self._randbelow(istart)
        raise ValueError("empty range for randrange()")

```

可以看到此处 `random.randrange(len(valid_words) * (2 ** 20))` 函数实际就是在调用 `getrandbits(k)`，其中 `k = n.bit_length()`，此处 len(valid_words) \* (2 ** 20) = 4090 * (2 ** 20) 略小于 $2^{32}$，根据代码，程序生成的随机数若大于 $4060×2^{20}$，随机数会被丢弃并重新生成，故能连续取得 624 个随机数的概率为 $(4090/4096)^{624} = 0.4006237249847311$，还是比较高的，因此脚本逻辑即为：

1. 通过 Mode 0 猜单词获取 624 个随机数字。
2. 进入 Mode 3 预测随机数直接给出答案。

>Python random module cracker: <https://github.com/tna0y/Python-random-module-cracker>  
>Official Exp: <https://github.com/Konano/CTF-challenges/blob/master/wordle/exp.py>

## 图片隐写的一点内容

### png 文件头信息

- （固定）八个字节89 50 4E 47 0D 0A 1A 0A为png的文件头
- （固定）四个字节00 00 00 0D（即为十进制的13）代表数据块的长度为13
- （固定）四个字节49 48 44 52（即为ASCII码的IHDR）是文件头数据块的标示（IDCH）
- （可变）13位数据块（IHDR)
  - 前四个字节代表该图片的宽
  - 后四个字节代表该图片的高
  - 后五个字节依次为：
    Bit depth、ColorType、Compression method、Filter method、Interlace method
- （可变）剩余四字节为该png的CRC检验码，由从IDCH到IHDR的十七位字节进行crc计算得到。

使用 pngcheck 或者 stegsolve 可以检查 CRC 是否正确，windows 打开图片时即使 CRC 校验错误，图片仍能正常打开，而 Linux 在打开图片时若校验错误，文件会直接显示错误无法打开，可以通过这些方式来判断文件头（通常是缩小宽和高以隐藏信息）是否被修改。  

png 图片真实宽高爆破

```python
import zlib
import struct
import sys
crc32key = 0x4BBF572D #补上0x，winhex copy hex value。
data = bytearray(b'\x49\x48\x44\x52\x00\x00\x02\x85\x00\x00\x01\x65\x08\x06\x00\x00\x00')   #winhex copy grep hex。
n = 4095 # 理论上0xffffffff,但考虑到屏幕实际/cpu，0x0fff就差不多了
for w in range(n):
    width = bytearray(struct.pack('>i', w))
    for h in range(n):
        height = bytearray(struct.pack('>i', h))
        for x in range(4):
            data[x+4] = width[x]
            data[x+8] = height[x]
        crc32result = zlib.crc32(data)
        if crc32result == crc32key:
            print(width,height)
            sys.exit(0)
```

### 附加式的隐写

附加字符串或者文件到图片文件后，一般使用 binwalk 识别文件头即可辨别，或使用 winhex 观察文件尾。

### LSB 隐写

通过修改颜色最低位来隐藏信息，使用 stegsolve 观察即可。

## ZIP CRC 爆破

当压缩包文件中有小于 6 Bytes 的文件时可以考虑此方法，若大小大于 4 Bytes 则不建议用脚本爆破，现成的爆破工具。  
<https://github.com/theonlypwner/crc32>  
Usage: python3 crc32.py reverse (CRC32数值，前面加上0x)  

## picoCTF john_pollard

Description:  
Sometimes RSA certificates are breakable  
这里我用 OpenSSL 解出的 n 居然是错误的，难以理解，只能换用在线工具 <https://www.sslchecker.com/certdecoder>  

output  

```text
Certificate:
    Data:
        Version: 1 (0x0)
        Serial Number: 12345 (0x3039)
    Signature Algorithm: md2WithRSAEncryption
        Issuer: CN=PicoCTF
        Validity
            Not Before: Jul  8 07:21:18 2019 GMT
            Not After : Jun 26 17:34:38 2019 GMT
        Subject: OU=PicoCTF, O=PicoCTF, L=PicoCTF, ST=PicoCTF, C=US, CN=PicoCTF
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (53 bit)
                Modulus: 4966306421059967 (0x11a4d45212b17f)
                Exponent: 65537 (0x10001)
    Signature Algorithm: md2WithRSAEncryption
         07:6a:5d:61:32:c1:9e:05:bd:eb:77:f3:aa:fb:bb:83:82:eb:
         9e:a2:93:af:0c:2f:3a:e2:1a:e9:74:6b:9b:82:d8:ef:fe:1a:
         c8:b2:98:7b:16:dc:4c:d8:1e:2b:92:4c:80:78:85:7b:d3:cc:
         b7:d4:72:29:94:22:eb:bb:11:5d:b2:9a:af:7c:6b:cb:b0:2c:
         a7:91:87:ec:63:bd:22:e8:8f:dd:38:0e:a5:e1:0a:bf:35:d9:
         a4:3c:3c:7b:79:da:8e:4f:fc:ca:e2:38:67:45:a7:de:6e:a2:
         6e:71:71:47:f0:09:3e:1b:a0:12:35:15:a1:29:f1:59:25:35:
         a3:e4:2a:32:4c:c2:2e:b4:b5:3d:94:38:93:5e:78:37:ac:35:
         35:06:15:e0:d3:87:a2:d6:3b:c0:7f:45:2b:b6:97:8e:03:a8:
         d4:c9:e0:8b:68:a0:c5:45:ba:ce:9b:7e:71:23:bf:6b:db:cc:
         8e:f2:78:35:50:0c:d3:45:c9:6f:90:e4:6d:6f:c2:cc:c7:0e:
         de:fa:f7:48:9e:d0:46:a9:fe:d3:db:93:cb:9f:f3:32:70:63:
         cf:bc:d5:f2:22:c4:f3:be:f6:3f:31:75:c9:1e:70:2a:a4:8e:
         43:96:ac:33:6d:11:f3:ab:5e:bf:4b:55:8b:bf:38:38:3e:c1:
         25:9a:fd:5f
```

注意到 `Modulus: 4966306421059967 (0x11a4d45212b17f)` 仅长 53 bit，因此直接分解即可。  
picoCTF{73176001,67867967}  

## picoCTF Clouds(Stuck)

Reference:

- <https://github.com/gov-ind/ctf-writeups/blob/main/2021/picoctf/clouds/clouds.md>  
- <https://link.springer.com/content/pdf/10.1007%2F3-540-45473-X_16.pdf>

## TQLCTF HardRSA

hardrsa.py

```python
from sage.all import *
from Crypto.Util.number import bytes_to_long
from secret import flag

assert flag.startswith("TQLCTF{")
assert flag.endswith("}")

beta  = 0.223
delta = 0.226
gama  = 0.292
n_size = 1024
bound_q = 2**int(n_size*beta)
bound_p = 2**int(n_size*(1-beta))

while True:
    p = random_prime(bound_p, proof=False)
    q = random_prime(bound_q, proof=False)
    N = p * q
    if q < pow(N, beta) and gcd(p-1, (q-1)/2) == 1:
        break
        
assert p.is_prime()
assert q.is_prime()

while True:
    dp = randint(0, 2**int(n_size * delta))
    dq = randint(0, (q-1))
    if gcd(dp, p-1) == 1 and gcd(dq, (q-1)/2) == 1:
        break
        
d = crt([dp, dq], [p-1, (q-1)/2])
e = inverse_mod(d, (p-1)*(q-1)/2)
assert d > 2 * N ** gama

m = bytes_to_long(flag.encode())
print(f"N={N}\ne={e}")
print(f"c={pow(m,e,N)}")

#N=17898692915537057253027340409848777379525990043216176404521845629792286203459681133425615460580210961931628383718238208402935069434512008997422795968676635886265184398587211149645171148089263697198308448184434844310802022336492929706736607458307830462086477073132852687216229392067680807130235274969547247389
#e=7545551830675702855400776411651853827548700298411139797799936263327967930532764763078562198672340967918924251144028131553633521880515798926665667805615808959981427173796925381781834763784420392535231864547193756385722359555841096299828227134582178397639173696868619386281360614726834658925680670513451826507
#c=2031772143331409088299956894510278261053644235222590973258899052809440238898925631603059180509792948749674390704473123551866909789808259315538758248037806795516031585011977710042943997673076463232373915245996143847637737207984866535157697240588441997103830717158181959653034344529914097609427019775229834115

```

写之前再次去梳理了一下 CRT 在 RSA 中的应用。  
___
中国剩余定理 (CRT)：  

$p 和 q 是互相独立的大素数，n = p * q，对于任意(m1, m2), (0 <= m1 < p, 0<=m2< p)$
$必然存在一个唯一的 m , 0 <= m < n$  
使得  
$m1 \equiv m\ mod\ p$  
$m2 \equiv m\ mod\ q$  
即给定一个(m1,m2)，其满足上述等式的 m  必定唯一存在。  

所以解密 RSA 的流程 $c^d\ mod\ n$，可以分解为 $m1=c^d\ mod\ p$以及$m2=c^d\ mod\ q$方程组，然后再计算 m。  
此时指数 d 仍较大，运算还是比较消耗性能。  
对等式 $c^d\ mod\ p$  
令  
$d = k(p-1) + r$  
则  
$c^d\ mod\ p$  
$=c^{k(p-1) + r}\ mod\ p$  
$=c^r * c^{k(p-1)}\ mod\ p$  
因为 $c^{p-1}\ mod\ p = 1$ （欧拉定理）  
$c^d\ mod\ p=c^r\ mod\ p$  
r 是 d 除 p-1 的余数，即 r = d mod (p-1)  
所以 $c^d\ mod\ p$可以降阶为 $c^{(d\ mod\ p-1)}\ mod\ p$  
即  
$c^{dp}\equiv c^d\  mod\ p$
___
回过头看题，`d > 2 * N ** gama`，无法使用 Boneh and Durfee Attack。  
具体原理是利⽤题⾯条件给出等式：$ed_pq = (k − 1)(N − q) + N$, 因此双变 量多项式 $f(x, y) = x(N − y) + N$ mod e 有⼩根 $(k-1, q)$，使⽤coppersmith attack就能给出解了。（这段话我还需要亿点时间去理解）

exp

```python
from Crypto.Util.number import * 
def matrix_overview(BB): 
    for ii in range(BB.dimensions()[0]): 
        a = ('%02d ' % ii) 
        for jj in range(BB.dimensions()[1]):
            if BB[ii,jj] == 0: 
                a += ' ' 
            else:
                a += 'X' 
            if BB.dimensions()[0] < 60: 
                a += ' ' 
                print(a) 
def lattice_attack(PR, pol, e, mm, tt, X, Y): 
    x,y = PR.gens() 
    polys = [] 
    for ii in range(mm+1): 
        for jj in range(0, mm-ii+1): 
            poly = e ^ (mm - ii) * x ^ jj * pol ^ ii 
            polys.append(poly)

    for ii in range(mm+1): 
        for jj in range(1, tt+1): 
            poly = e ^ (mm - ii) * y ^ jj * pol ^ ii 
            polys.append(poly) 

    polys = sorted(polys) 
    monomials = [] 
    for poly in polys: 
        monomials += poly.monomials() 
    monomials = sorted(set(monomials)) 
    dims1 = len(polys) 
    dims2 = len(monomials) 
    M = matrix(QQ, dims1, dims2) 
    for ii in range(dims1): 
        M[ii, 0] = polys[ii](0, 0) 
        for jj in range(dims2): 
            if monomials[jj] in polys[ii].monomials(): 
                M[ii, jj] = polys[ii](x * X, y * Y).monomial_coefficient(monomials[jj]) 
    
    matrix_overview(M) 
    print('=' * 128) 
    B = M.LLL() 
    print('LLL done') 
    det = B.det() 
    print(f"monomials: {monomials}") 
    nn = len(monomials) 
    matrix_overview(B) 
    H = [(i, 0) for i in range(dims1)] 
    H = dict(H) 
    for j in range(dims2):
        for i in range(dims1): 
            H[i] += (monomials[j] * B[i, j]) / monomials[j](X, Y) 

    PQ.<q> = PolynomialRing(ZZ) 
    H = list(H.values()) 
    solutions = [] 
    print(len(H)) 
    for i in range(len(H)): 
        for j in range(i+1, len(H)): 
            pol1 = PR(H[i]) 
            pol2 = PR(H[j]) 
            rr = pol1.resultant(pol2, y) 
            if rr.is_zero() or rr.monomials() == [1]: 
                continue 
            sols = rr(q,q).roots() 
            for sol in sols: 
                solx = sol[0] 
                if solx == -1: 
                    continue 
                try:
                    soly = pol1(solx, q).roots()[0][0] 
                    solutions.append((solx, soly)) 
                    print('='*128) 
                except: 
                    pass 
                if len(solutions) > 0: 
                    break 
            if len(solutions) > 0: 
                break 
        if len(solutions) > 0: 
            break 
    return solutions 

N=17898692915537057253027340409848777379525990043216176404521845629792286203459681133425615460580210961931628383718238208402935069434512008997422795968676635886265184398587211149645171148089263697198308448184434844310802022336492929706736607458307830462086477073132852687216229392067680807130235274969547247389
e=7545551830675702855400776411651853827548700298411139797799936263327967930532764763078562198672340967918924251144028131553633521880515798926665667805615808959981427173796925381781834763784420392535231864547193756385722359555841096299828227134582178397639173696868619386281360614726834658925680670513451826507
c=2031772143331409088299956894510278261053644235222590973258899052809440238898925631603059180509792948749674390704473123551866909789808259315538758248037806795516031585011977710042943997673076463232373915245996143847637737207984866535157697240588441997103830717158181959653034344529914097609427019775229834115 
beta = 0.233 
delta = 0.226 
gama = 0.292 
n_size = 1024 
P.<x,y> = PolynomialRing(ZZ)
pol = N + x * (N-y) 
m = 5 
t = 5 
X = 2^460 
Y = 2^240 
print(lattice_attack(P, pol, e, m, t, X, Y)) 
# q = 169137218869484728712814942277531819318585090563481420862437016566714151 
# p = N / q 
# assert p*q == N 
# d = inverse_mod(e, (p-1)*(q-1)) 
# flag = long_to_bytes(pow(c, d, N)) 
# print(flag)
```

## SUSCTF large case

```python
from Crypto.Util.number import *
from secret import e,message

def pad(s):
    if len(s)<3*L:
        s+=bytes(3*L-len(s))
    return s

L=128
p=127846753573603084140032502367311687577517286192893830888210505400863747960458410091624928485398237221748639465569360357083610343901195273740653100259873512668015324620239720302434418836556626441491996755736644886234427063508445212117628827393696641594389475794455769831224080974098671804484986257952189021223
q=145855456487495382044171198958191111759614682359121667762539436558951453420409098978730659224765186993202647878416602503196995715156477020462357271957894750950465766809623184979464111968346235929375202282811814079958258215558862385475337911665725569669510022344713444067774094112542265293776098223712339100693
r=165967627827619421909025667485886197280531070386062799707570138462960892786375448755168117226002965841166040777799690060003514218907279202146293715568618421507166624010447447835500614000601643150187327886055136468260391127675012777934049855029499330117864969171026445847229725440665179150874362143944727374907
n=p*q*r

assert isPrime(GCD(e,p-1)) and isPrime(GCD(e,q-1)) and isPrime(GCD(e,r-1)) and e==GCD(e,p-1)*GCD(e,q-1)*GCD(e,r-1)
assert len(message)>L and len(message)<2*L
assert b'SUSCTF' in message
m=bytes_to_long(pad(message))

c=pow(m,e,n)
print(c)
'''
2832775557487418816663494645849097066925967799754895979829784499040437385450603537732862576495758207240632734290947928291961063611897822688909447511260639429367768479378599532712621774918733304857247099714044615691877995534173849302353620399896455615474093581673774297730056975663792651743809514320379189748228186812362112753688073161375690508818356712739795492736743994105438575736577194329751372142329306630950863097761601196849158280502041616545429586870751042908365507050717385205371671658706357669408813112610215766159761927196639404951251535622349916877296956767883165696947955379829079278948514755758174884809479690995427980775293393456403529481055942899970158049070109142310832516606657100119207595631431023336544432679282722485978175459551109374822024850128128796213791820270973849303929674648894135672365776376696816104314090776423931007123128977218361110636927878232444348690591774581974226318856099862175526133892
'''
```

题目给出了 n 的三个因子 p, q, r，根据语句 `assert isPrime(GCD(e,p-1)) and isPrime(GCD(e,q-1)) and isPrime(GCD(e,r-1)) and e==GCD(e,p-1)*GCD(e,q-1)*GCD(e,r-1)` 可以得知 e 为 p, q, r 各自的某个素因子的乘积，首先需要解决的问题是 e 究竟为哪三个因子的乘积，下面进行推导：  
$(c 密文，m 明文)$  
$c \equiv m^e\ mod\ n$  
$c \equiv m^e\ mod\ pqr$  
设 e 的三个因子分别为 $p_1,\ q_1,\ r_1$  
$c \equiv m^{p_1q_1r_1}\ mod\ pqr$  
$c^{(p-1)/p_1} \equiv m^{(p-1)q_1r_1}\ mod\ pqr$  
根据费马小定理  
$m^{p-1}\equiv1\ mod\ p$ (p is a prime)  
故  
$m^{(p-1)q_1r_1}\equiv1\ mod\ p$  
$(m^{p_1q_1r_1}\ mod\ pqr) \equiv 1\ mod\ p$  
$(c^{(p-1)/p_1}\ mod\ pqr) \equiv 1\ mod\ p$  
因此只要对 $p_1$ 进行穷举即可找到 e 的所有因子。
题中的 p 已在 factordb 中分解，q 也能在有限时间中在 yafu 中成功分解，r 也已在 factordb 存在了几个较小的素因子，但是也已经存在符合条件的因子了。  
以 p 为例子

```python
fp = [2, 7, 757, 1709, 85015583 , 339028665499, 149105250954771885483776047]
for i in fp:
    if pow(c,(p-1)//i,p)==1:
        print(i)
#757
```

由于本题 $e$ 与 $\phi(n)$ 不互素，无法用常规方式求解，需要使用 AMM 算法进行开根。运算前先进行一些化简。

```python
def pad(s):
    if len(s)<3*L:
        s+=bytes(3*L-len(s))
    return s

L=128
assert len(message)>L and len(message)<2*L
assert b'SUSCTF' in message
m=bytes_to_long(pad(message))
```

可知 flag 长度在 1032 bit 到 2040 bit 间，其 2048 到 3096 bit 的部分只是填充了 `b"\x00"`，可以去掉。  
$c \equiv m^e(2^{1024})^e\ mod\ n$  
$c*2^{-1024e} \equiv m^e\ mod\ n$  

同时由于其长度为 1032 bit 到 2040 bit，考虑模数 n 的三个因子的大小，$p *q > 2^{2040}$，这里可以将模数 n 转化为 p \* q，以求解降低复杂度。  
$dr_1 = inv(r_1, (p-1)*(q-1))$  
$c = c^{dr_1}\ mod\ pq$  
$c \equiv m^{p_1q_1}\ mod\ pq$  

再利用求逆元的方法得到 $m^{p_1}\ mod\ q$ 和 $m^{q_1}\ mod\ p$，接着使用现成的 AMM 算法对上式进行开根得到 $m\ mod\ p$ 的 $q_1$ 种可能性和 $m\ mod\ q$ 的 $p_1$ 种可能性，用 CRT 对二者进行组合，用 "SUSCTF" 进行检验，CRT 部分用 8 个线程跑，几分钟就可以出答案了。  

exp

```python
import random
import math
import time
import multiprocessing
from Crypto.Util.number import *
from sympy.ntheory.modular import crt


def AMM(x, e, p):
    y = random.randint(1, p - 1)
    while pow(y, (p - 1) // e, p) == 1:
        y = random.randint(1, p - 1)
    # p-1 = e^t*s
    t = 1
    s = 0
    while p % e == 0:
        t += 1
        print(t)
    s = p // (e**t)
    # s|ralpha-1
    k = 1
    while ((s * k + 1) % e != 0):
        k += 1
    alpha = (s * k + 1) // e
    # 计算 a = y^s b = x^s h =1
    # h 为 e 次非剩余部分的积
    a = pow(y, (e**(t - 1)) * s, p)
    b = pow(x, e * alpha - 1, p)
    c = pow(y, s, p)
    h = 1
    #
    for i in range(1, t - 1):
        d = pow(b, e**(t - 1 - i), p)
        if d == 1:
            j = 0
        else:
            j = -math.log(d, a)
        b = b * (pow(pow(c, e, p), j, p))
        h = h * pow(c, j, p)
        c = pow(c, e, p)
    # return (pow(x, alpha * h, p)) % p
    root = (pow(x, alpha * h, p)) % p
    roots = set()
    for i in range(e):
        mp2 = root * pow(a, i, p) % p
        assert (pow(mp2, e, p) == x)
        roots.add(mp2)
    return roots


def CRTPAIR(p, q, mp, mq):
    start = time.time()
    for mpp in mp:
        for mqq in mq:
            try:
                res = int(crt((p, q), (mpp, mqq))[0])
                solution = long_to_bytes(res)
                if b'SUSCTF' in solution:
                    print(solution)
                    print("Finished in {} seconds.".format(time.time() -
                                                           start))
            except:
                continue


def main():
    p = 127846753573603084140032502367311687577517286192893830888210505400863747960458410091624928485398237221748639465569360357083610343901195273740653100259873512668015324620239720302434418836556626441491996755736644886234427063508445212117628827393696641594389475794455769831224080974098671804484986257952189021223
    q = 145855456487495382044171198958191111759614682359121667762539436558951453420409098978730659224765186993202647878416602503196995715156477020462357271957894750950465766809623184979464111968346235929375202282811814079958258215558862385475337911665725569669510022344713444067774094112542265293776098223712339100693
    r = 165967627827619421909025667485886197280531070386062799707570138462960892786375448755168117226002965841166040777799690060003514218907279202146293715568618421507166624010447447835500614000601643150187327886055136468260391127675012777934049855029499330117864969171026445847229725440665179150874362143944727374907
    c = 2832775557487418816663494645849097066925967799754895979829784499040437385450603537732862576495758207240632734290947928291961063611897822688909447511260639429367768479378599532712621774918733304857247099714044615691877995534173849302353620399896455615474093581673774297730056975663792651743809514320379189748228186812362112753688073161375690508818356712739795492736743994105438575736577194329751372142329306630950863097761601196849158280502041616545429586870751042908365507050717385205371671658706357669408813112610215766159761927196639404951251535622349916877296956767883165696947955379829079278948514755758174884809479690995427980775293393456403529481055942899970158049070109142310832516606657100119207595631431023336544432679282722485978175459551109374822024850128128796213791820270973849303929674648894135672365776376696816104314090776423931007123128977218361110636927878232444348690591774581974226318856099862175526133892
    n = p * q * r

    # tmp = pow(int(1 << 1024), int(e), n)
    tmp = 2794203162952680694875426764547234241112236710433123774476303768639242351566319207612773628883250609134659396011750795113351981408956541443986997306105869563120160376511155383832592237253107342927670770094240045412123787825031261131955433947396826167219004667304636335427373984885928591487526163086731412269053200262557436796244981351739716063496342017497841802350338687039580076905949641402173299773716271511639533823663740291331408514189072329517625171120136705677613965360814741037067953490597466636290290725085921897578223035738383932219334876192857916281288629471625406358741715112812225419217748429901501082216480552255233899368763011103720695984389763743356559299690991047172680728215625377751497287365075742929734077041112027582350488222091280835389084342367259161290929159777553525296385682720359499417021854388648183468514374707670903349123145819166174953312125050648613697527164777642887701658900202492759171557250
    c = inverse(tmp, n) * c % n  # remove the padding

    p_1 = 757
    q_1 = 66553
    r_1 = 5156273
    d_r_1 = inverse(r_1, (p - 1) * (q - 1))
    c = pow(c, d_r_1, p * q)  # remove the r

    d_q_1 = inverse(q_1, p - 1)
    d_p_1 = inverse(p_1, q - 1)
    c_p = pow(c, d_q_1, p)
    c_q = pow(c, d_p_1, q)
    mp = list(AMM(c_p, 757, p))
    mq = list(AMM(c_q, 66553, q))

    print("Start CRT...")

    for i in range(0, len(mq), len(mq) // 8 + 1):
        proc = multiprocessing.Process(target=CRTPAIR, args=(p, q, mp, mq[i:i + len(mq) // 8 + 1]))
        proc.start()

if __name__ == "__main__":
    main()
```

## D^3CTF 2022 d3factor

找到了现成的算法：[New attacks on RSA with Moduli $N = p^rq$](https://eprint.iacr.org/2015/399.pdf)  
其中 Theorem 4 描述了当 $|d_1-d_2|<N^{r(r-1)/(r+1)^2}$ 时，在多项式时间内分解 N 的方法，根据其 Example 2 提供的方法，使用 sage 中 small_roots 封装的方法即可求解。

exp

```python
from Crypto.Util.number import long_to_bytes
from hashlib import md5
from gmpy2 import iroot
c = 2420624631315473673388732074340410215657378096737020976722603529598864338532404224879219059105950005655100728361198499550862405660043591919681568611707967
N = 1476751427633071977599571983301151063258376731102955975364111147037204614220376883752032253407881568290520059515340434632858734689439268479399482315506043425541162646523388437842149125178447800616137044219916586942207838674001004007237861470176454543718752182312318068466051713087927370670177514666860822341380494154077020472814706123209865769048722380888175401791873273850281384147394075054950169002165357490796510950852631287689747360436384163758289159710264469722036320819123313773301072777844457895388797742631541101152819089150281489897683508400098693808473542212963868834485233858128220055727804326451310080791
e1 = 425735006018518321920113858371691046233291394270779139216531379266829453665704656868245884309574741300746121946724344532456337490492263690989727904837374279175606623404025598533405400677329916633307585813849635071097268989906426771864410852556381279117588496262787146588414873723983855041415476840445850171457530977221981125006107741100779529209163446405585696682186452013669643507275620439492021019544922913941472624874102604249376990616323884331293660116156782891935217575308895791623826306100692059131945495084654854521834016181452508329430102813663713333608459898915361745215871305547069325129687311358338082029
e2 = 1004512650658647383814190582513307789549094672255033373245432814519573537648997991452158231923692387604945039180687417026069655569594454408690445879849410118502279459189421806132654131287284719070037134752526923855821229397612868419416851456578505341237256609343187666849045678291935806441844686439591365338539029504178066823886051731466788474438373839803448380498800384597878814991008672054436093542513518012957106825842251155935855375353004898840663429274565622024673235081082222394015174831078190299524112112571718817712276118850981261489528540025810396786605197437842655180663611669918785635193552649262904644919
r = 7
# N = p ^ 7 * q
PR.<x> = PolynomialRing(Zmod(N))
a = (e2-e1) * inverse_mod(e1*e2, N)
f = x - a   # define the function of solution
roots = f.small_roots(X=2^1000, beta=0.4)
if roots:
    g = gcd(int(roots[0]-a), N)
    p = iroot(int(g), r-1)[0]
    q = N // pow(p, r)
    n = p * q
    e = 0x10001
    phi = (p-1) * (q-1)
    d = inverse_mod(e, phi)
    msg = long_to_bytes(pow(int(c), int(d), int(n)))
    flag = 'd3ctf{'+md5(msg).hexdigest()+'}'
    print(flag)
```
