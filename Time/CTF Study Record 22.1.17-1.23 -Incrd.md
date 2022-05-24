# 学习记录22.1.17-1.23 -Incrd

## picoCTF Easy Peasy WP

Description:

```text
A one-time pad is unbreakable, but can you manage to recover the flag? (Wrap with picoCTF{}) nc mercury.picoctf.net 64260
```

otp.py:

```python
#!/usr/bin/python3 -u
import os.path

KEY_FILE = "key"
KEY_LEN = 50000
FLAG_FILE = "flag"


# 初始化函数
def startup(key_location):  # key_location = 0
    # 读取 flag 和 key
    flag = open(FLAG_FILE).read()
    kf = open(KEY_FILE, "rb").read()

    start = key_location  # 0
    stop = key_location + len(flag)  # len(flag)

    key = kf[start:stop]  # 从 key 中截取 [0:len(flag)] 部分
    key_location = stop   # key_location 后移至 len(flag) 位置

    print(f"key : {key}")
    print(f"flag : {flag}")
    # map(function, iterable, ...)，返回迭代器
    # flag 每一位与 key 每一位进行异或运算
    result = list(map(lambda p, k: "{:02x}".format(ord(p) ^ k), flag, key))
    print(f"result : {result}")
    print("This is the encrypted flag!\n{}\n".format("".join(result)))

    return key_location


def encrypt(key_location):
    ui = input("What data would you like to encrypt? ").rstrip()
    # rstrip 删除输入内容结尾的空格
    if len(ui) == 0 or len(ui) > KEY_LEN:
        return -1
    # 输入内容为空或长度超过密钥长度则退出循环
    start = key_location
    stop = key_location + len(ui)

    kf = open(KEY_FILE, "rb").read()

    # 结束位置超过 key 长度时返回开头
    if stop >= KEY_LEN:
        stop = stop % KEY_LEN
        key = kf[start:] + kf[:stop]
    else:
        key = kf[start:stop]
    key_location = stop

    result = list(map(lambda p, k: "{:02x}".format(ord(p) ^ k), ui, key))

    print("Here ya go!\n{}\n".format("".join(result)))

    return key_location


print("******************Welcome to our OTP implementation!******************")
c = startup(0)
while c >= 0:
    c = encrypt(c)

```

脚本逻辑还是比较清晰的，进入循环前先调用了 `startup(0)` 输出加密后的 flag，给出密钥长度为 50000，然后进入循环，加密用户输入的内容，加密方式只是简单的异或运算，只要得到加密 flag 所用的密钥即可得到 flag。加密时，对应加密内容的长度，密钥使用部分会同步向后移动，当移动到密钥尾端时，会重新回到开头，至此思路就明晰了，先填充 `50000 - len(encrypto_flag)` 长度的内容使得密钥回到开头，再输入已知的加密内容并根据加密结果反推得密钥。  
nc 连接后：

```text
C:\Users\45101>nc mercury.picoctf.net 64260
******************Welcome to our OTP implementation!******************
This is the encrypted flag!
51466d4e5f575538195551416e4f5300413f1b5008684d5504384157046e4959

What data would you like to encrypt?
```

使用 kali  
`(kali㉿kali)-[~/Documents]
└─$ python3 -c "print('\x00'*(50000-32)+'\n'+'\x00'*32)" | nc mercury.picoctf.net 64260`  
得到加密 flag 所用密钥为 `62275c786663615c783165725c786237225c7863315c7831375c7861305c7838`

decryption:

```python
import binascii

FLAG_LEN = len('51466d4e5f575538195551416e4f5300413f1b5008684d5504384157046e4959') // 2 # 32
encrypted_flag = binascii.a2b_hex('51466d4e5f575538195551416e4f5300413f1b5008684d5504384157046e4959')
key_true = binascii.a2b_hex('62275c786663615c783165725c786237225c7863315c7831375c7861305c7838')
flag = ''.join(list(map(lambda p, k: chr(p ^ k), encrypted_flag, key_true)))
print('picoCTF{%s}'% flag)
# picoCTF{3a16944dad432717ccc3945d3d96421a}
```

## Linux Shell管道

上面写命令写到了 `|` 符号，学习了一下管道(pipeline)  
pipeline 是 UNIX 系统，基础且重要的观念。连结上个指令的标准输出，做为下个指令的标准输入。  
Linux 管道的具体语法格式如下：

```shell
command1 | command2
command1 | command2 [ | commandN... ]
```

当在两个命令之间设置管道时，管道符 `|` 左边命令的输出就变成了右边命令的输入。只要第一个命令向标准输出写入，而第二个命令是从标准输入读取，那么这两个命令就可以形成一个管道。大部分的 Linux 命令都可以用来形成管道。
>这里需要注意，command1 必须有正确输出，而 command2 必须可以处理 command2 的输出结果；而且 command2 只能处理 command1 的正确输出结果，不能处理 command1 的错误信息。

## HGAME Easy RSA WP

最近的比赛的题，这道当是复习 RSA 了  

```python
from math import gcd
from random import randint
from gmpy2 import next_prime, invert
from Crypto.Util.number import getPrime
# from secret import flag

def encrypt(c):
    # getPrime Return a random N-bit prime number.
    p = getPrime(8)
    q = getPrime(8)
    # randint Return random integer in range [a, b], including both end points.
    e = randint(0, p * q)
    while gcd(e, (p - 1) * (q - 1)) != 1:
        e = int(next_prime(e))
    return e, p, q, pow(ord(c), e, p * q)

def decrypt(a) -> list:
    e, p, q, en_flag = a
    res = pow(en_flag, int(invert(e, (p - 1) * (q - 1))), p * q)
    return chr(res)



if __name__ == '__main__':
    #print(list(map(encrypt, flag)))
    en_flag = [(12433, 149, 197, 104), (8147, 131, 167, 6633), (10687, 211, 197, 35594), (19681, 131, 211, 15710), (33577, 251, 211, 38798), (30241, 157, 251, 35973), (293, 211, 157, 31548), (26459, 179, 149, 4778), (27479, 149, 223, 32728), (9029, 223, 137, 20696), (4649, 149, 151, 13418), (11783, 223, 251, 14239), (13537, 179, 137, 11702), (3835, 167, 139, 20051), (30983, 149, 227, 23928), (17581, 157, 131, 5855), (35381, 223, 179, 37774), (2357, 151, 223, 1849), (22649, 211, 229, 7348), (1151, 179, 223, 17982), (8431, 251, 163, 30226), (38501, 193, 211, 30559), (14549, 211, 151, 21143), (24781, 239, 241, 45604), (8051, 179, 131, 7994), (863, 181, 131, 11493), (1117, 239, 157, 12579), (7561, 149, 199, 8960), (19813, 239, 229, 53463), (4943, 131, 157, 14606), (29077, 191, 181, 33446), (18583, 211, 163, 31800), (30643, 173, 191, 27293), (11617, 223, 251, 13448), (19051, 191, 151, 21676), (18367, 179, 157, 14139), (18861, 149, 191, 5139), (9581, 211, 193, 25595)]
    flag = ''.join(list(map(decrypt, en_flag)))
    print(flag)
    # hgame{L00ks_l1ke_y0u've_mastered_RS4!}
```

## HGAME Dancing Line WP

题目给出一张图片，内容是一条弯折的线，背景为白色，线为蓝色，上面每隔一段距离有一个黑点，观察发现每个黑点之间大约都相差7个像素，推测是8个像素一组信息，线弯折的方向代表 0 和 1，以此传递信息，故解密脚本为

```python
import binascii
import numpy as np
from PIL import Image

image =Image.open(r'D:\Operator\Download\HGAME\Dancing Line.bmp').convert('RGB')
image_width = image.width
image_height = image.height
image_array = np.array(image)

def Color_Count(image):
    color_list = []
    for h_pos in range(image_height):
        for w_pos in range(image_width):
            if not list(image_array[h_pos, w_pos]) in color_list:
                color_list.append(list(image_array[w_pos, h_pos]))
    return color_list

def Not_Str(str):
    res = ''
    for i in str:
        if i == '1':
            res += '0'
        else:
            res += '1'
    return res
color_list = Color_Count(image)
print(f"出现的像素有{color_list}")
h_pos = w_pos = 0
data_binary = ''
while(w_pos != image_width-1 or h_pos != image_height-1):
    if list(image_array[h_pos, w_pos+1]) == [84, 150, 206] or list(image_array[h_pos, w_pos+1]) == [0, 0, 0]:
        data_binary += '1'
        w_pos += 1
    if list(image_array[h_pos+1, w_pos]) == [84, 150, 206] or list(image_array[h_pos+1, w_pos]) == [0, 0, 0]:
        data_binary += '0'
        h_pos += 1
if(w_pos == image_width):
    data_binary += '0' * (image_height-1 - h_pos)
else:
    data_binary += '1' * (image_width-1 - w_pos)

data_binary = Not_Str(data_binary)
flag = str(binascii.a2b_hex(hex(int(data_binary, 2))[2:]), 'utf-8')
print(flag)
# hgame{Danc1ng_L1ne_15_fun,_15n't_1t?}
```

学习了 PIL 中的 Image 库。  

## picoCTF The Numbers WP

Description  
The numbers... what do they mean?  
给出一张图片，上面有数字和左右大括号，猜测是字母编号  

```python
a = [16, 9, 3, 15, 3, 20, 6,'{',20, 8, 5, 14, 21, 13, 2, 5, 18, 19, 13, 1,19, 15, 14, '}']

res = ''
for i in range(len(a)):
    if isinstance(a[i], int):
        res += chr(a[i] + 96)
    else:
        res += a[i]
print(res)
# picoctf{thenumbersmason}
```

## picoCTF New Caesar WP

Description:  
We found a brand new type of encryption, can you break the secret code? (Wrap with picoCTF{})  mlnklfnknljflfmhjimkmhjhmljhjomhmmjkjpmmjmjkjpjojgjmjpjojojnjojmmkmlmijimhjmmj

new caesar.py:  

```python
import string

LOWERCASE_OFFSET = ord("a")
ALPHABET = string.ascii_lowercase[:16]  # 'abcdefghijklmnop'


def b16_encode(plain):
    enc = ""
    for c in plain:
        binary = "{0:08b}".format(ord(c))  # 每一位转为二进制
        enc += ALPHABET[int(binary[:4], 2)]  # 取二进制前四位转为十进制作为 ALPHABET 下标来获得密文
        enc += ALPHABET[int(binary[4:], 2)]  # 取二进制后四位，同上
    return enc


def shift(c, k):  # 偏移
    t1 = ord(c) - LOWERCASE_OFFSET
    t2 = ord(k) - LOWERCASE_OFFSET
    return ALPHABET[(t1 + t2) % len(ALPHABET)]


flag = "xxx"
key = "xxx"
assert all([k in ALPHABET for k in key])    # 检查 key 中的字母是否都在'abcdefghijklmnop'中
assert len(key) == 1                        # 要求 key 长度为 1

b16 = b16_encode(flag)
enc = ""
for i, c in enumerate(b16):                 # c 为迭代对象，i 为对应下标
    # 由于 len(key) == 1，故 key[i % len(key) 即为 key[0]
    enc += shift(c, key[i % len(key)])
print(enc)
# mlnklfnknljflfmhjimkmhjhmljhjomhmmjkjpmmjmjkjpjojgjmjpjojojnjojmmkmlmijimhjmmj
```

flag 先经过 `b16_encode` 函数（注意不是 base16），再通过 `shift` 函数加上了一个偏移量，得到密文，加密结构比较清晰，但是密钥是未知的，但是密钥只有 16 种可能，为 `ALPHABET` 中的一个元素，故考虑直接进行爆破。

now crack is:

```python
from base64 import encode
import string

LOWERCASE_OFFSET = ord("a")
ALPHABET = string.ascii_lowercase[:16]  # 'abcdefghijklmnop'

def re_shift(c, k): # 偏移
    t1 = ord(c) - LOWERCASE_OFFSET
    t2 = ord(k) - LOWERCASE_OFFSET
    return ALPHABET[(t1 - t2 + len(ALPHABET)) % len(ALPHABET)]

def b16_decode(plain):
    enc = ""
    for i in range(len(plain)//2):
        temp = chr((ALPHABET.find(plain[i*2]) << 4) + ALPHABET.find(plain[i*2+1]))
        if temp.isprintable():
            enc += temp
        else:
            return ''
    return enc


cipher = 'mlnklfnknljflfmhjimkmhjhmljhjomhmmjkjpmmjmjkjpjojgjmjpjojojnjojmmkmlmijimhjmmj'

for key in ALPHABET:
    cipher2 = ''
    for c in cipher:
        cipher2 += re_shift(c, key)
    cipher2 = b16_decode(cipher2)
    if(cipher2 != ''):
        print(cipher2)
```

输出：

```text
et_tu?_a2da1e18af49f649806988786deb2a6c
TcNcd.NP!SP T 'PU#(U%#('/%(''&'%STQ!P%R
íü×üý·×éºìé¹í¹°éî¼±î¾¼±°¸¾±°°¿°¾ìíêºé¾ë
```

加上 picoCTF{} 提交第一个就是正确 flag
