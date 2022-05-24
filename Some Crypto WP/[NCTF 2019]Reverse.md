# [NCTF 2019]Reverse

task.py

```py
import os
import pyDes


flag = "NCTF{******************************************}"
key = os.urandom(8)

d = pyDes.des(key)
cipher = d.encrypt(flag.encode())

with open('cipher', 'wb') as f:
    f.write(cipher)

# Leak: d.Kn[10] == [0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1]
```

DES 相关参考:  
<https://zh.wikipedia.org/wiki/%E8%B3%87%E6%96%99%E5%8A%A0%E5%AF%86%E6%A8%99%E6%BA%96#%E7%AE%97%E6%B3%95%E6%8F%8F%E8%BF%B0>  
<https://zh.wikipedia.org/wiki/DES%E8%A1%A5%E5%85%85%E6%9D%90%E6%96%99#%E6%89%A9%E5%BC%A0%E5%87%BD%E6%95%B0_(E%E5%87%BD%E6%95%B0)>  
注意：第一个链接中所描述的 DES 密钥产生过程中的左移，实际是循环左移，中文维基翻译不准确。

题中给出第十一个子密钥，由于产生子密钥前经过了 PC-2 的置换，丢弃了 8 bit 的数据，因此根据已知条件，只有 $2^8$ 中密钥情况，可以采用爆破，由 PC-2 逆置换，回到密钥调度前的状态，空余七位进行爆破，再根据密钥产生过程中循环左移的次数进行循环右移，恢复密钥刚经过 PC-1 处理后的状态，PC-1 将原始的 64-bit 密钥选出 56-bit 作为实际用作加密的密钥，其余 8-bit 的密钥实际是被丢弃的，因此最终恢复的密钥的那 8-bit 只要随意填充即可。

decrypt.py

```py
import pyDes
import os

# flag = "NCTF{******************************************}"
# Leak: d.Kn[10] == [0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1]
# d = pyDes.des(key)

key10 = [
    0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1,
    0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1
]
PC1 = [
    56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34,
    26, 18, 10, 2, 59, 51, 43, 35, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45,
    37, 29, 21, 13, 5, 60, 52, 44, 36, 28, 20, 12, 4, 27, 19, 11, 3
]
PC2 = [
    13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9, 22, 18, 11, 3, 25, 7, 15, 6, 26,
    19, 12, 1, 40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47, 43, 48, 38, 55,
    33, 52, 45, 41, 49, 35, 28, 31
]
movenum = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]  # 对应16轮中每一轮的循环左移位数


def getRE_PC2():
    RE_PC2 = [-1] * 56
    for i in PC2:
        RE_PC2[i] = i
    return RE_PC2


def getPC1_DiscardedBits():
    temp = [i for i in range(64)]
    for i in PC1:
        temp.remove(i)
    return temp


def getPC2_DiscardedBits():
    temp = [i for i in range(64)]
    for i in PC2:
        temp.remove(i)
    return temp


def ReductionKey(sub_key, round):
    sub_key_l = sub_key[:len(sub_key) // 2]
    sub_key_r = sub_key[len(sub_key) // 2:]
    for i in range(round, -1, -1):
        for j in range(movenum[i]):
            # 循环右移
            sub_key_l = sub_key_l[-1:] + sub_key_l[:-1]
            sub_key_r = sub_key_r[-1:] + sub_key_r[:-1]
    return sub_key_l + sub_key_r


curdir = os.path.split(os.path.realpath(__file__))[0]
with open(str(os.path.join(curdir, r'cipher')), 'rb') as f:
    cipher = f.read()

cipher_list = list(cipher)

RE_PC2 = getRE_PC2()
PC1_DiscardedBits = getPC1_DiscardedBits()
PC2_DiscardedBits = getPC2_DiscardedBits()

temp_sub_key = [0] * 56
for j in range(len(PC2)):
    temp_sub_key[PC2[j]] = key10[j]

for i in range(2**8):
    restore_bits = list(int(j, 2) for j in bin(i)[2:])
    restore_bits = [0] * (8 - len(restore_bits)) + restore_bits

    for j in range(len(restore_bits)):
        temp_sub_key[PC2_DiscardedBits[j]] = restore_bits[j]

    temp_sub_key1 = ReductionKey(temp_sub_key, 10)

    temp_key = [0] * 64
    for index, j in enumerate(PC1):
        temp_key[j] = temp_sub_key1[index]

    key = bytes()
    for i in range(8):
        dig = 0
        for j in range(8):
            dig = dig * 2 + temp_key[i * 8 + j]
        key += dig.to_bytes(1, 'big')

    d = pyDes.des(key)
    flag = d.decrypt(cipher)
    if (b'CTF' in flag):
        print("flag =", flag)
# flag = b'NCTF{1t_7urn3d_0u7_7h47_u_2_g00d_@_r3v3rs3_1snt}'
```
