# [AFCTF 2018]Tiny LFSR

Encrypt.py

```py
import sys
from binascii import unhexlify

if (len(sys.argv) < 4):
    print("Usage: python Encrypt.py keyfile plaintext ciphername")
    exit(1)


def lfsr(R, mask):
    output = (R << 1) & 0xffffffffffffffff
    i = (R & mask) & 0xffffffffffffffff
    lastbit = 0
    while i != 0:
        lastbit ^= (i & 1)
        i = i >> 1
    output ^= lastbit
    return (output, lastbit)


R = 0
key = ""
with open(sys.argv[1], "r") as f:
    key = f.read()
    R = int(key, 16)
    f.close

mask = 0b1101100000000000000000000000000000000000000000000000000000000000

a = ''.join(
    [chr(int(b, 16)) for b in [key[i:i + 2] for i in range(0, len(key), 2)]])

f = open(sys.argv[2], "r") # plaintext
ff = open(sys.argv[3], "wb") # ciphername
s = f.read() # plaintext
f.close()
lent = len(s)

for i in range(0, len(a)):
    ff.write((ord(s[i]) ^ ord(a[i])).to_bytes(1, byteorder='big'))

for i in range(len(a), lent):
    tmp = 0
    for j in range(8):
        (R, out) = lfsr(R, mask)
        tmp = (tmp << 1) ^ out
    ff.write((tmp ^ ord(s[i])).to_bytes(1, byteorder='big'))
ff.close()

```

另外给出了 .bash_history.txt

```txt
python Encrypt.py key.txt Plain.txt cipher.txt
python Encrypt.py key.txt flag.txt flag_encode.txt
rm flag.txt
rm key.txt
```

已知明密文 Plain.txt 和 cipher.txt，以及加密的 flag，flag_encode.txt。  
观察加密代码，我们发现，密文的前一部分是由明文和密钥直接异或得到的，后一部分的内容是由密钥作为 LFSR 的初始状态来生成密钥流，用密钥流与明文做异或得到剩下的密文，由此我们可以知道密钥的长度即为 LFSR 一个状态的长度即 MASK 的长度，因此我们只要计算 (plain ^ cipher)\[:len(MASK)\] 即可获得 key，再通过 LFSR 函数获得余下的密钥流。

decrypt

```py
from Crypto.Util.number import *

mask = 0b1101100000000000000000000000000000000000000000000000000000000000
keylen = mask.bit_length() // 8
def lfsr(R, mask):
    output = (R << 1) & 0xffffffffffffffff
    i = (R & mask) & 0xffffffffffffffff
    lastbit = 0
    while i != 0:
        lastbit ^= (i & 1)
        i = i >> 1
    output ^= lastbit
    return (output, lastbit)

def bytes_xor(a: bytes, b: bytes) -> bytes:
    assert len(a) == len(b)
    return b"".join([long_to_bytes(_a ^ _b) for _a, _b in zip(a, b)])
    # return bytes(int.from_bytes(a, 'big') ^ int.from_bytes(b, 'big')).zfill(max(len(a), len(b)))

with open(r"D:\Operator\CTF-attachment\BUUCTF\Plain.txt", "rb") as f:
    plain = f.read()
with open(r"D:\Operator\CTF-attachment\BUUCTF\cipher.txt", "rb") as f:
    cipher = f.read()

key = bytes_xor(plain, cipher)[:keylen]

with open(r"D:\Operator\CTF-attachment\BUUCTF\flag_encode.txt", "rb") as f:
    flag_encode = f.read()

res = b''
res += bytes_xor(flag_encode[:keylen], key)
R = bytes_to_long(key)
for i in range(keylen, len(flag_encode)):
    tmp = 0
    for j in range(8):
        (R, out) = lfsr(R, mask)
        tmp = (tmp << 1) ^ out
    res += ((tmp ^ flag_encode[i])).to_bytes(1, byteorder='big')
print(res)

```

output

```txt
b'In computing, a linear-feedback shift register (LFSR) is a shift register whose input bit is a linear function of its previous state.\n\nThe most commonly used linear function of single bits is exclusive-or (XOR). Thus, an LFSR is most often a shift register whose input bit is driven by the XOR of some bits of the overall shift register value.\n\nThe initial value of the LFSR is called the seed, and because the operation of the register is deterministic, the stream of values produced by the register is completely determined by its current (or previous) state. 
Likewise, because the register has a finite number of possible states, it must eventually enter a repeating cycle. However, an LFSR with a well-chosen feedback function can produce a sequence of bits that appears random and has a very long cycle.\n\nApplications of LFSRs include generating pseudo-random numbers, pseudo-noise sequences, fast digital counters, and whitening sequences. Both hardware and software implementations of LFSRs are common.\n\nThe mathematics of a cyclic redundancy check, used to provide a quick check against transmission errors, are closely related to those of an LFSR.\n\nCongratulations! flag is afctf{read_is_hard_but_worthy}'
```

`afctf{read_is_hard_but_worthy}`
