# [BSidesCF 2019]RsaOS

题目：

```txt
nc node4.buuoj.cn 26662

      ___           ___           ___           ___           ___
     /\  \         /\  \         /\  \         /\  \         /\  \
    /::\  \       /::\  \       /::\  \       /::\  \       /::\  \
   /:/\:\  \     /:/\ \  \     /:/\:\  \     /:/\:\  \     /:/\ \  \
  /::\~\:\  \   _\:\~\ \  \   /::\~\:\  \   /:/  \:\  \   _\:\~\ \  \
 /:/\:\ \:\__\ /\ \:\ \ \__\ /:/\:\ \:\__\ /:/__/ \:\__\ /\ \:\ \ \__\
 \/_|::\/:/  / \:\ \:\ \/__/ \/__\:\/:/  / \:\  \ /:/  / \:\ \:\ \/__/
    |:|::/  /   \:\ \:\__\        \::/  /   \:\  /:/  /   \:\ \:\__\
    |:|\/__/     \:\/:/  /        /:/  /     \:\/:/  /     \:\/:/  /
    |:|  |        \::/  /        /:/  /       \::/  /       \::/  /
     \|__|         \/__/         \/__/         \/__/         \/__/


> help
Unprivileged commands:
    date                Get the date
    debug               Debug the OS.
    echo                Echo the arguments.
    enable              Enable all commands as privileged.
    exit                Exit the OS.
    foldhash            Get foldhash of first argument
    get-publickey       Retrieve the Public Key
    help                Get information about all commands.
    md5                 Get md5 of first argument

Privileged commands:
    get-flag            Get the flag.
    get-privatekey      Retrieve the Private Key
    security            Get information about security.
```

公钥和详细的题目内容

```txt
> help security
DBG: CRC-32(0x65ba5dc5) SIG(0x3305c41233266f256e0ea10c616fa6d2f3130a34142d88c59d4136789b0f388095372c9ec4060b498fe47f9a257a3ce7060996a501d3322c6506c80d8387bb61497b5812772cb92d2656470b8035894f1bc1f2a621ca27d61f5544dd183380c3af6fe3e6d64e01a47c0e90fb46c257aec853ab7c0dabbe899ca21a0e5f54b204)
security

        Authentication and authorization for operations is provided by RSA signing.
        Unpriviliged commands are automatically signed by the client using the IEEE
        CRC-32 of the full command line.

        Privileged commands must be manually signed by RSA over the FoldHash of the
        full command line.  FoldHash is a hash that was developed in response to the
        Shattered attack on SHA-1.  FoldHash provides 80 bits of security by use of
        an exclusive-or operation on the output of the standard SHA-1 hash split in
        two.

        All RSA signing operations are unpadded signatures of the hash value in
        big endian order.  This avoids attacks where only bad sources of entropy are
        available.

> get-publickey
DBG: CRC-32(0x8731d92b) SIG(0x14f70ca0e44bd03ddb5c0d4f63b96f17c56b58574024efae1a0918c236475bfb75f39959cb1068b09f4b4f91d45db74205dc895c7ed647f4de5b26fb62970ea5152a56c6dfc86bda282b7db246b4af0d4232eb49317ce0e16f13a63330e12204a264236c18ad45130968752eb7cc353d3ceca2a8f2d8edaae17a87668f2c09ce)
Public key parameters:
N: 0xd888075370effdb016d85de8c894ee7ac2764527210d8ce1d8bd14a06c67de148b4680781366002f9649e3885e18ab950120c660970ab9a499ea74ea7aa38fe732940b5204300ef7b96a608efec1a74007a4b1d592cf9eb23890d8fa416202857d0e0f9ebad79324d03d09db0502ff4bae0b2dfc0b150ddea806a5ff24e2d32f
E: 0x10001
```

签名使用的算法是 RSA + CRC-32/FoldHash，
对于 Privileged 的命令，命令的签名使用的哈希算法是 FoldHash，对于 Unprivileged 的命令，使用 CRC-32，根据 Security 信息的最后一条，输入 get-flag 时，可以隔一个空格在后面输入其他的值对签名内容进行改变而不影响 get-flag 命令的执行。  
因此题中要想获取 flag，只需要获取 $(FoldHash("get-flag\ \dots"))^d\ mod\ n$ 的值，私钥 d 无从获取，因此需要其他的方法来还原出签名。  
先回顾一下 RSA 签名过程：  
$消息 x, RSA 公私钥 e, d, n$  
$sign(x) = hash(x)^d\ mod\ n$  
$验签，比较 hash(x)\ mod\ n\ 和\ sign(x)^e\ mod\ n，相等则验签成功$  
若 Hash(x) 可因数分解，则由 RSA 的乘法同态性，有  
$sig1 = {h_1}^d\ mod\ n$  
$sig2 = {h_2}^d\ mod\ n$  
$\Rightarrow sig = (h_1*h_2)^d\ mod\ n = {h_1}^d*{h_2}^d\ mod\ n$  
$= sig1*sig2\ mod\ n$  
因子多于 2 个时有相同的结论。因此可以尝试获取签名 sig 的因子，即尝试获取 hash(x) 的因子再使用加密机获得 sig，这里的 hash 指题中给出的 FoldHash 算法，若因子小于 32-bit，则可以利用对 Unprivileged 命令的签名构造出 sig，CRC-32 不限制明文长度时，构造明文获取特定的 CRC32 的值是比较容易的。  
$sig = crc32(x)^d\ mod\ n$  
我们要做的就是使 crc32(x) = hash(x) 的因子。  
一个非常好的工具 <https://www.nayuki.io/page/forcing-a-files-crc-to-any-value>  
尝试分解 foldhash(b'get-flag')

```py
from hashlib import *
def foldhash(x):
    h = sha1(x).digest()
    return bytes_to_long(xor(h[:10], h[10:]))

a = b'get-flag'
b = foldhash(a)
fac = factor(b)
for i in fac:
    print(i[0], "< 2^32 ?", i[0] < 2**32)
```

out

```txt
2 < 2^32 ? True
3 < 2^32 ? True
5 < 2^32 ? True
29 < 2^32 ? True
498535537 < 2^32 ? True
396808855493 < 2^32 ? False
```

随便加点后缀或者写个循环枚举，所有因子都小于 2^32 的概率还是很可观的。  
这里我改为 "get-flag -"

out

```txt
2 < 2^32 ? True
5 < 2^32 ? True
2729 < 2^32 ? True
2767 < 2^32 ? True
2896031 < 2^32 ? True
1024701211 < 2^32 ? True
```

exp

```py
import re
import random
from sympy import factorint
from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes
from hashlib import sha1
import sys
sys.path.append("D:\Operator\Python\Programming_Files\CTF") 
from forcecrc32 import *

s = remote('node4.buuoj.cn', 27785)
s.sendlineafter(b'> ', b'debug enable')

def foldhash(x):
    h = sha1(x).digest()
    return bytes_to_long(xor(h[:10], h[10:]))


def get_publickey():
    s.sendlineafter(b'> ', b'get-publickey')
    s.recvuntil(b'N: ')
    N = int(s.recvline().strip(), 16)
    s.recvuntil(b'E: ')
    e = int(s.recvline().strip(), 16)
    return (N, e)

def get_sig(cmd):
    s.sendlineafter(b'> ', cmd)
    r = re.search(r'CRC-32\(0x([a-f0-9]+)\) SIG\(0x([a-f0-9]+)\)', s.recvline().decode())
    return map(lambda x: int(x, 16), r.groups())

payload = b"get-flag -"
factors = factorint(foldhash(payload))
N, e = get_publickey()
print("N =", N)
final_sig = 1
for fac in factors:
    assert fac < 2**32
    send = modify_bytes_crc32(b'echo xxxx', 5, fac)
    crc, sig = get_sig(send)
    print("crc =", crc)
    for i in range(factors[fac]):
        final_sig *= sig

final_sig = final_sig % N
s.sendline(payload)
s.sendlineafter(b'RSA(FoldHash) sig: ', hex(final_sig).encode())

print(s.recv())
```

out

```txt
[x] Opening connection to node4.buuoj.cn on port 27785
[x] Opening connection to node4.buuoj.cn on port 27785: Trying 117.21.200.166
[+] Opening connection to node4.buuoj.cn on port 27785: Done
N = 152053493188785380386569544595406953568251552084011566269403213621999713109505155872105564103040115675201110625913282667946584428778614500364229967467481221516263129038153104558948930841348081570926801598485672186682688130364296301937141499642082959500364703105166045705427666931615577053728090839589377463087
New CRC-32 successfully verified
crc = 2
New CRC-32 successfully verified
crc = 5
New CRC-32 successfully verified
crc = 2729
New CRC-32 successfully verified
crc = 2767
New CRC-32 successfully verified
crc = 2896031
New CRC-32 successfully verified
crc = 1024701211
b'The flag is: flag{7b38402f-0fa2-45b5-ae53-c65e36b3476e}\n\n'
[*] Closed connection to node4.buuoj.cn port 27785
```
