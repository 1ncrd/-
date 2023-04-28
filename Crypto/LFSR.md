# LFSR

线性反馈移位寄存器的反馈函数一般如下  
$$a_{i+n}=\sum_{j=1}^nc_ja_{i+n-j}$$
在 CTF 中 $c_j$ 一般在代码中为 MASK。

例

```py3
def lfsr(R, mask):
    output = (R << 1) & 0xf
    i = (R & mask) & 0xf
    lastbit = 0
    while i != 0:
        lastbit ^= (i & 1)
        i = i >> 1
    output ^= lastbit
    return (output, lastbit)

MASK = 0b1111
MASKSTR = bin(MASK)[2:].zfill(MASK.bit_length())
R = 0b1001
L = R.bit_length()
output = ""
for i in range(L):
    (R, out) = lfsr(R, MASK)
    output += str(out)
print(output)
```

其中的 `lfsr` 函数在题目中基本都是一样的。  

## Given n bits, mask

下面介绍在已知了 n 位的输出以及 MASK 的情况下如何逆推出 lfsr 的初始状态。  
考虑第 n 次生成输出比特的情形。  
此处用 c 表示除初始状态外的比特位。  

$statu:a_nc_0c_1...c_{n-1}$  
$output=c_n=a_n\oplus c_0\oplus c_1\oplus ...\oplus c_{n-1}$  

此时我们可以通过计算 $c_n\oplus c_0\oplus c_1\oplus ...\oplus c_{n-1}$ 即可得到 $a_n$  
通过这种方法向前逆推即可。  
试验代码


```py3
def lfsr(R, mask):
    output = (R << 1) & 0xf
    i = (R & mask) & 0xf
    lastbit = 0
    while i != 0:
        lastbit ^= (i & 1)
        i = i >> 1
    output ^= lastbit
    return (output, lastbit)

MASK = 0b1111
MASKSTR = bin(MASK)[2:].zfill(MASK.bit_length())
R = 0b1010
print("status :", bin(R)[2:].zfill(R.bit_length()))
L = R.bit_length()
output = ""
for i in range(L):
    (R, out) = lfsr(R, MASK)
    output += str(out)
print("output :", output)

temp = output
res = ""
for i in range(L):
    p = 0
    for j in range(L):
        p ^= int(temp[j]) & int(MASKSTR[j])
    res += str(p)
    temp = str(p) + temp[:-1]
print("initial status :", res[::-1])
```

```txt
status : 1010
output : 0101
initial status : 1010
```

成功还原。
通用 exp:

```py3
def inverse_lfsr(out, mask):
    out = out[::-1]
    mask = mask[::-1]
    index = []
    for i in range(len(mask)):
        if mask[i] == '1':
            index.append(i)
    print(index)
    for i in range(len(out)):
        mid = int(out[0])
        for j in range(len(index)-1):
            mid ^= int(out[index[j]+1])
        out = out[1:] + str(mid)
    return out[::-1]
```

## Given 2n bits

如果已知至少2n位的密钥流，但不知道抽头序列（MASK），则即为KPA问题，因为只要把前 n 个 bit $(a_1,\dots,a_n)$看成原本状态，则对后 n 个 bit $(b_1, \dots, b_n)$ 均有 $(b_i = \sum_{i=1}^{n}a_i\&p_i)$，$p_i$即为抽头序列，有 n 个这样的表达式，即为解 n 元一次方程，故而一定有解，通用 exp 如下

```py3
def inverse_lfsr(out, mask):
    out = out[::-1]
    mask = mask[::-1]
    index = []
    for i in range(len(mask)):
        if mask[i] == '1':
            index.append(i)
    print(index)
    for i in range(len(out)):
        mid = int(out[0])
        for j in range(len(index)-1):
            mid ^= int(out[index[j]+1])
        out = out[1:] + str(mid)
    return out[::-1]


def init_stream(known_plain, known_cipher):
    assert(len(known_plain) == len(known_cipher) and len(known_plain) <= 24)
    known_plain_dec = int(known_plain, 16)
    known_cipher_dec = int(known_cipher, 16)
    return bin(known_plain_dec ^ known_cipher_dec)[2:].rjust(4 * len(known_plain), '0')


def lfsr_crack_key(stream, key_length, p):
    assert(len(stream) >= 2 * key_length)
    solver = Solver()
    for i in range(len(stream) - key_length):
        cur = stream[i: i + key_length + 1]
        equation = ''
        for j in range(key_length):
            if cur[j] == '1':
                equation += 'p[' + str(j) + ']+'
            else:
                pass
        if len(equation):
            equation = equation[:-1] + ' == ' + str(cur[-1])
            solver.add(eval(equation))
    if solver.check() == sat:
        m = solver.model()
        feedback = ''.join([str(m[p[i]]) for i in range(key_length)])
        return stream[:key_length], feedback
    else:
        return False, False


def inverse_lfsr_kpa(stream):
    for key_length in tqdm(range(2, len(stream)//2 + 1)):
        p = []
        for i in range(32):
            p.append('p%d' % i)
        p = [BitVec(i, 1) for i in p]
        key, mask = lfsr_crack_key(stream, key_length, p)
        if (key, mask) != (False, False):
            return inverse_lfsr(key, mask)
```

## NLFSR

<https://github.com/0ssigeno/Writeups/blob/master/de1CTF2020/nlfsr/writeup.md>
