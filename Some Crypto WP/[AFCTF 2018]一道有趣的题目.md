# [AFCTF 2018]一道有趣的题目

task.py

```py
#加密代码
def encrypt(plainText):
    space = 10
    cipherText = ""
    for i in range(len(plainText)):
        if i + space < len(plainText) - 1:
            cipherText += chr(ord(plainText[i]) ^ ord(plainText[i + space]))
        else:
            cipherText += chr(ord(plainText[i]) ^ ord(plainText[space]))
        if ord(plainText[i]) % 2 == 0:
            space += 1
        else:
            space -= 1
    return cipherText
    
# 密码
# 15120d1a0a0810010a031d3e31000d1d170d173b0d173b0c07060206
```

需要注意的是，这里给出的密文并不是 cipherTexxt 直接的结果，而是其十六进制串，需要第一步转换。  

```py
c = "15120d1a0a0810010a031d3e31000d1d170d173b0d173b0c07060206"
# 这里刚开始被误导了，实际这串密文是十六进制串
cipher = [int(c[i:i+2], 16) for i in range(0, len(c), 2)]
```

观察算法发现，`space` 的值根据当前位置明文的奇偶性来变化，有就是明文当前位的二进制最低位的值，同时我们拥有密文，可以对明文二进制最低位进行爆破，检验方式为，用加密函数加密明文最低位，与密文最低位进行比较，相同则成功。  

```py
c = "15120d1a0a0810010a031d3e31000d1d170d173b0d173b0c07060206"
# 这里刚开始被误导了，实际这串密文是十六进制串
cipher = [int(c[i:i+2], 16) for i in range(0, len(c), 2)]
length = len(cipher)
print("cipher =", cipher)
print("length =", length)
cipher_low1 = []

# 获取密文最低位
def cal_low():
    for cipher_i in cipher:
        cipher_low1.append(cipher_i & 1)
    print("cipher_low1 =", cipher_low1)
    plain_low1 = []
    for i in tqdm(range(2 ** length)):
        temp_low1 = bin(i)[2:].zfill(length)
        space = 10
        found = True
        for i in range(length):
            if i + space < length - 1:
                xorres = int(temp_low1[i]) ^ int(temp_low1[i + space])
            else:
                xorres = int(temp_low1[i]) ^ int(temp_low1[space])
            if xorres != cipher_low1[i]:
                found = False
                break
            if int(temp_low1[i]) % 2 == 0:
                space += 1
            else:
                space -= 1
        if found:
            plain_low1.append(temp_low1)
            print("found, ", temp_low1)
    print(plain_low1)
    # "1010011010010101111111101001"
```

注意，算法爆破中与密文比较这一步，一定要计算的时候直接比对，有一位不同就退出当前循环，进入下一个循环，这样会大大降低爆破所需要的时间。  
爆破得出明文最低位后，我们就已知了 space 在每一状态的值，下一步，我一开始的想法是用解异或线性方程组的方式来写，但是失败了，方程组无法得出唯一解，应该是数据原因导致了信息不足，方程矩阵不满秩。  
然后我采用了另一种方法，即猜测明文结构为 `"afctf{" + "?" + "}"`，再慢慢推出每一位，比如加密的第一次循环是  
`cipherText[0] = plainText[0] ^ plainText[10]`  
而 `cipherText[0]` 和 `plainText[0]` 都是一直的，便可以求得 `plainText[10]`，以此类推。

exp

```py
c = "15120d1a0a0810010a031d3e31000d1d170d173b0d173b0c07060206"
# 这里刚开始被误导了，实际这串密文是十六进制串
cipher = [int(c[i:i+2], 16) for i in range(0, len(c), 2)]
length = len(cipher)
print("cipher =", cipher)
print("length =", length)
cipher_low1 = []

# 获取密文最低位
def cal_low():
    for cipher_i in cipher:
        cipher_low1.append(cipher_i & 1)
    print("cipher_low1 =", cipher_low1)
    plain_low1 = []
    for i in tqdm(range(2 ** length)):
        temp_low1 = bin(i)[2:].zfill(length)
        space = 10
        found = True
        for i in range(length):
            if i + space < length - 1:
                xorres = int(temp_low1[i]) ^ int(temp_low1[i + space])
            else:
                xorres = int(temp_low1[i]) ^ int(temp_low1[space])
            if xorres != cipher_low1[i]:
                found = False
                break
            if int(temp_low1[i]) % 2 == 0:
                space += 1
            else:
                space -= 1
        if found:
            plain_low1.append(temp_low1)
            print("found, ", temp_low1)
    # print(plain_low1)
plain_low1 = [int(i) for i in "1010011010010101111111101001"]

plain_text = [ord(i) for i in ("afctf{" + "\0" * (length - 7) + "}")]

def cal_space() -> list:
    pair = []
    space = 10
    for i in range(length):
        if i + space < length - 1:
            pair.append(i+space)
        else:
            pair.append(space)
        if plain_low1[i] % 2 == 0:
            space += 1
        else:
            space -= 1
    return pair
pair = cal_space()

count = 0
while 0 in plain_text:
    count += 1
    for i in range(length):
        if plain_text[i] != 0:
            plain_text[pair[i]] = plain_text[i] ^ cipher[i]
        elif plain_text[pair[i]] != 0:
            plain_text[i] = plain_text[pair[i]] ^ cipher[i]
    if count > 30:
        print("fail")
        break
print("flag found")
flag = "".join([chr(i) for i in plain_text])
print(flag)
```
