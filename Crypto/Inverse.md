# 乘法逆元

这里总结整理一下乘法逆元的求法。

## 定义

在 $mod\ p$ 的意义下我们把 $x$ 的乘法逆元写作 $x^{-1}$  
乘法逆元有如下的性质：  
$$x\cdot x^{-1}\equiv 1\ (mod\ p)$$

## 1. 费马小定理

众所周知，费马小定理是欧拉定理的特殊情况，欧拉定理：  
$a, p$ 互素，则有  
$$a^{\phi(p)}\equiv 1\ (mod\ p) $$  
> 欧拉定理证明见 <https://www.cnblogs.com/1024th/p/11349355.html>

当 $p$ 为质数时，$\phi(p)=p-1$ ，即有  
$$a^{p-1}\equiv 1\ (mod\ p)$$
此即为费马小定理，上式变形为  
$$a\cdot a^{p-2}\equiv 1\ (mod\ p)$$  
显然 $a^{p-2}$ 即为 $a$ 的乘法逆元，用快速幂计算即可，复杂度 $O(log\ p)$  

```py
def power_mod(base, exponent, modulus):
    res = 1
    while exponent:
        if exponent & 1:
            res = res * base % modulus
        base = base * base % modulus
        exponent = exponent >> 1
    return res
```

运用费马小定理求逆元要求模数为质数，无法处理 $a,p$ 互质但 $p$ 不为质数的情况，下面介绍更好的运用扩展欧几里得算法求逆元。  

## 2. 扩展欧几里得

$$a\cdot a^{-1}\equiv 1\ (mod\ p)$$
$$\Rightarrow a\cdot a^{-1} +k\cdot p=1$$
扩展欧几里得的证明见 <https://www.cnblogs.com/Parsnip/p/10115948.html>。  

```py
def ext_gcd(a, b):    
    if b == 0:          
        return 1, 0, a     
    else:         
        x, y, gcd = ext_gcd(b, a % b)
        x, y = y, (x - (a // b) * y)
        return x, y, gcd
```

因此求逆元函数即为

```py
def ext_gcd(a, b):
    if b == 0:
        return 1, 0, a
    else:
        x, y, gcd = ext_gcd(b, a % b)
        x, y = y, (x - (a // b) * y)
        return x, y, gcd

def inverse(a, p):
    x, y, gcd = ext_gcd(a, p)
    if gcd != 1:
        raise ValueError("gcd(a, p) is not equal to 1")
    return x if x > 0 else x + p
```
