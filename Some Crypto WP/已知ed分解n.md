# 已知 ed 分解 n

<https://www.di-mgt.com.au/rsa_factorize_n.html>

```py
def getpq(n, e, d):
    while True:
        k = e * d - 1
        g = random.randint(0, n)
        while k % 2 == 0:
            k = k // 2
            temp = gmpy2.powmod(g, k, n)-1
            if gmpy2.gcd(temp, n) > 1 and temp != 0:
                return gmpy2.gcd(temp, n)

def getpq(n, ed):
    while True:
        k = ed - 1
        g = random.randint(0, n)
        while k % 2 == 0:
            k = k // 2
            temp = gmpy2.powmod(g, k, n)-1
            if gmpy2.gcd(temp, n) > 1 and temp != 0:
                return gmpy2.gcd(temp, n)
```
