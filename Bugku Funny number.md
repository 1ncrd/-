# Bugku Funny number

```py
int.from_bytes(bytes, byteorder, *, signed=False)
```

可实现不固定长度的bytes类型数据转int类型数据，byteorder标志小字节顺序还是大字节顺序
根据结果还原flag，其中byteorder='little'代表小端序（反序），假设 $t$ 为 $s$ 反序字符串对应的int值，$p$ 为结果值，根据已知关系有：

t左移10000位后后175位值为结果值。

因 $a<<b \Rightarrow a\cdot 2^b$ ，故 $t<<10000 \Rightarrow t\cdot 2^{10000}$，又 $t\cdot 2^{10000}$ 以 175位的 $p$ 结尾，即：

$p = (t\cdot 2^{10000}) \bmod (10^{175})$

但此时不能直接应用模逆运算计算出 $t$ ，因为 $\gcd(2^{10000},10^{175}) \neq 1$；

做一下转换：

$p \equiv (t\cdot 2^{10000}) \pmod {10^{175}} \ \Rightarrow t\cdot 2^{10000}=x\cdot 10^{175}+p$

分解 $p$ 发现：

$p=2^{176} \cdot 3 \cdot 43973 \cdot 69653 \cdot 6642192645148709014118321101167435034612406484841133642520224597359790421504311588434603251039359463852561066413$

设 $y=\cfrac{p}{2^{175}}$，则

$t\cdot 2^{10000}=x\cdot 10^{175}+2^{175}\cdot y \ \Rightarrow t\cdot 2^{9825}=x\cdot 5^{175}+ y \ \Rightarrow y \equiv t \cdot 2^{9825} \pmod {5^{175}} \ \Rightarrow y \cdot (2^{9825})^{-1} \equiv t \pmod {5^{175}}$

通过求模逆可还原 $t$ ，再还原出flag。

```py
from gmpy2 import invert

n = pow(5,175)
p = 5845718273413614238047854434058144506973237928951593664100212455023083304425941087047510727554535833686148194478724602632928856425119454505382766186798132132909079456410238976

y = p // pow(2,175)
k = pow(2, 9825, n)
kinv = int(invert(k, n))
t = (y * kinv) % n
print(t)
#t=int.from_bytes(str(s).encode(), byteorder='little')

flag = bytes.fromhex(hex(t)[2:])[::-1]
print(flag)
#flag{NuM8eR_7HE0rY_1s_S0_Funny~}
```