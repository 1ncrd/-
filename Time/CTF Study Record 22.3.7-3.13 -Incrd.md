# 学习记录22.3.7-3.13 -Incrd

## D^3CTF qcg

记录一下二元 coppersmith 的写法。（我写不出来）

```python
import itertools

def small_roots(f, bounds, m=1, d=None):
    if not d:
        d = f.degree()
    R = f.base_ring()
    N = R.cardinality()
    f /= f.coefficients().pop(0)
    f = f.change_ring(ZZ)
    G = Sequence([], f.parent())
    for i in range(m+1):
        base = N^(m-i) * f^i
        for shifts in itertools.product(range(d), repeat=f.nvariables()):
            g = base * prod(map(power, f.variables(), shifts))
            G.append(g)
    B, monomials = G.coefficient_matrix()
    monomials = vector(monomials)
    factors = [monomial(*bounds) for monomial in monomials]
    for i, factor in enumerate(factors):
        B.rescale_col(i, factor)
    B = B.dense_matrix().LLL()
    B = B.change_ring(QQ)
    for i, factor in enumerate(factors):
        B.rescale_col(i, 1/factor)
    H = Sequence([], f.parent().change_ring(QQ))
    for h in filter(None, B*monomials):
        H.append(h)
        I = H.ideal()
        if I.dimension() == -1:
            H.pop()
        elif I.dimension() == 0:
            roots = []
            for root in I.variety(ring=ZZ):
                root = tuple(R(root[var]) for var in f.variables())
                roots.append(root)
            return roots
    return []
```

有了这个此题的第一步就很简单了。

```python
import hashlib
from Crypto.Util.number import *
import itertools

UnKnownBits = 146

def small_roots(f, bounds, m=1, d=None):
    if not d:
        d = f.degree()
    R = f.base_ring()
    N = R.cardinality()
    f /= f.coefficients().pop(0)
    f = f.change_ring(ZZ)
    G = Sequence([], f.parent())
    for i in range(m+1):
        base = N^(m-i) * f^i
        for shifts in itertools.product(range(d), repeat=f.nvariables()):
            g = base * prod(map(power, f.variables(), shifts))
            G.append(g)
    B, monomials = G.coefficient_matrix()
    monomials = vector(monomials)
    factors = [monomial(*bounds) for monomial in monomials]
    for i, factor in enumerate(factors):
        B.rescale_col(i, factor)
    B = B.dense_matrix().LLL()
    B = B.change_ring(QQ)
    for i, factor in enumerate(factors):
        B.rescale_col(i, 1/factor)
    H = Sequence([], f.parent().change_ring(QQ))
    for h in filter(None, B*monomials):
        H.append(h)
        I = H.ideal()
        if I.dimension() == -1:
            H.pop()
        elif I.dimension() == 0:
            roots = []
            for root in I.variety(ring=ZZ):
                root = tuple(R(root[var]) for var in f.variables())
                roots.append(root)
            return roots
    return []

a = 3591518680290719943596137190796366296374484536382380061852237064647969442581391967815457547858969187198898670115651116598727939742165753798804458359397101
c = 6996824752943994631802515921125382520044917095172009220000813718617441355767447428067985103926211738826304567400243131010272198095205381950589038817395833
p = 7386537185240346459857715381835501419533088465984777861268951891482072249822526223542514664598394978163933836402581547418821954407062640385756448408431347
r1h = 67523583999102391286646648674827012089888650576715333147417362919706349137337570430286202361838682309142789833 << UnKnownBits
r2h = 70007105679729967877791601360700732661124470473944792680253826569739619391572400148455527621676313801799318422 << UnKnownBits
# r1 = (a * secret^2 + c) % p
# r1 >> 146 = r1h
# r2 = (a * r1^2 + c) % p
# r2 >> 146 = r2h
P.<x, y> = PolynomialRing(Zmod(p))
f = (x + r2h) - (a*(r1h + y)^2 + c)
print(small_roots(f, [2^146, 2^146], m=3, d=6))
```

类似于 RSA 高位攻击的思想。
第二步就是解一个有限域的一元二次方程，直接用 PolynomialRing(Zmod(p)) 的 roots() 方法即可。
完整 exp

```python
import hashlib
from Crypto.Util.number import *

import itertools

UnKnownBits = 146

def small_roots(f, bounds, m=1, d=None):
    if not d:
        d = f.degree()
    R = f.base_ring()
    N = R.cardinality()
    f /= f.coefficients().pop(0)
    f = f.change_ring(ZZ)
    G = Sequence([], f.parent())
    for i in range(m+1):
        base = N^(m-i) * f^i
        for shifts in itertools.product(range(d), repeat=f.nvariables()):
            g = base * prod(map(power, f.variables(), shifts))
            G.append(g)
    B, monomials = G.coefficient_matrix()
    monomials = vector(monomials)
    factors = [monomial(*bounds) for monomial in monomials]
    for i, factor in enumerate(factors):
        B.rescale_col(i, factor)
    B = B.dense_matrix().LLL()
    B = B.change_ring(QQ)
    for i, factor in enumerate(factors):
        B.rescale_col(i, 1/factor)
    H = Sequence([], f.parent().change_ring(QQ))
    for h in filter(None, B*monomials):
        H.append(h)
        I = H.ideal()
        if I.dimension() == -1:
            H.pop()
        elif I.dimension() == 0:
            roots = []
            for root in I.variety(ring=ZZ):
                root = tuple(R(root[var]) for var in f.variables())
                roots.append(root)
            return roots
    return []

a = 3591518680290719943596137190796366296374484536382380061852237064647969442581391967815457547858969187198898670115651116598727939742165753798804458359397101
c = 6996824752943994631802515921125382520044917095172009220000813718617441355767447428067985103926211738826304567400243131010272198095205381950589038817395833
p = 7386537185240346459857715381835501419533088465984777861268951891482072249822526223542514664598394978163933836402581547418821954407062640385756448408431347
r1h = 67523583999102391286646648674827012089888650576715333147417362919706349137337570430286202361838682309142789833 << UnKnownBits
r2h = 70007105679729967877791601360700732661124470473944792680253826569739619391572400148455527621676313801799318422 << UnKnownBits
# r1 = (a * secret^2 + c) % p
# r1 >> 146 = r1h
# r2 = (a * r1^2 + c) % p
# r2 >> 146 = r2h
P.<x, y> = PolynomialRing(Zmod(p))
f = (x + r2h) - (a*(r1h + y)^2 + c)
print(small_roots(f, [2^146, 2^146], m=3, d=6))
x1 = 9089234402520025586415667640120652372860183
y1 = 50712831100361370819145886978385347931029768
r2 = x1 + r2h
r1 = y1 + r1h
P.<s> = PolynomialRing(Zmod(p))
g = a*s^2+c - r1
# g = g.monic()
print(g.roots())
root1 = 4041175780036883478815867467461047550933982405318965631484489156717330002773568568536902190010839138410185231519872805730895806870604072973967270279033142
root2 = 3345361405203462981041847914374453868599106060665812229784462734764742247048957655005612474587555839753748604882708741687926147536458567411789178129398205
x1 = bytes_to_long(hashlib.sha512(b'%d'%(root1)).digest())
x2 = bytes_to_long(hashlib.sha512(b'%d'%(root2)).digest())
enc = 6176615302812247165125832378994890837952704874849571780971393318502417187945089718911116370840334873574762045429920150244413817389304969294624001945527125
print(long_to_bytes(x1^^enc))
print(long_to_bytes(x2^^enc))
```

## D^3CTF BUG

task.py

```python
from Crypto.Util.number import *
from secret import flag
assert flag.startswith("D3CTF{")
assert flag.endswith("}")
message = bytes_to_long(flag[6:-1]) # 去除前后缀
assert message < 2**64
mask = 0b1010010000001000000010001001010010100100000010000000100010010100

def lfsr_MyCode(R,mask):
    output = (R << 1) & 0xffffffffffffffff
    i = (R ^ mask) & 0xffffffffffffffff

    lastbit = 0
    while i != 0:
        lastbit ^= (i & 1)  # lastbit 为 i 每一位的异或结果
        i = i>>1

    output ^= lastbit
    # ^ (0/1), 仅改变最低位，前面进行了output = (R << 1)，故为向最低位添加lastbit
    return (output,lastbit)

def lfsr_CopiedfromInternet(R,mask):
    output = (R << 1) & 0xffffffffffffffff
    i = (R & mask) & 0xffffffffffffffff
#          ^
    lastbit = 0
    while i != 0:
        lastbit ^= (i & 1)
        i = i>>1
  
    output ^= lastbit
    return (output,lastbit)

f=open("standardResult","w")
R=message
for i in range(35):
    (R, out) = lfsr_CopiedfromInternet(R,mask)
    f.write(str(out))
f.close()

f=open("myResult","w")
R=message
for i in range(35):
    (R, out) = lfsr_MyCode(R,mask)
    f.write(str(out))
f.close()

#Why are the results always different?!!
#Can you help me debug my code? QAQ
```

这题实际可以转化为一个有 70 条等式，最多64个未知数的方程组问题，并且是在 (mod 2) 意义下的。
设
$message = m_0m_1...m_{63}$
$mask = k_0k_1...k_{63}$
$standardResult = c_0c_1...c_{63}$
$myResult = y_0y_1...y_{63}$

根据 `lfsr_CopiedfromInternet`，有如下等式(均为 $mod\ 2$ 意义下)
$c_0 = m_0k_0 + m_1k_1 + ... + m_{63}k_{63}$
$c_1 = m_1k_0 + m_2k_1 + ... + m_{63}k_{62} + c_0k_{63}$
$=m_0k_0k_{63}+m_1(k_0+k_1k_{63})+m_2(k_1+k_2k_{63})+...+m_{63}(k_{62}+k_{63}k_{63})$
以此类推

同理根据 `lfsr_MyCode`，有
$y_0=m_0+k_0+m_1+k_1+...+m_{63}+k_{63}$
$=m_0+m_1+...+m_{63}$
`mask` 中 1 的个数为偶数，故 k 均可以省去。
$y_1=m_1+m_2+...m_{63}+y_0$
$=m_0+2m_1+2m_2+...2m_{63}$
以此类推
然后构造一个矩阵方程即可，由于方程组的单个方程间有较明显的规律，可以进行如下构造。

```python
T1 = matrix(GF(2),64,64)
T2 = matrix(GF(2),64,64)
for i in range(63):
    T1[i,i+1] = 1
    T2[i,i+1] = 1
T1[-1] = [int(i) for i in '1010010000001000000010001001010010100100000010000000100010010100']
T2[-1] = [1]*64
E1 = T1^64
E2 = T2^64
```

由 `lfsr_MyCode` 得出的等式中，未知数前的系数均为 1，故有语句 `T2[-1] = [1]*64`。
给出一个例子帮助理解迭代的正确性，即 $T1 *T1$。

$$
\begin{pmatrix}
0&1&0\\
0&0&1\\
k_0&k_1&k_2\\
\end{pmatrix} \times
\begin{pmatrix}
\begin{pmatrix}0&1&0\end{pmatrix}\\
\begin{pmatrix}0&0&1\end{pmatrix}\\
\begin{pmatrix}k_0&k_1&k_2\end{pmatrix}\\
\end{pmatrix} =
\begin{pmatrix}
\begin{pmatrix}0&0&1\end{pmatrix}\\
\begin{pmatrix}k_0&k_1&k_2\end{pmatrix}\\
\begin{pmatrix}0&k_1&k_2\end{pmatrix}+
k_2*\begin{pmatrix}k_0&k_1&k_2\end{pmatrix}\\
\end{pmatrix}

$$

可见矩阵构造符合条件。

$$



$$

综上写出 exp

```python
A = matrix(GF(2),70,64)
T1 = matrix(GF(2),64,64)
T2 = matrix(GF(2),64,64)
for i in range(63):
    T1[i,i+1] = 1
    T2[i,i+1] = 1
T1[-1] = [int(i) for i in '1010010000001000000010001001010010100100000010000000100010010100']
T2[-1] = [1]*64
E1 = T1^64
E2 = T2^64
r1 = '01111101111010111000010010111001101'
r2 = '00100110001000110001101010101001001'
for i in range(35):
    A[i] = E1[i]
    A[i+35] = E2[i]

b = [int(i) for i in r1+r2]
ans = A.solve_right(b)
print(ans)
flag = 0
for i in ans:
    flag = flag*2+int(i)
print(int.to_bytes(int(flag),8,'big'))
```

## D^3CTF equivalent

考点: equivalent key attack.
本题基于论文：[基于子集和问题的公钥密码系统等效密钥攻击](https://ietresearch.onlinelibrary.wiley.com/doi/10.1049/iet-ifs.2018.0041)通读代码得知要找出满足以下条件的密钥：

1. $a_i=es_i\ mod\ p$
2. $e, p$ 互质即 $gcd(e, p) = 1$
3. $p > sum(s_i)$
4. $s_i$ 均为正奇数

下面复现论文中的算法，别问原理（~~因为看不懂~~）。

1. 设 $\vec{a}=e\vec{s}+p\vec{k}$

   $$
   \vec{a}=\begin{pmatrix}
   a_1\\
   a_2\\
   \dots\\
   a_n
   \end{pmatrix}


   \vec{s}=\begin{pmatrix}
   s_1\\
   s_2\\
   \dots\\
   s_n
   \end{pmatrix}


   \vec{k}=\begin{pmatrix}
   k_1\\
   k_2\\
   \dots\\
   k_n
   \end{pmatrix}

   $$
2. 计算正交格 $\mathscr{L}^{\perp}(a) = \mathscr{L}(t_1,t_2\dots,t_ {n})$，其中 $\mathscr{L}^{\perp}(a)$ 即为正交化后的矩阵的核(kernel)。
   sage:

   ```python
   def orthogonal_lattice(B):
       '''
       计算正交格
       '''
       LB = B.transpose().left_kernel(basis="LLL").basis_matrix()
       return LB
   ```
3. 计算 $\mathscr{L}(t_1,t_2\dots,t_{n-2})$ 的正交格，记为$\mathscr{L}^{\perp}_1=\mathscr{L}(u_1,u_2)$，$\mathscr{L}(u_1,u_2)$ 即为包含 $\vec{s},\vec{k}$ 的格。
4. 令 $\vec{s}=x_1u_1+x_2u_2,k=y_1u_1+y_2u_2,x_i,y_i\in Z,i=1,2.枚举|x_i|,|y_i|<\sqrt{N},i=1,2$
5. 计算出 $e, p$，筛选条件

   1. $e, p$ 互质即 $gcd(e, p) = 1$
   2. $p > sum(s_i)$
   3. $s_i$ 均为正奇数

得出的 $e,p$ 即为等价的私钥。
但在本题中直接进行这样的穷举时间复杂度尚无法接受，我跑了十几分钟也没有出来，因此需要一些优化。

观察 $\vec{s}=x_1u_1+x_2u_2$
有 $\vec{s}\ mod\ 2=(x_1\ mod\ 2)(u_1\ mod\ 2)+(x_2\ mod\ 2)(u_2\ mod\ 2)$ 此处 mod 对向量的每一维分量计算
由于 $s_i$ 均为正奇数，易知 $\vec{s} = (1,1,\dots,1)$
由此可解出 $x_1\ mod\ 2,\ x_2\ mod\ 2$，即得出了 $x_1$ 和 $x_2$ 的奇偶性用于提高穷举效率。
设 $\vec{a}=z_1\vec{u_1}+z_2\vec{u_2}$
可解出 $\begin{pmatrix}z_1&z_2\end{pmatrix}$
由 $a_i=es_i\ mod\ p$
得

$$
\begin{pmatrix}
e&p
\end{pmatrix}
\cdot
\begin{pmatrix}
x_1&x_2\\
y_1&y_2
\end{pmatrix}
=\begin{pmatrix}z_1&z_2\end{pmatrix}

$$

穷举时依此解出 $e,p$(写完发现这一步没有优化，就当是对算法流程的解释吧)

$$



$$

然后，由之前的步骤容易得出
$z_1=ex_1+py_1\Rightarrow p=z_1/y_1-ex_1/y_1$
$z_2=ex_2+py_2\Rightarrow p=z_2/y_2-ex_2/y_2$
其中 $p>e\gg a\gg z_i>z_i/y_i$
故 $x_1/y_1\approx x_2/y_2$
即 $x_1/x_2\approx y_1/y_2$
依次缩小枚举 $y_1,y_2$ 的范围。
官方 exp 中将 $y_1/y_2$ 取为最靠近 $x_1/x_2$ 的连分数，虽然这确实满足 $x_1/x_2\approx y_1/y_2$，但我无从得知这样做取得正确的概率有多大，若根据实际 exp 的运行速度为50s 左右，且主要时间都花在枚举前的 LLL 求 left_kernel 上，所以估计这个概率还是比较大的。

official exp:

```python
from collections import namedtuple
PublicKey = namedtuple('PublicKey', ['a'])
SecretKey = namedtuple('SecretKey', ['s', 'e', 'p'])
def bits2bytes(bits):
    num = int(''.join(map(str, bits)), 2)
    b = num.to_bytes((len(bits)+7)//8, 'big')
    return b

def dec(c, sk):
    d = inverse_mod(sk.e, sk.p)
    m = (d * c % sk.p) % 2
    return m

def decrypt(cip, sk):
    msg = bits2bytes([dec(c, sk) for c in cip])
    return msg

exec(open(r'D:\Operator\Python\Programming Files\CTF\D^3CTF\data.txt', 'r').read())
# pk = ...
# cip = ...

n = len(pk.a)

def orthogonal_lattice(B):
    '''
    计算正交格
    '''
    start = time.time()
    LB = B.transpose().left_kernel(basis = "LLL").basis_matrix()
    print(f"orthogonal_lattice: {time.time()-start} seconds")
    return LB

a = vector(ZZ, pk.a)    # 以 a_i 创建向量
La = orthogonal_lattice(Matrix(a))  # 计算 a 的正交格

L1 = orthogonal_lattice(La.submatrix(0, 0, n-2, n))
u1, u2 = L1
# u1, u2 即包含 s, k 的基底向量

L1_m = L1.change_ring(Zmod(2))
x1_m, x2_m = L1_m.solve_left(vector(Zmod(2),[1]*n)).change_ring(ZZ)
z = L1.solve_left(a).change_ring(ZZ)
print(f"x1_m = {x1_m}")
print(f"x2_m = {x2_m}")
def gen_close(x1,x2):
    cc=list((x1/x2).continued_fraction())   # continued_fraction 连分数

    if randint(0,1):#两种都能出
        cc[-1]-=1 
    else:
        cc=cc[:-1]
        cc[-1]+=1 

    cc=continued_fraction(cc).convergents()[-1]
    return cc.numer(),cc.denom()

K=40 # 太大容易sum(s)>p
for _ in range(16):
    while True:
        xx1 = randint(-2**K,2**K)*2 + x1_m
        xx2 = randint(-2**K,2**K)*2 + x2_m
        ss = xx1*u1 + xx2*u2 
        if min(ss)>0:
            break 

    yy1, yy2 = gen_close(xx1, xx2)
    ee, pp = Matrix(ZZ,[[xx1,xx2],[yy1,yy2]]).solve_left(z)

    if not ee.is_integer() or ee < 0:
        continue
    if not pp.is_integer():
        continue
    if pp < 0:
        yy1, yy2 = -yy1, -yy2
        pp = -pp
    if gcd(ee,pp) != 1:
        continue
    if sum(ss)>pp:
        continue
    sk=SecretKey(ss.list(),ee,pp)
    print(decrypt(cip,sk))
    break
```
