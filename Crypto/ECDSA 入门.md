# ECDSA 入门

2022.7.24

---
今天在打 DASCTF 月赛遇到一道入门的 ECDSA 的题目，写的时候基本是一知半解，正好借此机会整理一下。

---
> 椭圆曲线数字签名算法（英语：Elliptic Curve Digital Signature Algorithm，缩写作 ECDSA）是一种基于椭圆曲线密码学的公开公钥加密算法。
> <https://zh.wikipedia.org/wiki/%E6%A4%AD%E5%9C%86%E6%9B%B2%E7%BA%BF%E6%95%B0%E5%AD%97%E7%AD%BE%E5%90%8D%E7%AE%97%E6%B3%95>

## 密钥生成

生成密钥前，需要知道椭圆曲线的参数
$$y^2=x^3+ax+b\ mod\ p$$
域参数为 $(p, a, b, G, n, h)$
其中 $G$ 为生成点 (generater) 或称基点 (base point)，$n$ 为曲线的阶 (order)，$h$ 称为辅因子，必须很小，最好是 $h = 1$ (做题暂时没见到这个参数)，

Key Pair Generation:

1. 在区间 [1, n - 1] 生成随机整数 d。
2. 计算 $Q = dG$。
3. Q 为公钥，d 为私钥。

（暂且省略了密钥有效性验证的部分）  

## 签名和验签

### 签名

签名消息为 $m$。

1. 在区间 [1, n - 1] 生成随机整数 k。
2. 计算 $kG = (x_1,y_1)$，另 $r = x_1\ mod\ n$，如果 $r = 0$，则返回步骤 1。
3. 计算 $k^{-1}\ mod\ n$。
4. 计算 $e = HASH(m)$。
5. 计算 $s = k^{-1}(e+dr)\ mod\ n$，如果 $s = 0$，则返回步骤 1。
6. 签名结果即为 $(r, s)$。

### 验签

1. 验证 $r, s \in [1,n - 1]$。
2. 计算 $e = HASH(m)$。
3. 计算 $w = s^{-1}$。
4. 计算 $u=ew\ mod\ n,\ u_2=rw\ mod\ n$。
5. 计算 $X = u_1G+u_2Q$。
6. 如果 $X = O$，验签失败，否则取 x 坐标，$v=x_1\ mod\ n$
7. 若 $v=r$，则验签成功。

### 证明

$k\equiv s^{-1}(e+dr)\equiv s^{-1}e+s^{-1}rd\equiv we+wrd\equiv u_1+u_2d\pmod n$  
$\therefore u_1G+u_2Q=(u_1+u_2d)G=kG$  
