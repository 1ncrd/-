# WP

## old

base64解码得到  
svciqytf10r3ln!nule7
推测再次解密后的感叹号应该在字符串结尾，结合题目描述，使用 W 型栅栏解密，栏目数为 3，得到  
syntvfu1c0lri3elqn7!
由于源字符串中没有出现字符 g，因此得到的字符串肯定还要进一步处理，由于没有任何提示，首先尝试凯撒密码，枚举得到  
flagish1p0yev3ryda7!
对 h1p0yev3ryda7! 进行 MD5 哈希得到 flag 内容。  
flag{a9462922e5da8ef93d213c33168881c5}
