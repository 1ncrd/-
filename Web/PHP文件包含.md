# PHP 文件包含

## 文件包含漏洞利用的前提

1. web 应用采用 include 等文件包含函数，并且需要包含的文件路径是通过用户传输参数的方式引入。
2. 用户能够控制包含文件的参数，被包含的文件可被当前页面访问。

## 伪协议文件包含

```txt
file://     访问本地文件系统
http://     访问 HTTPs 网址
ftp://      访问 ftp URL 
Php://      访问输入输出流
Zlib://     压缩流
Data://     数据
Ssh2://     security shell2 
Expect://   处理交互式的流
Glob://     查找匹配的文件路径
```

php:// 访问各个输入/输出流（I/O streams），在CTF中经常使用的是php://filter和php://input，php://filter用于读取源码，php://input用于执行php代码。

> <https://ctf-wiki.org/web/php/php/>
