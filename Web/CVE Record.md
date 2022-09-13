# CVE Record

## CVE-2022-30190: Microsoft Office 远程代码执行漏洞

利用了 Microsoft MSHTML
MSHTML（又称 Trident）是微软 Windows 操作系统 Internet Explorer（IE）浏览器的排版组件。软件开发人员使用该组件，可以在应用中快速实现网页浏览功能。MSHTML 除应用于 IE 浏览器、IE 内核浏览器外，还在 Office 的 Word、Excel 和 PowerPoint 文档中用来呈现 Web 托管内容。
当目标用户点击文档后，MSHTML 会请求访问远程 html 页面 ，从而加载恶意 JavaScript。
exploit.html 中的 JS 代码调用了 PowerShell，进行 PowerShell-EncodeCommand 命令执行，

### Powershell EncodeCommand

由于 Powershell 中存在单双引号，然而有些时候在应用的时，难免会遇到多个单双引号嵌套 [比如在 Web 中]，就涉及到转义的问题。好在 Powershell 支持 Base64 编码后的指令使用 -e 或者 - Encodedcommand 指明后面的指令为编码后的即可。

```ps
powershell.exe -e cABpAG4AZwAgADEAMgA3AC4AMAAuADAALgAxAAoA

Pinging 127.0.0.1 with 32 bytes of data:
Reply from 127.0.0.1: bytes=32 time<1ms TTL=128
Reply from 127.0.0.1: bytes=32 time<1ms TTL=128
Reply from 127.0.0.1: bytes=32 time<1ms TTL=128
Reply from 127.0.0.1: bytes=32 time<1ms TTL=128

Ping statistics for 127.0.0.1:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 0ms, Average = 0ms
```

## Reference

><https://nosec.org/home/detail/5009.html>
<https://mp.weixin.qq.com/s?__biz=Mzg2NjQ2NzU3Ng==&mid=2247490632&idx=1&sn=a089dd9f44dd643de250bb07f9a24c9b>
