# CTF SR 23.3.30

## picoCTF GET aHEAD

### Description

Find the flag being held on this server to get ahead of the competition http://mercury.picoctf.net:21939/
Hints:
Maybe you have more than 2 choices
Check out tools like Burpsuite to modify your requests and look at the responses

### HEAD

HTTP `HEAD` 方法 请求资源的头部信息，并且这些头部与 HTTP `GET` 方法请求时返回的一致。该请求方法的一个使用场景是在下载一个大文件前先获取其大小再决定是否要下载，以此可以节约带宽资源。

题中 Red 按钮请求 GET 方法，抓包后修改为 HEAD 即可得到 FLAG

> https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Methods/HEAD  

## picoCTF Cookies

### Description

Who doesn't love cookies? Try to figure out the best one.


访问页面，输入框尝试无果，查看本地 cookies 发现 `name=-1`，修改为 `name=1` 页面发生变化，尝试枚举一下 cookies。

```py
import requests

url = "http://mercury.picoctf.net:17781/check"

s = requests.Session()
s.get(url)

for i in range(0, 100):
    cookie = {'name': str(i)}

    req = s.get(url, cookies=cookie)

    if "picoCTF{" in req.text:
        print(req.text)
        break
    else:
        print(f"Trying cookie: {i}")

```

### requests.Session
A Requests session.
Provides cookie persistence, connection-pooling, and configuration

`name=18` 时得到 flag

## picoCTF Insp3ct0r

### Description

Kishor Balan tipped us off that the following code may need inspection: https://jupiter.challenges.picoctf.org/problem/41511/ (link) or http://jupiter.challenges.picoctf.org:41511

```txt
How
I used these to make this site:
HTML
CSS
JS (JavaScript)
```

flag 分三部分在 html,css `mycss.css`,js `myjs.js` 页面中

## picoCTF Scavenger Hunt

### Description

There is some interesting information hidden around this site http://mercury.picoctf.net:44070/. Can you find it?

前两部分同样在 html,css 中找到，js 文件中看到 `/* How can I keep Google from indexing my website? */` 得知访问 robots.txt

```txt
User-agent: *
Disallow: /index.html
# Part 3: t_0f_pl4c
# I think this is an apache server... can you Access the next flag?
```

### apache .htaccess

.htaccess是一个纯文本文件，它里面存放着Apache服务器配置相关的指令。
.htaccess主要的作用有：URL重写、自定义错误页面、MIME类型配置以及访问权限控制等。主要体现在伪静态的应用、图片防盗链、自定义404错误页面、阻止/允许特定IP/IP段、目录浏览与主页、禁止访问指定文件类型、文件密码保护等。
.htaccess的用途范围主要针对当前目录。

`GET /.htaccess`

```txt
# Part 4: 3s_2_lO0k
# I love making websites on my Mac, I can Store a lot of information there.
```

### .DS_Store

英文全称 Desktop Services Store ，是 Mac OS 中 保存文件夹自定义属性的隐藏文件，目的在于存贮文件夹的自定义属性，例如文件图标位置、视图设置，或背景色等，相当于Windows下的 desktop.ini

`GET /.DS_Store`

```txt
Congrats! You completed the scavenger hunt. Part 5: _7a46d25d}
```

## picoCTF Some Assembly Required 1

### Description

http://mercury.picoctf.net:55336/index.html

发现无网络交互，查看源码有一个 `G82XCw5CX3.js` 文件。

```js
const _0x402c=['value','2wfTpTR','instantiate','275341bEPcme','innerHTML','1195047NznhZg','1qfevql','input','1699808QuoWhA','Correct!','check_flag','Incorrect!','./JIFxzHyW8W','23SMpAuA','802698XOMSrr','charCodeAt','474547vVoGDO','getElementById','instance','copy_char','43591XxcWUl','504454llVtzW','arrayBuffer','2NIQmVj','result'];const _0x4e0e=function(_0x553839,_0x53c021){_0x553839=_0x553839-0x1d6;let _0x402c6f=_0x402c[_0x553839];return _0x402c6f;};(function(_0x76dd13,_0x3dfcae){const _0x371ac6=_0x4e0e;while(!![]){try{const _0x478583=-parseInt(_0x371ac6(0x1eb))+parseInt(_0x371ac6(0x1ed))+-parseInt(_0x371ac6(0x1db))*-parseInt(_0x371ac6(0x1d9))+-parseInt(_0x371ac6(0x1e2))*-parseInt(_0x371ac6(0x1e3))+-parseInt(_0x371ac6(0x1de))*parseInt(_0x371ac6(0x1e0))+parseInt(_0x371ac6(0x1d8))*parseInt(_0x371ac6(0x1ea))+-parseInt(_0x371ac6(0x1e5));if(_0x478583===_0x3dfcae)break;else _0x76dd13['push'](_0x76dd13['shift']());}catch(_0x41d31a){_0x76dd13['push'](_0x76dd13['shift']());}}}(_0x402c,0x994c3));let exports;(async()=>{const _0x48c3be=_0x4e0e;let _0x5f0229=await fetch(_0x48c3be(0x1e9)),_0x1d99e9=await WebAssembly[_0x48c3be(0x1df)](await _0x5f0229[_0x48c3be(0x1da)]()),_0x1f8628=_0x1d99e9[_0x48c3be(0x1d6)];exports=_0x1f8628['exports'];})();function onButtonPress(){const _0xa80748=_0x4e0e;let _0x3761f8=document['getElementById'](_0xa80748(0x1e4))[_0xa80748(0x1dd)];for(let _0x16c626=0x0;_0x16c626<_0x3761f8['length'];_0x16c626++){exports[_0xa80748(0x1d7)](_0x3761f8[_0xa80748(0x1ec)](_0x16c626),_0x16c626);}exports['copy_char'](0x0,_0x3761f8['length']),exports[_0xa80748(0x1e7)]()==0x1?document[_0xa80748(0x1ee)](_0xa80748(0x1dc))[_0xa80748(0x1e1)]=_0xa80748(0x1e6):document[_0xa80748(0x1ee)](_0xa80748(0x1dc))[_0xa80748(0x1e1)]=_0xa80748(0x1e8);}
```

经过了很多混淆，注意到 `_0x1d99e9 = await WebAssembly[_0x48c3be(0x1df)]` 结合题目名字，应该是执行了一段 wasm 代码

### WebAssembly

WebAssembly 是一种新的编码方式，可以在现代的网络浏览器中运行 － 它是一种低级的类汇编语言，具有紧凑的二进制格式，可以接近原生的性能运行，并为诸如 C / C ++等语言提供一个编译目标，以便它们可以在 Web 上运行。它也被设计为可以与 JavaScript 共存，允许两者一起工作。

---

查看控制台源代码，在 top/wasm/986e784a 文件底部找到 flag

## picoCTF Some Assembly Required 2

### Description

http://mercury.picoctf.net:61778/index.html

除了 wasm 文件其他的都一样，文件结尾串变成了 `xakgK\5cNs((j:l9<mimk?:k;9;8=8?=0?>jnn:j=lu` 上面的代码应该经过了一些加密，

```sh
> diff (cat E:/Download/compiled.wasm-o.c) (cat E:/Download/JIFxzHyW8W.c)

InputObject                                         SideIndicator
-----------                                         -------------
data d_picoCTF51e513c498950a515b1aa(offset: 1024) = =>
"picoCTF{51e513c498950a515b1aab5e941b2615}\00\00";  =>
  var g:byte_ptr = e[2];                            =>
  g[1072] = f;                                      =>
data d_xakgKNsnjl909mjn9m0n9088100u(offset: 1024) = <=
"xakgK\Ns>n;jl90;9:mjn9m<0n9::0::881<00?>u\00\00";  <=
  if (eqz(f)) goto B_a;                             <=
  var g:int = e[3];                                 <=
  var h:int = 8;                                    <=
  var i:int = g ^ h;                                <=
  e[3] = i;                                         <=
  label B_a:                                        <=
  var j:int = e[3];                                 <=
  var k:byte_ptr = e[2];                            <=
  k[1072] = j;                                      <=
```

对比 copy 函数

```txt
function copy(a:int, b:int) {
  var c:int = g_a;
  var d:int = 16;
  var e:int_ptr = c - d;
  e[3] = a;
  e[2] = b;
  var f:int = e[3];
  var g:byte_ptr = e[2];
  g[1072] = f;
}

function copy(a:int, b:int) {
  var c:int = g_a;
  var d:int = 16;
  var e:int_ptr = c - d;
  e[3] = a;
  e[2] = b;
  var f:int = e[3];
  if (eqz(f)) goto B_a;
  var g:int = e[3];
  var h:int = 8;
  var i:int = g ^ h;
  e[3] = i;
  label B_a:
  var j:int = e[3];
  var k:byte_ptr = e[2];
  k[1072] = j;
}
```

得知应该是 XOR 8

```py
>>> from pwn import xor
>>> xor(r"xakgK\Ns>n;jl90;9:mjn9m<0n9::0::881<00?>u", 8)
b'picoCTF{6f3bd18312ebf1e48f12282200948876}'
```

> 刚开始复制了浏览器控制台的加密 flag，导致 `"xakgK\Ns>n;jl90;9:mjn9m<0n9::0::881<00?>u"` 中的 `\N` 解析成了别的东西。

或者也可以用 [CyberChef](https://gchq.github.io/CyberChef/#recipe=Magic(3,true,false,'picoC')&input=eGFrZ0tcTnM%2BbjtqbDkwOzk6bWpuOW08MG45OjowOjo4ODE8MDA/PnU)，利用 Magic 模块给出 flag 前缀自动推测。