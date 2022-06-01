# CISCN2022-Crypto

## 签到电台

公众号获得电码，与密码本前 4*7 位进行模十相加，结果发包即可。

## 基于挑战码的双向认证 1

ssh 登陆远程服务器，`grep -rn "flag{"` 获得 flag。

## 基于挑战码的双向认证 2

同上

## 基于挑战码的双向认证 3

登陆 root 账户，弱密码爆破结果为 toor，然后在 /root/cube-shell/instance/flag_server/ 路径下找到 flag。
