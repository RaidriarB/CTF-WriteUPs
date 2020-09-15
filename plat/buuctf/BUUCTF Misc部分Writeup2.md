---
title: BUUCTF MISC Writeup Part2 <比较有难度>
categories:
  - 平台Writeup
tags:
  - ctf
  - Misc
  - Writeup
index_img: /img/used/prac.jpg
date: 2020-01-12 15:00:45
---

# BUUCTF MISC Writeup Part2

从这部分开始的题目就稍有难度。

## 学到/需要掌握的知识

+ LSB隐写的加密和cloacked-pixel的使用
+ NTFS隐写的简单应用
+ zipfile和CRC
+ 压缩包注释里可以藏不少内容
+ ImageMagick  的 Identify命令
+ linux一些对文件字符串操作
+ tshark的使用

## 参考链接

[Linux各种教程参考](http://blog.51yip.com/category/linux)

## 喵喵喵

给了一张图片，发现有LSB隐写。BGR模式发现是一张PNG图片。

导出后得到半张二维码，这里猜测是宽度高度作了修改，直接尝试把高度改为宽度，就得到了完整的二维码图片。二维码颜色对换后扫描，在百度网盘下载了flag.rar。

打开压缩包，提示flag不在这里。。思路卡在这里，看到网上说了一种神奇的隐写方式：NTFS隐写。于是照葫芦画瓢使用工具NTFSStreamEditor，发现隐藏的pyc文件。

在网上在线反编译pyc文件，得到了python脚本，这是一段加密程序，我们只要构造它的解密程序即可。

```python
def encode():
    flag = '*************'
    ciphertext = []
    for i in range(len(flag)):
        s = chr(i ^ ord(flag[i]))
        if i % 2 == 0:
            s = ord(s) + 10
        else:
            s = ord(s) - 10
        ciphertext.append(str(s))
    
    return ciphertext[::-1]  #倒序一遍
```

解密：

```python
ciphertext = ciphertext[::-1]
 
def decode():
    flag = ''
    for i in range(24):
        if(i%2 == 0):
            a = int(ciphertext[i]) - 10
        else:
            a = int(ciphertext[i]) + 10
        a = i ^ a
        flag = flag + chr(a)
    print(flag)
```

运行得到flag。

`flag{Y@e_Cl3veR_C1Ever!}`

## 穿越时空的想念

给了一段音频，发现右声道有莫斯代码，尝试分离。

![](https://ww1.yunjiexi.club/2020/01/12/jQwlw.png)

技术不够，只好人工识别01，识别如下：

```
0010 11111 00111 11110 1000 100 10000 0010 00000 00000 01111 01111 00011 11110 0 0 100 0 1000 11100 0 00001 00000 01 01111 11000 00000 1000 11111 11000 11100 10000
```

解密:

```
F029BD6F551139EEDEB8E45A175B0786
```

后面还有一段

```
0010 11111 00111 11110 1000 100 10000 0010 00000
```

解密：

```
F029BD6F5
```

是重复的，不予理会。题目说是32位的小写字符，转换一下

```
>>> "F029BD6F551139EEDEB8E45A175B0786".lower()
'f029bd6f551139eedeb8e45a175b0786'
>>> len("F029BD6F551139EEDEB8E45A175B0786")
32
```

于是得到 `flag{f029bd6f551139eedeb8e45a175b0786}`

## zip

打开题目，发现60多个压缩包，每个都有密码，而且使用暴力破解还打不开。。

于是想到直接CRC碰撞内部内容。看到里面每个只有四字节，又因为题目提示了是base64编码，所以遍历base64字母表即可，编写脚本如下：

（通过这道题也学习了一些python处理压缩包的知识。zipfile库可以进一步学习）

```python
#!/usr/bin/env python
import zipfile
import string
import binascii

ret = ""
def crcCrack(crc):
    global ret
    #本题目是四位的字符
    for i in dic:
        for j in dic:
            for k in dic:
                for l in dic:
                    s = i+j+k+l
                    if crc == binascii.crc32(s.encode()):
                        print(s)
                        ret += s
                        return
                
def ZipCrack():
    for i in range(0,68):
        file = 'out'+str(i)+".zip"
        crc = zipfile.ZipFile(file,'r').getinfo('data.txt').CRC
        crcCrack(crc)
        print("[INFO] "+str(i)+" Finished.")

dic = string.ascii_letters + string.digits + '+/='
ZipCrack()
print("[INFO] ALL Finished.")
print("Result: "+ret)
```

得到结果

```
z5BzAAANAAAAAAAAAKo+egCAIwBJAAAAVAAAAAKGNKv+a2MdSR0zAwABAAAAQ01UCRUUy91BT5UkSNPoj5hFEVFBRvefHSBCfG0ruGnKnygsMyj8SBaZHxsYHY84LEZ24cXtZ01y3k1K1YJ0vpK9HwqUzb6u9z8igEr3dCCQLQAdAAAAHQAAAAJi0efVT2MdSR0wCAAgAAAAZmxhZy50eHQAsDRpZmZpeCB0aGUgZmlsZSBhbmQgZ2V0IHRoZSBmbGFnxD17AEAHAA==
```

base64转换后发现它并不全部落在ASCII范围内，我们要使用字节流方式写入。于是编写脚本：

```python
#!/usr/bin/env python
import base64
string = "z5BzAAANAAAAAAAAAKo+egCAIwBJAAAAVAAAAAKGNKv+a2MdSR0zAwABAAAAQ01UCRUUy91BT5UkSNPoj5hFEVFBRvefHSBCfG0ruGnKnygsMyj8SBaZHxsYHY84LEZ24cXtZ01y3k1K1YJ0vpK9HwqUzb6u9z8igEr3dCCQLQAdAAAAHQAAAAJi0efVT2MdSR0wCAAgAAAAZmxhZy50eHQAsDRpZmZpeCB0aGUgZmlsZSBhbmQgZ2V0IHRoZSBmbGFnxD17AEAHAA=="

nstr = base64.b64decode(string)

with open("out",'wb') as file: #注意：想要以字节流方式读取、写入，必须模式选择wb 或 rb
    file.write(nstr)
```

使用Hex编辑器查看

![](https://ww1.yunjiexi.club/2020/01/12/jQlID.png)

要求修复这个文件，但是这个文件是什么格式呢？

由后面的flag.txt和前面的pkc字符猜测，这是一个压缩包文件。事实上，CF9073是RAR压缩文件头的CRC，这一点是不变的。

于是我们和正常压缩包进行对比，补全文件头。

> RAR 文件头：526172211A0700
>
> RAR 文件尾：C43D7B00400700

补全后打开压缩包，可以在压缩包的描述中发现flag。

`flag{nev3r_enc0de_t00_sm4ll_fil3_w1th_zip}`

## 弱口令

题目压缩包需要密码，但是字典爆破失败了。

发现压缩包的注释部分藏了不可见字符，复制过来查看：

![](https://ww1.yunjiexi.club/2020/01/12/jQLDb.png)

在sublime中查看：

![](https://ww1.yunjiexi.club/2020/01/12/jQibL.png)

显然是摩尔斯代码。转换后得：

`HELL0FORUM`

用此密码解压压缩包，成功，获得一张图片。

正常方式检测lsb隐写，并没有成功，什么都没发现。。。

在网上查了才知道：LSB隐写也可以使用加密的。正好对应了题目中提示的弱密码，用123456进行解密。这里用到的工具叫做cloacked-pixel，是一个专门检测、解密LSB隐写的工具。

在使用LSB隐写的过程中，发现报错`ImportError: No module named Crypto.Cipher`。这是由于Python中Crypto的包原来是大写，后来变成了小写，没做好兼容造成的。而包内很多代码也需要大写Crypto的包名，而不是小写的crypto，所以我们要到Python的site-package中找到crypto，将文件夹名改为大写Crypto。

然后执行命令

```bash
python lsb.py extract 女神.png new 123456
```

得到flag。

`flag{jsy09-wytg5-wius8}`

## 秘密文件

流量分析题还是很有意思的！

题目描述：深夜里，Hack偷偷的潜入了某公司的内网，趁着深夜偷走了公司的秘密文件，公司的网络管理员通过通过监控工具成功的截取Hack入侵时数据流量，但是却无法分析出Hack到底偷走了什么机密文件，你能帮帮管理员分析出Hack到底偷走了什么机密文件吗？

给了一个抓包文件，首先大体上分析：发现了DNS，TCP，HTTP，FTP等协议，逐个分析。

首先看HTTP，分析了一段并没有发现太多线索，这里我记录了一些传输的信息。（实际上没什么用

接下来看了看DNS，可能是在寻找内网的一些主机，后面还用了逆向解析，不知道要干什么

最后看了看FTP，从命令得到了用户的意图：

![](https://ww1.yunjiexi.club/2020/01/12/juRB0.png)

于是寻找那个rar文件。根据计算机网络知识，FTP会建立一个控制连接和数据连接，我们只要寻找到数据连接，Follow Stream即可。于是很容易找到那个rar，把它dump下来。

![](https://ww1.yunjiexi.club/2020/01/12/jucMt.png)

压缩包需要密码，使用ctf这个密码不成功，于是放在Windows中爆破，成功得到密码。

打开压缩包就获得了flag

`flag{d72e5a671aa50fa5f400e5d10eedeaa5}`

## 被偷走的文件

和上一道题异曲同工。依然是分析FTP传输的文件（这里是FTP-data协议），找到了flag.rar，暴力破解即可。

`flag{6fe99a5d03fb01f833ec3caa80358fa3}`

## 谁赢了比赛？

题目是一张png，foremost分理压缩包，暴力破解获得一张gif和txt。

txt没什么用，主要分析gif：用Stegsolve的Frame Browser查看每一帧，发现300左右有一张特殊的白色图片，上面标注了do_you_know_where_is_the_flag

把这张图片保存为BMP，先用老套路strings formost binwalk一波，没有隐藏什么东西，然后用StegSolve，在红色通道发现LSB隐写的二维码。扫描就可以获得flag了。

`flag{shanxiajingwu_won_the_game}`

## 蜘蛛侠呀

一道不错的题，要好好总结一下。

首先是一个抓包文件，有ssh、HTTP和好多好多的ICMP流量。分析http，提示不存在flag，ssh又不知道密码，于是观察好多好多的ICMP流量。点开看data发现每个的data都不太一样，还发现了`$$START$$-----BEGIN CERTIFICATE-----`这样的字样，好像传输一个证书。于是想办法把ICMP流量的data提取出来。

首先用wireshark过滤器，仅保存ICMP的reply流量

```
icmp && ip.addr == xxx.xxx...
```

保存成为新文件`icmpreply.pcap`

使用tshark工具：

```
tshark -r icmpreply.pcap -T fields -e data >out.txt
```

然后打开out.txt，tshark把数据用十六进制数字的形式保存下来了，我们要转为ASCII码。编写python脚本（python3之后处理hex的方法不太一样

```python
lines = open("out.txt",'r').readlines()
files = open("out01.txt","w")
for line in lines:
	newline = ''
	for i in range(len(line)//2):
		byte = line[i*2:i*2+2] #两个为单位读取数字
		num = int(byte,16) #16进制数转换为十进制
		character = chr(num)#根据十进制转换ASCII
		newline += character
	files.writelines(newline)
files.close()
```

打开txt，发现文件行都是重复的，用`uniq`命令去除

![](https://ww1.yunjiexi.club/2020/01/13/jUPWq.png)

```bash
uniq out01.txt > single.txt 
```

去除后，正则提取内容，使用`sed`命令,其中括号记得转义，后面的\1代表用第一个括号替换整体的内容。

```bash
cat single.txt | sed 's/$$START$$\(.*\)/\1/g' > replace.txt
```

![](https://ww1.yunjiexi.club/2020/01/13/jUWuC.png)

看起来是一个base64编码。

去除换行，在vim中输入命令

```
%s/\n//g
```

然后手动删除证书头尾，base64解码

```python
#!/usr/bin/env python
import base64
string = open("replace.txt",'r').read()
nstr = base64.b64decode(string)
with open("out",'wb') as file: #注意：想要以字节流方式读取、写入，必须模式选择wb 或 rb
    file.write(nstr)
```

解码后用编辑器查看，发现是PK文件头，ZIP格式，解压缩发现一张gif图片

![](https://ww1.yunjiexi.club/2020/01/13/jUjS4.gif)

查看帧并没有发现隐写，但是播放感觉很卡顿，于是考虑播放间隔会不会有什么信息。这里使用`ImageMagick`中的`identify`命令，它可以提供图片的很多信息。其中查看gif的帧间隔的方法就是：

```bash
identify -format "%T" flag.gif 
2050502050502050205020202050202020205050205020502050205050505050202050502020205020505050205020206666
```

显然是二进制。转换一下

```
011011010100010000110101010111110011000101110100
```

```python
>>> for i in range(6):
	print(chr(int(a[i*8:i*8+8],2)),end='')

mD5_1t
```

题目要求使用md5加密一下，就可以获得flag了。（bash命令）

```bash
$ md5 -s "mD5_1t"
MD5 ("mD5_1t") = f0f1003afe4ae8ce4aa8e8487a8ab3b6
```

`flag{f0f1003afe4ae8ce4aa8e8487a8ab3b6}`

## 间谍启示录

给了一个ISO。解压缩后发现一个exe，这个exe会自动解压缩一些文件，执行后发现文件已被销毁。

把exe拖到编辑器中看了看，搜索一下flag字串，发现了一个del flag.exe的字样，可以发现是程序删除了这个文件。

所以我们直接解压这个exe，就可以发现flag.exe，执行后得到flag。

`Flag{379:7b758:g7dfe7f19:9464f:4g9231}`

## john-in-the-middle

给了一个抓包文件，分析可知，传输了五个png。这次我们直接用formost进行分离：

```bash
foremost test.pcap
```

然后挨个strings了一下，没什么结果，打开Stegsolve，第一张图片的Random颜色通道就可以看到flag。

![](https://ww1.yunjiexi.club/2020/01/13/jU8WB.png)

`flag{J0hn_th3_Sn1ff3r}`

## 二维码

PS题目，修复破损图片。。

![](https://ww1.yunjiexi.club/2020/01/13/jUJSM.png)

经过一通技艺不精的PS。。

![](https://ww1.yunjiexi.club/2020/01/13/jU4Uj.png)

`flag{7bf116c8ec2545708781fd4a0dda44e5}`

## 黑客帝国

给了一个txt文件，是一大堆字符。首先当然是要分析统计规律，发现只有数字和a-f的字母，判断是16进制表示.复制到16进制编辑器中，发现是RAR文件，需要密码。进行爆破，解压出一张png图片。

但是图片打不开，于是用16进制编辑器查看，发现JFIF段，这明显是jpg的格式特征。于是上网查一下jpg文件头的格式如下：

```
FF D8 FF E0 00 10 4A 46 49 46
```

修复图片，就可以获得flag了。

`flag{57cd4cfd4e07505b98048ca106132125}`

## [SWPU2019]神奇的二维码

binwalk好像坏了，手动提取出四个压缩包。。

第一个是一段base64，为第二个压缩包密码。

第二个没什么用

第三个是一段好多层的base64

```python
import base64

with open ("flag.doc",'r') as f:
    ns = f.read()

try:
    while True:
        ns = base64.b64decode(ns)
except:
    pass
print(ns)
```

得到`comEON_YOuAreSOSoS0great`

用这个解压第四个压缩包，是一段摩斯代码，解密即可。

`flag{morseisveryveryeasy}`

## [SWPU2019]我有一只马里奥

点击程序，自解压了一个txt，提示ntfs隐写，用工具即可。

`flag{ddg_is_cute}`

## 黄金六年

一个视频，最后有一段base64编码的字串，解密获得压缩包。

观看视频看不出什么

ffmpeg分离，发现其中有隐藏的二维码。一共四个，加起来就是`iwantplayctf`

`flag{CTF-from-RuMen-to-RuYuan}`