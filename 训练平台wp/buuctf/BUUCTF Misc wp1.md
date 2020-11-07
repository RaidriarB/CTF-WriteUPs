---
title: BUUCTF MISC Writeup Part1 <超简单签到部分>
categories:
  - 平台Writeup
tags:
  - ctf
  - Misc
  - Writeup
index_img: /img/used/prac.jpg
date: 2020-1-12 10:21:24

---

# BUUCTF MISC Writeup Part1

写这一部分的题解纯粹是因为太无聊了想把BUUCTF的格子都点亮

## 签到

直接获得flag

## 金三胖

gif图片，分离帧即可。

可以用convert分离:

```
convert test.gif %03d.png
```

可以写python脚本分离:

```python
from PIL import Image

gif = Image.open("test.gif")
for i,frame in enumerate(ImageSequence.Iterator(gif),1):
  if frame.mode == "JPEG":
        frame.save("%d.jpg"%i)
  else:
        frame.save("%d.png"%i)
```

也可以直接在StegSolver中的帧分离器中分离。

## 二维码

扫描二维码发现没有flag。

从图片入手，binwalk一下，发现一个压缩包。尝试一些密码失败后，开始暴力破解，成功。

解开压缩包就获得flag。

## N种方法解决

题目是一个打不开的exe。分析Hex，发现隐藏了一张base64编码的图片。网上工具解码，扫描得到的图片二维码即可获得flag。

## 大白

CRC和图片长宽不匹配。枚举长宽验证CRC即可。脚本如下：

```python
#python2
import os
import binascii
import struct

def encode(s):
    st = ''
    for c in s:
        k = hex(ord(c)).replace('0x', '')
        if len(k) == 1:
            k = "0"+k
        st += k
    return st

misc = open("test.png","rb").read()
pic_crc = int(encode(misc[29:33]),16)
for i in range(4096):
    for j in range(4096):
        data = misc[12:16] + struct.pack('>i',i)+struct.pack('>i',j)+ misc[24:29]
        crc32 = binascii.crc32(data) & 0xffffffff
        if crc32 == pic_crc:
            print hex(i),hex(j)
```

修改长宽后即可获得flag。

## 基础破解

压缩包暴力破解+解密txt中base64即可获得flag。

## 你竟然赶我走

直接strings图片就发现了后面的flag。

## LSB

明显的提示LSB隐写。原理不再赘述，下面阐述如何发现LSB隐写：

![](https://ww1.yunjiexi.club/2020/01/12/jQWhQ.png)

我们发现在Blue Plane 的最低位（LSB）的图案中，呈现出有规律的异样方格（上方），于是依据这种规律性，可以判断存在隐写。接下来提取隐写信息

![](https://ww1.yunjiexi.club/2020/01/12/jQPow.png)

发现是一张PNG图片，二维码。扫描即可获得flag。

## 乌镇峰会种图

strings 一下直接就看到flag了。

## rar

提示了密码四位数，直接暴力破解flag就有了。

## qr

签到题  扫码获得flag

## ningen

jpg，strings后发现文件名，binwalk发现zip压缩包，foremost分离，发现需要密码，根据题目提示，四位数密码直接爆破。

然后就获得flag了

## 文件中的秘密

strings是找不到flag的，因为它用空格分隔开每个字符了。

直接Hex打开，发现文件中间的flag信息。

## wireshark

题目要求找到管理员密码，这就容易了。

直接追踪http流，看到验证码的php，感觉登录就在这个附近了。

很快发现POST包，在其中找到了管理员密码。

## 镜子里的世界

LSB隐写。解密出是一个字符串

## 小明的保险箱

foremost+暴力破解rar



