---
title: BUUCTF MISC Writeup Part3 <困难>
categories:
  - 平台Writeup
tags:
  - ctf
  - Misc
  - Writeup
index_img: /img/used/prac.jpg
date: 2020-01-13 21:09:05
---

# BUUCTF MISC Writeup Part3

100分以上的题目了，挑战一下自我，学到更多知识。



## jigsaw

拼图游戏，老套路了，首先上github上搜了一个jigsaw solver叫做gaps，他需要一张完整的图片，于是写个脚本把图片（231张）拼在一起。

```python
# 231 = 11*21
from PIL import Image
import os

i,j = 0,0
imax,jmax = 21,11

im = Image.open("0a72d187.jpg",'r')
width,height = im.size
big_img = Image.new("RGB",(imax*width,jmax*height))

dirs = os.listdir('./')

for k in dirs:
    if(k.endswith('jpg')):
        # do something
        curim = Image.open(k,'r')
        region = curim.crop((0,0,width,height))
        big_img.paste(region,(i*width,j*height),None)
        # next pointer
        j += 1
        if j == jmax :
            i += 1
            j = 0 
    else:
        continue

big_img.show()
big_img.save("out.png,'png')
```

拼好了长成这样子

![](https://ww1.yunjiexi.club/2020/01/13/jUwyq.png)

使用gaps

```
gaps --image = out.png --generations=20 --population=600 --size=100 --verbose
```

至今还没有拼出来

## [DDCTF]流量分析[unsolved]

很大的流量包，还给了一个RSA私钥格式。

发现其中关键点：传了一个fl-g.zip和sqlmap.zip，以及中间发了一些邮件。

首先当然是分析这些压缩包，提取出来后发现文件末尾损坏，找不到末尾修复的方法。

于是打算从邮件入手，发现一大串Base64编码：

编写脚本解密

```python
import base64
nstr = base64.b64decode(open("b64",'r').read())
with open("out.png",'wb') as file:
    file.write(nstr)
```

获得图片，自然要OCR识别一下。

![](https://ww1.yunjiexi.club/2020/01/13/jyPFg.png)

然后补全题目的RSA私钥

用了多个OCR，然后diff一下不同，手动确认。。

```
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDCm6vZmclJrVH1AAyGuCuSSZ8O+mIQiOUQCvN0HYbj8153JfSQ 
LsJIhbRYS7+zZ1oXvPemWQDv/u/tzegt58q4ciNmcVnq1uKivgc6QOtvT7oiSTyO 
vMX/q5iE2iClYUIHZEKX3BjjNDxrYvLQzPyGD1EY2DZIO6T45FNKYC2VDwIDAQAB 
AoGAbtWUKUkx37lLfRq7B5sqjZVKdpBZe4tL0jg6cX5Djd3Uhk1inR9UXVNw4/y4 
QGfzYqOn8+Cq7QSoBysHOeXSiPztW2cL09ktPgSlfTQyN6ELNGuiUOYnaTWYZpp/ 
QbRcZ/eHBulVQLlk5M6RVs9BLI9X08RAl7EcwumiRfWas6kCQQDvqC0dxl2wIjwN 
czILcoWLig2c2u71Nev9DrWjWHU8eHDuzCJWvOUAHIrkexddWEK2VHd+F13GBCOQ 
ZCM4prBjAkEAz+ENahsEjBE4+7H1HdIaw0+goe/45d6A2ewO/lYH6dDZTAzTW9z9 
kzV8uz+Mmo5163/JtvwYQcKF39DJGGtqZQJBAKa18XR16fQ9TFL64EQwTQ+tYBzN 
+04eTWQCmH3haeQ/0Cd9XyHBUveJ42Be8/jeDcIx7dGLxZKajHbEAfBFnAsCQGq1 
AnbJ4Z6opJCGu+UP2c8SC8m0bhZJDelPRC8IKE28eB6SotgP61ZqaVmQ+HLJ1/wH 
/5pfc3AmEyRdfyx6zwUCQCAH4SLJv/kprRz1a1gx8FR5tj4NeHEFFNEgq1gmiwmH
2STT5qZWzQFz8NRe+/otNOHBR2Xk4e8IS+ehIJ3TvyE=
-----END RSA PRIVATE KEY-----
```

得到RSA key后用wireshark的协议编辑器，导入这个私钥，就可以看到TLS解密后的数据了。

至今这个私钥还没有OCR对

## flag不在这里[unsolved]

给了一个超大二维码,QRResearch扫描出如下信息

```
https://cn.bing.com/search?q=key%E4%B8%8D%E5%9C%A8%E8%BF%99%E9%87%8C&m=10210897103375566531005253102975053545155505050521025256555254995410298561015151985150375568&qs=n&form=QBRE&sp=-1&sc=0-38&sk=&cvid=2CE15329C18147CBA4C1CA97C8E1BB8C
```

## weird_list

给了一堆python列表。。脑洞大开，把所有数字替换成多个连续字符，1不动

```python
#!/usr/bin/env python

lt = []
with open("weirdlist",'r') as f:
    for line in f:
        nline = ""
        k = line[1:-2:].split(" ")
        print(k)
        for each in k:
            if each == " " or each =="\n":
                continue
            if int(each) != 1:
                nline += " "*int(each)
            else:
                nline += "@"
        lt.append(nline)

with open("ntxt","w") as f:
    for line in lt:
        f.write(line+"\n")
```

然后看到字符flag（这到底是什么啊

![](https://ww1.yunjiexi.club/2020/02/04/1PyHD.png)

根据”眯着眼睛看就能看清东西的原理“，我们可以离远点并且眯着眼睛，就看到flag了。

用ppt处理了下

![](https://ww1.yunjiexi.club/2020/02/04/1Pzm9.md.png)

`flag{93lds_sk23a_p1o23}`

