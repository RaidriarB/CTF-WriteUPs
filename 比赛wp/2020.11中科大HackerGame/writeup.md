# HackerGame2020

## 233同学的docker

我们知道，docker的镜像fs是分层的，使用`docker history`可以查看每一次的操作，使用`docker save`命令就可以得到一个tar文件，包含了镜像的每一层。然后搜索flag就可以了。

参考链接https://www.52cik.com/2018/10/01/docker-alinode-dockerfile.html

`flag{Docker_Layers!=PS_Layers_hhh}`

## 自复读的复读机

先RCE拿到代码，flag有权限保护

```python
import subprocess
import hashlib

if __name__ == "__main__":
    code = input("Your one line python code to exec(): ")
    print()
    if not code:
        print("Code must not be empty")
        exit(-1)
    p = subprocess.run(
        ["su", "nobody", "-s", "/bin/bash", "-c", "/usr/local/bin/python3 /runner.py"],
        input=code.encode(),
        stdout=subprocess.PIPE,
    )

    if p.returncode != 0:
        print()
        print("Your code did not run successfully")
        exit(-1)

    output = p.stdout.decode()

    print("Your code is:")
    print(repr(code))
    print()
    print("Output of your code is:")
    print(repr(output))
    print()

    print("Checking reversed(code) == output")
    if code[::-1] == output:
        print(open("/root/flag1").read())
    else:
        print("Failed!")
    print()

    print("Checking sha256(code) == output")
    if hashlib.sha256(code.encode()).hexdigest() == output:
        print(open("/root/flag2").read())
    else:
        print("Failed!")


```

https://codegolf.stackexchange.com/questions/16021/print-your-code-backwards-reverse-quine

https://stackoverflow.com/questions/1364927/code-golf-reverse-quine

在网上找到Quine关键字，找到reverse quine，大概理解原理魔改一下

注意代码是以双括号括起来的，所以print的end用双括号才能正常显示，单括号并不能显示出来。如果不修改end，代码会多出一个\n来。

### reverse

```
x='x=%r;print((x%%x)[::-1],end="")';print((x%x)[::-1],end="")
```

### sha256

```
x='x=%r;import hashlib;print(hashlib.sha256((x%%x).encode()).hexdigest(),end="")';import hashlib;print(hashlib.sha256((x%x).encode()).hexdigest(),end="")
```



## 从零开始的火星文生活

题目说是GBK编码，但我的Mac自动用UTF-8编码打开了，看起来很整齐。然而用GBK编码打开之后就很混乱，于是尝试用VSCode下，以UTF-8打开，保存为GBK编码。

接下来分析文本的特征：首先写个脚本可视化二进制

```python
with open("gibberish_message copy.txt","rb") as f:
	a = f.read()

with open("res","w") as f:
	r = 1
	for k in a:
		if r%2 == 1:
			f.write(str(bin(k))[2:])
		if r%2 == 0:
			f.write(str(bin(k))[2:])
			f.write("\n")
		r += 1
```

<img src="https://s1.ax1x.com/2020/11/03/By2bwV.png" alt="By2bwV.png" style="zoom:50%;" />

<img src="https://s1.ax1x.com/2020/11/03/By2jW4.png" alt="By2jW4.png" style="zoom:50%;" />

发现很多冗余位。从信息论的角度，它们不可能藏匿信息，直接去掉。修改上面代码

```python
		if r%2 == 1:
			f.write(str(bin(k))[2+7:])
		if r%2 == 0:
			f.write(str(bin(k))[2+2:])
```

然后转换为ASCII

```python
with open("res",'r') as f:
	s = f.read()
	lst = s.split("\n")
	for k in lst:
		num = int(k,2)
		print(chr(num),end='')
```

得到文本

```
NR9%FFAK#H#a#c#k#e#r#g#a#m#e5D7~NqFw#,M55=AKK|CG5D#f#l#a#g#,OVTZNR0Q#f#l#a#g7"8xDc#:#f#l#a#g#{#H#4#v#3#_#F#u#N#_#w#1#T#h#_#3#n#c#0#d#1#n#g#_#4#N#d#_#d#3#c#0#D#1#n#G#_#9#q#D#2#R#8#h#s#}?lH%1HH|F=L(La=;0I#!2;R*TY0QUb7]PEO"W*7"8xFdK{HKAK#,R*JG1;7"OV>MTc8bAK#!
```

替换所有的#就可以看到flag了。

```
NR9%FFAKHackergame5D7~NqFw,M55=AKK|CG5Dflag,OVTZNR0Qflag7"8xDc:flag{H4v3_FuN_w1Th_3nc0d1ng_4Nd_d3c0D1nG_9qD2R8hs}?lH%1HH|F=L(La=;0I!2;R*TY0QUb7]PEO"W*7"8xFdK{HKAK,R*JG1;7"OV>MTc8bAK!
```

`flag{H4v3_FuN_w1Th_3nc0d1ng_4Nd_d3c0D1nG_9qD2R8hs}`

## 来自一教的图片

傅里叶光学...搜集了一番资料，还是决定先傅里叶变换+逆傅里叶变换试一试。结果傅里叶变换一下就出来了

```python
import cv2 as cv
import numpy as np
from matplotlib import pyplot as plt
#读取图像
img = cv.imread('./ori.bmp', 0)
#傅里叶变换
f = np.fft.fft2(img)
res = np.log(np.abs(f))
#展示结果
plt.subplot(132), plt.imshow(res, 'gray')
plt.axis('off')
plt.show()
```

![B2Y54I.png](https://s1.ax1x.com/2020/11/05/B2Y54I.png)

`flag{Fxurier_xptics_is_fun}`

## 狗狗银行

资产 - 负债 = 净资产->-inf

0.3%  0.5%

0.2% -> 正溢出

正 - 正 = 正溢出

正 - 负溢出



## 233同学的字符串工具

python总有一些奇怪的特性。。

```python
print('ﬂag'.upper())
```

### uppercase

本来想啃源码，后来搜了一下，搜出来了一些issue。

https://ideone.com/8qCHVE

https://stackoverflow.com/questions/57190507/strange-behavior-of-pythons-upper-method

`flag{badunic0debadbad_4e95509eaa}`

### utf7

寻找了一大通找到这样一个网站

http://string-functions.com/encodingtable.aspx?encoding=65000&decoding=65001

非常好用

![BhT1Tf.png](https://s1.ax1x.com/2020/11/06/BhT1Tf.png)

发现了一个会decode出奇怪的符号的结构：`+XXX-`，于是写脚本遍历

```python
def find():
	table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	for i in table:
		for j in table:
			for k in table:
				s = "+"+i+j+k+"-"
				st = s.encode('utf-8')
				#print(st)
				try:
					k = st.decode('utf-7')
					if k in 'flag':
						print(s,k)
				except:
					pass

find()
```

结果

```
+AGE- a
+AGY- f
+AGc- g
+AGw- l
```

传入`fl+AGE-g`即可。

`flag{please_visit_www.utf8everywhere.org_c68fb2da99}`

## 超基础的数理模拟器

发现了一个库sympy，需要学习解定积分+输入latex公式



## 超安全的代理服务器

### secret

经过了很多失败的尝试：Fiddler一通抓，curl一通模拟，charles一通抓，全都失败了，不被识别为浏览器。http2可能有一些难以伪造的验证字段。

这是http2的服务器，从题目知道有一个push功能，由于某种原因浏览器未能显示。

查看RFC文档的push介绍https://httpwg.org/specs/rfc7540.html#PUSH_PROMISE

尝试使用chrome插件：HTTP/2 and SPDY indicator 抓取浏览器日志，然后放入日志分析器中，寻找到了http2的HTTP_PUSH_PROMISE字段。

![BhrkIx.png](https://s1.ax1x.com/2020/11/06/BhrkIx.png)

访问这个path获得flag

![BhrZRO.png](https://s1.ax1x.com/2020/11/06/BhrZRO.png)

`flag{d0_n0t_push_me}`