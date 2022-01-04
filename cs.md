---
title: cs使用

renderNumberedHeading: true
grammar_cjkRuby: true
---
# CS简介

	Cobalt Strike是一款美国Red Team开发的渗透测试神器，常被业界人称为CS。

Cobalt Strike是一款由java编写的全平台多方协同渗透测试框架，在3.0版本之前它基于Metasploit框架工作，在3.0后的版本以独立成一个渗透测试平台。它分为客户端与服务端，服务端只有一个并运行在linux中，客户端可以有多个，可被团队进行分布式协团操作。本篇文章讲解的是4.0版本的使用。

Cobalt Strike集成了端口转发、扫描多模式端口Listener、socket代理、提权、钓鱼、远控木马Windows exe程序生成、Windows dll动态链接库生成、java程序生成、office宏代码生成，包括站点克隆获取浏览器的相关信息等功能。该工具几乎覆盖了APT攻击链中所需要用到的各个技术环节，且其最大的优点在于可以进行团队合作和优越的UI界面。

Cobalt Strike是一个c/s架构，他被分配作为客户端并连接到团队服务器。团队服务器是Cobalt Strike的一部分用来与目标环境做交互。


  	团队成员需要知道
	
	- 服务端的外部IP地址
	
	- 连接服务端的密码
	
	团队成员上线同一个服务端，会在团队成员内：

    - 使用相同的会话
	
	- 分享靶机数据
	
	- 通过一个共享的事件日志交流
	
# CS的安装

Strategic Cyber 责任有限公司发行了适用于 Windows、Linux 和 MacOS X 的 Cobalt Strike 软件包。要安装 Cobalt Strike，只需将其存档解压到你的操作系统上。
* 系统要求
	 Cobalt Strike 要求 Oracle Java 1.8，Oracle Java 11, 或 OpenJDK 11，kali系统自带JAVA环境，也可自行删除重装JDK。
	 ![查询kali中的java版本](./images/1_1.png)
	如果你的系统上装有防病毒产品，请确保在安装 Cobalt Strike 前将其禁用。

**英文版：https://pan.baidu.com/s/1M8VJE9J7BHFh-SLitMtZkw 密码: b3ju
汉化版：https://pan.baidu.com/s/1iElxAMg5jiXtUgjmNwLlog  密码:45ih**

	运行 更新 程序
		Cobalt Strike 发emphasized text行套件包含 Cobalt Strike 启动器、支持文件和更新程序。它不包含 Cobalt Strike 程序本身。你必须运行更新程序才能下载 Cobalt Strike 产品。
		./update

打开文件目录
![文件目录](./images/2.png)

CobaltStrike一些主要文件功能如下：

· agscript：扩展应用的脚本

· c2lint：用于检查profile的错误和异常

· teamserver：服务器端启动程序

· cobaltstrike.jar：CobaltStrike核心程序

· cobaltstrike.auth：用于客户端和服务器端认证的文件，客户端和服务端有一个一模一样的

· cobaltstrike.store：秘钥证书存放文件

一些目录作用如下： 

· data：用于保存当前TeamServer的一些数据

· download：用于存放在目标机器下载的数据

· logs：日志文件，包括Web日志、Beacon日志、截图日志、下载日志、键盘记录日志等

· third-party：第三方工具目录

· Scripts： 插件目录

# CS 的登录
## 团队服务器

Cobalt Strike 分为客户端组件和服务器组件。服务器组件，也就是团队服务器，是 Beacon payload 的控制器，也是 Cobalt Strike 社会工程功能的托管主机。团队服务器还存储由 Cobalt Strike 收集的数据，并管理日志记录。

Cobalt Strike 团队服务器必须在受支持的 Linux 系统上运行。要启动一个 Cobalt Strike 团队服务器，使用 Cobalt Strike Linux 安装包中的 teamserver 脚本文件。

***启动服务端***
		
		./teamserver  192.168.201.131 hyy
		# 该ip地址为团队服务端IP，而后是连接服务器的密码
	注意：cs默认监听端口为50050，可以打开teamserver文件，修改端口。
![3.启动服务器](./images/3.png)

	当团队服务器启动，它会发布团队服务器的 SSL 证书的 SHA256 hash。你需要给你的团队成员分发这个 hash。当你的团队成员连接团队服务器时，在身份验证至团队服务器前、他们的 Cobalt Strike 客户端会询问他们是否承认这个 hash 。这是抵御中间人攻击的重要保护措施。

## 客户端

客户端可以在任意操作系统中运行，需要配置Jdk的环境。

***启动客户端***

	./start.sh
	HOST 为服务器的IP地址
	PORT 为端口号 （默认即可）
	USER 为用户名 （默认即可）
	Password 为登录密码 （服务端密码）


![4.启动客户端](./images/4_1.png)
	
	按下 Connect 按钮来连接到 Cobalt Strike 的团队服务器
	
	如果这是你第一次连接至此团队服务器， Cobalt Strike 会询问你是否承认这个团队服务器的 SHA256hash。如果你承认，那么按 OK ，然后 Cobalt Strike 的客户端就会连接到这个团队服务器。Cobalt Strike 也会在未来的连接中记住这个 SHA256 hash。你可以通过 Cobalt Strike→ Preferences → Fingerprints 来管理这些团队服务器的 hash。
![](./images/9.png)

![5.登入成功](./images/5.png)	

### 用户接口

>Cobalt Strike 用户接口分为两部分。接口的顶部是会话或目标的视觉化展示。接口的底部展示了每个你
与之交互的 Cobalt Strike 功能或会话的标签页。你可以点击这两部分之间的区域、按你的喜好重新调
整这两个区域的大小。

	Cobalt Strike 顶部的工具条提供访问 Cobalt Strike 常用功能的快捷方式。熟悉此工具条按钮会提升你使用 Cobalt Strike 的效率。
![6.工具条的中文解释](./images/6_1.png)
>CobaltStrike模块
	· New Connection：新建连接窗口
	· Preferences：偏好设置，设置CobaltStrike外观的
	· Visualization：将主机以不同的权限展示出来(主要以输出结果展示)
	· VPN Interfaces：设置VPN接口
	· Listeners：创建监听器
	· Script Interfaces：查看和加载CNA脚本
	· Close：关闭
![7.CobaltStrike模块](./images/7.png)

> VIew模块
	· Applications：显示受害者主机的应用信息
	· Credentials：显示受害主机的凭证信息
	· Downloads：查看从受害主机上下载的文件
	· Event Log：主机上线记录以及团队协作聊天记录
	· Keystrokes：查看键盘记录
	· Proxy Pivots：查看代理模块
	· Screenshots：查看屏幕截图
	· Script Console：加载第三方脚本以增强功能
	· Targets：查看所有受害主机
	· Web Log：查看web日志
![8.View模块](./images/8.png)

>Attacks模块
	 Packages：
	· HTML Application:生成(executable/VBA/powershell)这三种原理实现的恶意木马文件
	· MS Office Macro:生成office宏病毒文件
	· Payload Generator:生成各种语言版本的payload
	· Windows Executable:生成可执行exe木马
	· Windows Executable(S):生成无状态的可执行exe木马
![10Attacks模块](./images/10_1.png)
	Web Drive-by:
	· Manage:对开启的web服务进行管理
	·Clone Site:克隆网站，记录受害者提交的数据
	· Host File: 提供文件下载，可以选择Mime类型
	· Scripted Web Delivery:为payload提供web服务以便下载和执行，类似于Metasploit的web_delivery
	· Signed Applet Attack:使用java自签名的程序进行钓鱼攻击(该方法已过时)
	· Smart Applet Attack: 自动检测java版本并进行攻击，针对Java 1.6.0_45以下以及Java 1.7.0_21以下版本(该方法已过时)
	· System Profiler:用来获取系统信息，如系统版本，Flash版本，浏览器版本等
![11Attacks模块](./images/11_1.png)

>Reporting模块
	· Activity Report:活动报告
	· Hosts Report:主机报告
	· Indicators of Compromise:IOC报告：包括C2配置文件的流量分析、域名、IP和上传文件的MD5 hashes
	· Sessions Report:会话报告
	· Social Engineering Report:社会工程报告：包括鱼叉钓鱼邮件及点击记录
	· Tactics, Techniques, and Procedures:战术技术及相关程序报告：包括行动对应的每种战术的检测策略和缓解策略
	· Reset Data:重置数据
	· Export Data: 导出数据，导出.tsv文件格式
![12.Reporting模块](./images/12.png)

>Help模块
	· Homepage:官方主页 
	· Support:技术支持 
	· Arsenal:开发者 
	· System information:版本信息 
	· About:关于
![13.Help模块](./images/13.png)

# CS的使用
## 使用 Event log 进行聊天
	View->Event Log
	会显示连接团队服务器的成员，可进行聊天
![14.团队间沟通](./images/14.png)







## 创建监听器Listener
	任何行动的第一步都是建立基础设施。就Cobalt Strike而言，基础设施由一个或多个团队服务器、重定向器以及指向你的团队服务器和重定向器的 DNS 记录组成。一旦团队服务器启动并运行，你将需要连接到它并将其配置为接收来自受害系统的连接。监听器就是 Cobalt Strike 中用来执行这种任务的机制。
	Cobalt Strike的内置监听器为Beacon，在目标主机执行相关payload会向cd反弹一个shell；外置监听器为Foreign，使用cs派生一个MSF的shell回来就需要使用外部监听器。CobaltStrike的Beacon支持异步通信和交互式通信。

**建立监听**
1. Cobalt Strike → Listeners。这会打开一个标签页，列举出所有你的配置的 payload 和监听器。
2. 按 Add 按钮来创建一个新的监听器。

>name：监听器名字
payload：payload类型
HTTP Hosts：shell反弹主机，是服务端IP
HTTP Host(Stager)：控制HTTP Beacon的HTTP Stager的主机，当此payload与需要显示的stager
HTTP Port(C2)：C2监听的端口

![15.创建监听器](./images/15.png)

**手动的 HTTP 代理设置**
> Proxy Type: 配置了代理的类型。 
> Proxy Host : Beacon 代理运行地址
> Proxy Port ：Beacon 代理运行端口
> Username ：Beacon对代理的身份凭据（可选）
> Password ：Beacon对代理的身份凭据（可选）
> Ignore proxy settings;use direct connection：强制Beacon 不通过代理尝试其 HTTP 和 HTTPS 请求。（忽略则使用直连）

点击 Set 来更新 Beacon 对话框。
点击 Reset 可以把代理配置重置为默认行为。
![16HTTP 代理设置](./images/16.png)



## 创建
















```代码块
printf
```

CobaltStrike常见命令 BeaconCommands
===============
    Command                   Description
    -------                   -----------
    browserpivot              注入受害者浏览器进程
    bypassuac                 绕过UAC
    cancel                    取消正在进行的下载
    cd                        切换目录
    checkin                   强制让被控端回连一次
    clear                     清除beacon内部的任务队列
    connect                   Connect to a Beacon peerover TCP
    covertvpn                 部署Covert VPN客户端
    cp                        复制文件
    dcsync                    从DC中提取密码哈希
    desktop                   远程VNC
    dllinject                 反射DLL注入进程
    dllload                   使用LoadLibrary将DLL加载到进程中
    download                  下载文件
    downloads                 列出正在进行的文件下载
    drives                    列出目标盘符
    elevate                   尝试提权
   	execute                   在目标上执行程序(无输出)
    execute-assembly          在目标上内存中执行本地.NET程序
    exit                      退出beacon
    getprivs                  Enable system privileges oncurrent token
    getsystem                 尝试获取SYSTEM权限
    getuid                    获取用户ID
    hashdump                  转储密码哈希值
    help                      帮助
    inject                    在特定进程中生成会话
    jobkill                   杀死一个后台任务
    jobs                      列出后台任务
    kerberos_ccache_use       从ccache文件中导入票据应用于此会话
    kerberos_ticket_purge     清除当前会话的票据
    kerberos_ticket_use       从ticket文件中导入票据应用于此会话
    keylogger                 键盘记录
    kill                      结束进程
    link                      Connect to a Beacon peerover a named pipe
    logonpasswords            使用mimikatz转储凭据和哈希值
    ls                        列出文件
    make_token                创建令牌以传递凭据
    mimikatz                  运行mimikatz
    mkdir                     创建一个目录
    mode dns                  使用DNS A作为通信通道(仅限DNS beacon)
    mode dns-txt              使用DNS TXT作为通信通道(仅限D beacon)
    mode dns6                 使用DNS AAAA作为通信通道(仅限DNS beacon)
    mode http                 使用HTTP作为通信通道
    mv                        移动文件
    net                       net命令
    note                      备注      
    portscan                  进行端口扫描
    powerpick                 通过Unmanaged PowerShell执行命令
    powershell                通过powershell.exe执行命令
    powershell-import         导入powershell脚本
    ppid                      Set parent PID forspawned post-ex jobs
    ps                        显示进程列表
    psexec                    Use a service to spawn asession on a host
    psexec_psh                Use PowerShell to spawn asession on a host
    psinject                  在特定进程中执行PowerShell命令
    pth                       使用Mimikatz进行传递哈希
    pwd                       当前目录位置
    reg                       Query the registry
    rev2self                  恢复原始令牌
    rm                        删除文件或文件夹
    rportfwd                  端口转发
    run                       在目标上执行程序(返回输出)
    runas                     以另一个用户权限执行程序
    runasadmin                在高权限下执行程序
    runu                      Execute a program underanother PID
    screenshot                屏幕截图
    setenv                    设置环境变量
    shell                     cmd执行命令
    shinject                  将shellcode注入进程
    shspawn                   生成进程并将shellcode注入其中
    sleep                     设置睡眠延迟时间
    socks                     启动SOCKS4代理
    socks stop                停止SOCKS4
    spawn                     Spawn a session
    spawnas                   Spawn a session as anotheruser
    spawnto                  Set executable tospawn processes into
    spawnu                    Spawn a session underanother PID
    ssh                       使用ssh连接远程主机
    ssh-key                   使用密钥连接远程主机
    steal_token               从进程中窃取令牌
    timestomp                 将一个文件时间戳应用到另一个文件
    unlink                    Disconnect from parentBeacon
    upload                    上传文件
    wdigest                   使用mimikatz转储明文凭据
    winrm                     使用WinRM在主机上生成会话
    wmi                       使用WMI在主机上生成会话
    argue                     进程参数欺骗
