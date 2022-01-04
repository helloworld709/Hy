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

# CS 的使用

## 团队服务器

Cobalt Strike 分为客户端组件和服务器组件。服务器组件，也就是团队服务器，是 Beacon payload 的控制器，也是 Cobalt Strike 社会工程功能的托管主机。团队服务器还存储由 Cobalt Strike 收集的数据，并管理日志记录。

Cobalt Strike 团队服务器必须在受支持的 Linux 系统上运行。要启动一个 Cobalt Strike 团队服务器，使用 Cobalt Strike Linux 安装包中的 teamserver 脚本文件。

***启动服务端***


## 客户端



