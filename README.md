# 项目介绍

本系统是Linux服务器上WebShell文件的检测与分析系统，共七种功能五种检测方法。采用正则匹配、信息熵、提取URL重定向关系、进程监控、提取Opcode等技术提高检测效率和准确率。此外，本系统还支持导出检测报告、邮件提示（发现webshell后立即向用户发送邮件）

# 环境说明

##  开发环境

- 操作系统：Ubuntu server 20.04
- 编程语言：Python3.8.10
- 开发工具：Visual Studio、Navicat

## 环境依赖

- 操作系统:Ubuntu server 20.04
- Python: 3.8.10
- MySQL: 版本：5.7.26  编码：utf8
- PHP:7.4
- [PHP插件vld:0.16.0]([PECL :: Package :: vld](https://pecl.php.net/package/vld))

# 使用说明

## Docker镜像使用

导入docker镜像文件

百度网盘链接：https://pan.baidu.com/s/1Wlg-92MyzhKXOeyO0zHXOA 
提取码：1234

## 常规使用

### 安装python依赖

```python
pip install -r requirements.txt
```

### 运行

```python
python app.py
```

| 初始账号 | 初始密码 |
| -------- | -------- |
| admin    | admin    |

### initial.ini 配置文件

```
[flaskConfig]设置该系统的访问IP和端口
[users]设置用户账户和密码（密码采用sha256加密）
其他项不需要手动更改
```

## 项目结构

| 文件/文件夹      | 功能                                 |
| ---------------- | ------------------------------------ |
| auxiliary        | 读取 initial.ini 配置文件            |
| mysource         | 存放实现检测功能的代码               |
| report           | 存放生成检测报告的代码以及导出的报告 |
| save             | 存放机器学习的模型                   |
| static           | 存放静态资源                         |
| templates        | 存放HTML页面                         |
| app.py           | 总程序                               |
| initial.ini      | 配置文件                             |
| requirements.txt | python依赖库                         |

## 设置邮箱

该邮箱是用来发送邮件的，而不是接收邮件

具体看`mysource/threataware.py`

# 技术说明

整体采用flask框架

后端采用Flask-SocketIO向前端提供数据

前端采用Layui、Jinja2

该项目支持数据持久化，具体看`mysource/sqldata.py`

# 项目展示

![QQ截图20230324144411](.\pic\QQ截图20230324144411.png)

![QQ截图20230324144441](.\pic\QQ截图20230324144441.png)

![QQ截图20230324144527](.\pic\QQ截图20230324144527.png)

![QQ截图20230324144541](.\pic\QQ截图20230324144541.png)

![QQ截图20230324144554](.\pic\QQ截图20230324144554.png)

![QQ截图20230324144605](.\pic\QQ截图20230324144605.png)

![QQ截图20230324144616](.\pic\QQ截图20230324144616.png)

![QQ截图20230324144646](.\pic\QQ截图20230324144646.png)

![QQ截图20230324144717](.\pic\QQ截图20230324144717.png)