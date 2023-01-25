# coding=utf-8
import pymysql
from pymysql.converters import escape_string
# from mysource import filetree

#数据库连接
def connect():
    conn = pymysql.connect(
            host='127.0.0.1',
            user='root',
            password='root',
            db='webshell',
            charset='utf8',
            # autocommit=True,    # 如果插入数据，， 是否自动提交? 和conn.commit()功能一致。
        )
    return conn

#注册
def register(id,password):
    conn = connect()
    cur = conn.cursor()
    try:
        insert_sqli ="insert into ws_user(user_id,user_password) values ('%s','%s')" % (id,password)
        print(insert_sqli)
        cur.execute(insert_sqli)
    except Exception as e:
        print("插入数据失败:", e)
    else:
        # 如果是插入数据， 一定要提交数据， 不然数据库中找不到要插入的数据;
        conn.commit()
        print("插入数据成功;")
    # 4. 关闭游标
    cur.close()
    # 5. 关闭连接
    conn.close()
#登录
def login(id,password):  #帐号密码均为字符串
    conn = connect()
    cur = conn.cursor()
    sql = """select user_password from ws_user where user_id =%s """
    cur.execute(sql, (id,))
    result = cur.fetchone()
    print(result)
    if result == None:
        print("帐号或密码错误")
    elif result[0] == password:
        print("登录成功")
    else:
        print("帐号或密码错误")
    # 4. 关闭游标
    cur.close()
    # 5. 关闭连接
    conn.close()

#动态检测参数：进程名（字符串），说明（字符串），PID（字符串），运行时间（字符串）,随机数（字符串）
def dynamicscan(name,PID,time,random):
    conn = connect()
    cur = conn.cursor()
    try:
        insert_sqli = "insert into dynamicscan(name,statement,PID,time,random) values ('%s','可疑进程','%s','%s','%s')" % (name,PID,time,random)
        cur.execute(insert_sqli)
    except Exception as e:
        print("插入数据失败:", e)
    else:
        # 如果是插入数据， 一定要提交数据， 不然数据库中找不到要插入的数据;
        conn.commit()
        print("插入数据成功;")
    # 4. 关闭游标
    cur.close()
    # 5. 关闭连接
    conn.close()
#测试
"""
name = "qq.exe"
PID = "332"
time = "2020-02-31 21:23:34"
random = "123"
dynamicscan(name,PID,time,random)
"""

#文件监控参数：文件（字符串），操作（字符串），时间（字符串），随机数（字符串）
def filemonitor(file,action,time,random):
    conn = connect()
    cur = conn.cursor()
    try:
        insert_sqli = "insert into filemonitor(file,action,time,random) values ('%s','%s','%s','%s')" % (file,action,time,random)
        cur.execute(insert_sqli)
    except Exception as e:
        print("插入数据失败:", e)
    else:
        # 如果是插入数据， 一定要提交数据， 不然数据库中找不到要插入的数据;
        conn.commit()
        print("插入数据成功;")
    # 4. 关闭游标
    cur.close()
    # 5. 关闭连接
    conn.close()
#测试
"""
file = "D:\\test\\test.txt"
action = "文件被移动"
time = "2021-07-23 17：54：01"
random = "234"
filemonitor(file,action,time,random)
"""

#日志分析参数：URL（字符串），说明（固定字符串："页面独立性较高"），随机数（字符串）
def loganalyse(URL,random):
    conn = connect()
    cur = conn.cursor()
    try:
        insert_sqli = "insert into loganalyse(URL,statement,random) values ('%s','页面独立性较高','%s')" % (URL,random)
        cur.execute(insert_sqli)
    except Exception as e:
        print("插入数据失败:", e)
    else:
        # 如果是插入数据， 一定要提交数据， 不然数据库中找不到要插入的数据;
        conn.commit()
        print("插入数据成功;")
    # 4. 关闭游标
    cur.close()
    # 5. 关闭连接
    conn.close()
#测试
"""
URL = "http://192.168.1.34"
random = "313"
loganalyse(URL,random)
"""

#端口扫描参数：协议（字符串）、本地端口（字符串），端口状态（字符串）、目标IP（字符串）、进程PID（字符串）、进程名（字符串）、随机数（字符串）
def scanport(protocol,localport,portstatus,targetip,PID,name,random):
    conn = connect()
    cur = conn.cursor()
    try:
        insert_sqli = "insert into scanport(protocol,localport,portstatus,targetip,PID,name,random) values ('%s','%s','%s','%s','%s','%s','%s')" % (
        protocol,localport,portstatus,targetip,PID,name,random)
        cur.execute(insert_sqli)
    except Exception as e:
        print("插入数据失败:", e)
    else:
        # 如果是插入数据， 一定要提交数据， 不然数据库中找不到要插入的数据;
        conn.commit()
        print("插入数据成功;")
    # 4. 关闭游标
    cur.close()
    # 5. 关闭连接
    conn.close()
#测试
"""
protocol = "TCP"
localport = "5540"
portstatus = "正在监听"
targetip = "10.1.45.56"
PID = "54"
name = "qq.exe"
random = "7841"
scanport(protocol,localport,portstatus,targetip,PID,name,random)
"""

#正则匹配参数：文件（字符串），危险代码（字符串），时间（字符串），随机数（字符串）
def staticscan_1(file, dangercode, time, random):
    dangercode = escape_string(dangercode)      # 转义
    conn = connect()
    cur = conn.cursor()
    try:
        insert_sqli = "insert into staticscan_1(file,dangercode,time,random) values ('%s','%s','%s','%s')" % (file, dangercode, time, random)
        cur.execute(insert_sqli)
    except Exception as e:
        print("插入数据失败:", e)
    else:
        # 如果是插入数据， 一定要提交数据， 不然数据库中找不到要插入的数据;
        conn.commit()
        print("插入数据成功;")
    # 4. 关闭游标
    cur.close()
    # 5. 关闭连接
    conn.close()

# 信息熵参数：文件（字符串），熵（字符串）时间（字符串），随机数（字符串）
def staticscan_2(file,var,time,random):
    conn = connect()
    cur = conn.cursor()
    try:
        insert_sqli = "insert into staticscan_2(file,showfile,var,time,random) values ('%s','可疑文件','%s','%s','%s')" % (file,var,time,random)
        cur.execute(insert_sqli)
    except Exception as e:
        print("插入数据失败:", e)
    else:
        # 如果是插入数据， 一定要提交数据， 不然数据库中找不到要插入的数据;
        conn.commit()
        print("插入数据成功;")
    # 4. 关闭游标
    cur.close()
    # 5. 关闭连接
    conn.close()
#测试
"""
file = "D:\\test"
dangercode = "eaco@"
time = "2020-02-04 12:36:00"
random = "12"
var = "5.12"
staticscan_1(file, dangercode, time, random)
staticscan_2(file, var, time, random)
"""
#威胁提示：用户名（字符串），邮箱（字符串）

def threataware(user,email):
    conn = connect()
    cur = conn.cursor()
    try:
        sql = "UPDATE ws_user SET user_email = '%s' WHERE user_id = '%s'" % (email,user)
        cur.execute(sql)
    except Exception as e:
        print("更新数据失败:", e)
    else:
        # 如果是插入数据， 一定要提交数据， 不然数据库中找不到要插入的数据;
        conn.commit()
        print("更新数据成功;")
    # 4. 关闭游标
    cur.close()
    # 5. 关闭连接
    conn.close()
#测试
"""
user = "first"
email = "111111@qq.com"
threataware(user,email)
"""

#智能检测：文件（字符串），opcode（字符串）,检测结果（字符串）
def smartscan(file,opcode,resault,random):
    conn = connect()
    cur = conn.cursor()
    try:
        insert_sqli = "insert into smartscan(file,opcode,resault,random) values ('%s','%s','%s','%s')" % (
        file,opcode,resault,random)
        cur.execute(insert_sqli)
    except Exception as e:
        print("插入数据失败:", e)
    else:
        # 如果是插入数据， 一定要提交数据， 不然数据库中找不到要插入的数据;
        conn.commit()
        print("插入数据成功;")
    # 4. 关闭游标
    cur.close()
    # 5. 关闭连接
    conn.close()
# ------------------------------------------------- 获取目录树----------------------------------------


if __name__ == '__main__':

    # s = '''("$x($_POST['x'])", 'x', 'POST', "'x'")'''
    # s = escape_string(s)
    #
    # staticscan_1("/root/testshell/2020.08.20.12.php",s,"2021-07-04 16:02:04","5")
    pass