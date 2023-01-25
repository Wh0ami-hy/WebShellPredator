from flask import Flask,redirect,url_for,flash,session,request,render_template,send_file
from flask_socketio import SocketIO,emit
from datetime import timedelta
import json
import os
import gevent
import time
import random
import configparser
from mysource import loganalyse,dynamicscan, staticscan,filemonitor,smartscan,scanport,threataware
from mysource.Report import report
from auxiliary.iniFileOperations import IniFileOperations
import hashlib

# -----------------------分割-------------------------------

app = Flask(__name__) # 实例化Falsk
app.config['SECRET_KEY'] = 'FFx5EX0GxW8qNchTk0r2c96NMo1ij4Zg' # 设置密钥
app.jinja_env.variable_start_string = '{:' # 设置jinjia2模板匹配括号，避免与VUE发生冲突
app.jinja_env.variable_end_string = ':}'

socketio = SocketIO(app, async_mode='threading') # socketIo的实例化

baseDir = os.path.dirname(os.path.abspath(__file__)) # 获取app.py文件所在的绝对路径
myIniOpera = IniFileOperations(os.path.join(baseDir, 'initial.ini')) # 将ini文件操作类实例化

# --------------------------------------------------------

# 生成当前时间
def get_time():
    return time.strftime("%Y.%m.%d.%H:%M:%S", time.localtime()) 

# 该函数用于身份验证，接受帐号和口令，返回布尔值
def authentication(account,password):
    psdInSHA256 = hashlib.sha256(password.encode('utf-8')).hexdigest()
    try:
        return myIniOpera.get_passwordSummary(account) == psdInSHA256
    except:
        return False

# 该函数用于验证黑名单或白名单是否可用，返回布尔值
def check_file_available(filename):
    # filename变量由前端传递过来只能有两个值：blackList或whiteList
    if filename == "blackList":
        return myIniOpera.get_blacklist_vstr() != ''
    else:
        return myIniOpera.get_whitelist_vstr() != ''

# ------------------------文本编辑器消息--------------------------------

# 接收获取黑名单文本内容的请求，并发送该资源
@socketio.on('give me file blackList')
def send_blackList(data):
    content = myIniOpera.get_blacklist_vstr()
    socketio.emit('get blackList',content)

# 接收获取白名单文本内容的请求，并发送该资源
@socketio.on('give me file whiteList')
def send_blackList(data):
    content = myIniOpera.get_whitelist_vstr()
    socketio.emit('get whiteList',content)

# 接收发送过来的文本，保存并返回文本状态
@socketio.on('save file')
def save_file(dataInDict):
    # dataInDict为字典，包含filename和data两个键值对，分别为文件名和文本内容
    flag = 0
    if dataInDict['filename'] == 'whiteList':
        myIniOpera.set_whitelist(dataInDict['data'])
    else:
        myIniOpera.set_blacklist(dataInDict['data'])
    
    if check_file_available(dataInDict['filename']):
        flag = 1
    else:
        flag = 0
    socketio.emit('check file condition ' + dataInDict['filename'],flag)

# 接收检查黑/白名单是否可用，并返回信息
@socketio.on('check file')
def check_file(dataInDict):
    # dataInDict只有一个filename键值对
    flag = 1
    if check_file_available(dataInDict['filename']): # 1为可用，0为不可用
        flag = 1
    else:
        flag = 0
    socketio.emit('check file condition ' + dataInDict['filename'],flag)

# ---------------------总览页面消息-----------------------------

# 发送页面初始数据
@socketio.on('total get initdata')
def total_get_initdata(data):
    socketio.emit('total receive data',{
        'op1': myIniOpera.get_staticresult(),
        'op2':  myIniOpera.get_intellreuslt(),
        'op3':{
            'dt1': myIniOpera.get_historydate(),
            'dt2': myIniOpera.get_historydata()
        }
    })


# --------------------正则匹配页面消息------------------------------

# 接收开始检测的请求，并返回检测出的数据
@socketio.on('regular matching start test')
def regular_matching_start_test(dataInDict):
    data = staticscan.regex(path=str(dataInDict['path']), socketio=socketio) # 调用正则匹配函数，返回字典
    socketio.emit('regular matching receiving data in table', data.results1) # 发送数据，数据结构为：字典的列表
    myIniOpera.set_staticresult(normal=data.all - data.num, target=data.num) # 更新ini中的数据

# ----------------------信息熵页面消息----------------------------------

# 功能同上
@socketio.on('information entropy start test')
def information_entropy_start_test(dataInDict):
    data = staticscan.Entropy(path=dataInDict['path'], socketio=socketio).results2
    socketio.emit('information entropy receiving data in table', data)

# ----------------------智能检测页面消息----------------------------------

# 功能同上
@socketio.on('intelligent detection start test')
def intelligent_detection_start_test(dataInDict):
    data = smartscan.SmartScanStart(dir=dataInDict['path'], socketio=socketio, pklPath=os.path.join(baseDir,'save'))
    myIniOpera.set_pathtested(dataInDict['path'])
    myIniOpera.set_intellresult(normal=data.normal, target=data.target)
    myIniOpera.update_history(htime=get_time(), hdata=data.target)
    print(data.result)
    socketio.emit('intelligent detection receiving data in table', data.result)
    print('智能检测:已经发送检测结果')

# ---------------------进程监控页面消息-----------------------------------

# 功能同上
@socketio.on('process monitoring start test')
def process_monitoring_start_test(data):
    dynamicscan.StartCheckPro(data=myIniOpera.get_blacklist_vstr(), socketio=socketio,iniUpdateFuncPoint=myIniOpera.update_blackresult)

# 接收终止监控的请求
@socketio.on('process monitoring stop test')
def process_monitoring_stop_test(data):
    dynamicscan.D.dynamicscan_start = False

# -----------------文件监控页消息---------------------------------

# 大致逻辑同上
@socketio.on('file monitoring start test')
def file_monitoring_start_test(dataInDict):
    filemonitor.MonitorFile(path=dataInDict['path'], socketio=socketio, iniUpdateFuncPoint=myIniOpera.update_fileresult)

@socketio.on('file monitoring stop test')
def file_monitoring_stop_test(data):
    filemonitor.StopMonitor()


# -----------------------端口扫描页消息---------------------------

# 接收扫描请求
@socketio.on('port scan start test')
def port_scan_start_test(data):
    data = scanport.Start()
    socketio.emit('port scan receiving data in table', data)

# ----------------------日志分析页消息----------------------------

# 同正则匹配页逻辑相同
@socketio.on('log analysis start test')
def log_analysis_start_test(dataInDict):
    data = loganalyse.MainLog(data=dataInDict['path'], socketio=socketio)
    socketio.emit('log analysis receiving data in table', data)

# --------------------威胁提示页消息------------------------------

# 这个是接收邮箱的
@socketio.on('threat warming submit')
def threat_warming_submit(dataInString):
    threataware.Mail.sendmail = dataInString
    threataware.Mail.setmail = True

# 这个是用来解绑邮箱的
@socketio.on('threat warming unbind')
def threat_warming_unbind(dataInString):
    threataware.Mail.setmail = False

# ----------------------检测报告页面消息----------------------------

# 用于保存报表
@socketio.on('report create report')
def report_create_report(data):
    report.create_report(myIniOpera)

# --------------------------------------------------

# 登录页路由
@app.route('/',methods=['GET','POST'])
def login():
    # 先判断用户是否已经再session会话中，如果在，就直接跳转到index
    if 'username' in session:
        return redirect(url_for('index',username=session['username']))
    else:
        # 否则 就渲染登录页
        if request.method == 'POST': # 当接收到表单请求时，代表用户登录请求
            if authentication(request.form['username'], request.form['password']): # 身份验证正确就重定向到主页
                session['username'] = request.form['username']
                return redirect(url_for('index',username=request.form['username']))
            else: # 否则重新刷新页面，并渲染一个消息闪现
                flash('帐号或密码错误，请重新输入')
                return redirect(url_for('login'))
        else: 
            return render_template('login.html')

# 主页路由
@app.route('/index/<username>')
def index(username):
    # 先判断用户会名是否在会话中，否则让他重回到登录页进行登录
    if 'username' not in session:
        return redirect(url_for('login'))
    else: # 在会话中，渲染模板
        myIniOpera.clean_blackresult() # 清空进程监控和文件监控的结果
        myIniOpera.clean_fileresult()
        return render_template('index.html', username=username)

# 各个页面渲染
@app.route('/pages/<pagename>')
def select_pages(pagename):
    if(pagename != 'report_template'):
        return render_template(pagename+'.html')
    else:
        data = report.generate_data(myIniOpera) # 报表页面要单独传递数据
        return render_template(pagename+'.html',
                            host_name=data['host_name'],
                            sys_name=data['sys_name'],
                            ip_adders=data['ip_adders'],
                            curr_time=data['curr_time'],
                            path_name=data['path_name'],
                            process=data['process'],
                            monitors=data['monitors'],
                            static_normal=data['static'][0],
                            static_danger=data['static'][1],
                            intel_normal=data['intel'][0],
                            intel_danger=data['intel'][1],
                            history_date=data['history_date'],
                            history_data=data['history_data'],
                            process_num=len(data['process']),
                            monitors_num=len(data['monitors']),
                            detect_num=data['static'][0] + data['intel'][0])

# 登出路由
@app.route('/logout')
def logout():
    session.pop('username',None) # 弹出会话
    return redirect(url_for('login'))

# 文件树弹出层
@app.route('/pathselect')
def path_select():
    return render_template('path_select.html')

# 编辑器弹出层
@app.route('/editor')
def editor():
    return render_template('editor.html')


if __name__ == '__main__':
    # gevent.get_hub().NOT_ERROR += (KeyboardInterrupt,) #这一句话只在windows下使用
    # webbrowser.open('http://127.0.0.1:5000/')
    socketio.run(app, host=myIniOpera.get_flaskconfig()['address'], port=int(myIniOpera.get_flaskconfig()['port']))
