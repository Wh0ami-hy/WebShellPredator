# coding=utf-8
import random
import threading
import time
import datetime
from watchdog.events import *
from watchdog.observers import Observer
# from mysource import sqldata
from mysource import threataware

class F:

    filemonitor_flag = 0         # 用来判断，程序是否已经运行，防止点击多次，运行多次
    Random = '0'


class FileEventHandler(FileSystemEventHandler):

    def __init__(self, socketio=None, iniUpdateFuncPoint=None):
        FileSystemEventHandler.__init__(self)
        self.socketio = socketio
        self.iniUpdateFuncPoint = iniUpdateFuncPoint

    def on_moved(self, event):
        rewhat = event.src_path
        rewhat = rewhat.split("/")[-1]
        prwhat = event.dest_path
        prwhat = prwhat.split("/")[-1]
        time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if event.is_directory:
            print(rewhat,'重命名为' + prwhat,time)
            self.socketio.emit('file monitoringg receiving data in table', {
            'filename': rewhat,
            'operation': "重命名为",
            'runningTime': prwhat.time
        })
            self.iniUpdateFuncPoint({
            'filename': rewhat,
            'operation': "重命名为",
            'runningTime': prwhat.time
        })
            # sqldata.filemonitor(rewhat, '重命名为' + prwhat, time, F.Random)

            if threataware.Mail.setmail:            # 邮件提示
                threataware.Smtp(str(rewhat) + '-重命名为-' + str(prwhat) + str(time))
            else:
                pass

        else:
            print(rewhat,'重命名为' + prwhat,time)
            self.socketio.emit('file monitoringg receiving data in table', {
            'filename': rewhat,
            'operation': "重命名为" + prwhat,
            'runningTime': time
        })
            self.iniUpdateFuncPoint({
            'filename': rewhat,
            'operation': "重命名为" + prwhat,
            'runningTime': time
        })
            # sqldata.filemonitor(rewhat, '重命名为' + prwhat, time, F.Random)
            if threataware.Mail.setmail:            # 邮件提示
                threataware.Smtp(str(rewhat) + '-重命名为-' + str(prwhat) + str(time))
            else:
                pass


    def on_created(self, event):
        what = event.src_path
        what = what.split("/")[-1]
        time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if event.is_directory:
            print(what,'文件夹被创建',time)
            self.socketio.emit('file monitoringg receiving data in table', {
            'filename': what,
            'operation': "文件夹被创建",
            'runningTime': time
        })
            self.iniUpdateFuncPoint({
            'filename': what,
            'operation': "文件夹被创建",
            'runningTime': time
        })
            # sqldata.filemonitor(what, '文件夹被创建', time, F.Random)
            if threataware.Mail.setmail:            # 邮件提示
                threataware.Smtp(str(what) + '-文件夹被创建-' + str(time))
            else:
                pass

        else:
            print(what,'文件被创建',time)
            self.socketio.emit('file monitoringg receiving data in table', {
            'filename': what,
            'operation': "文件夹被创建",
            'runningTime': time
        })
            self.iniUpdateFuncPoint({
            'filename': what,
            'operation': "文件夹被创建",
            'runningTime': time
        })
            # sqldata.filemonitor(what, '文件被创建', time, F.Random)
            if threataware.Mail.setmail:            # 邮件提示
                threataware.Smtp(str(what) + '-文件被创建-' + str(time))
            else:
                pass



    def on_deleted(self, event):
        what = event.src_path
        what = what.split("/")[-1]
        time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if event.is_directory:
            print(what,"文件夹被删除",time)
            self.socketio.emit('file monitoringg receiving data in table', {
            'filename': what,
            'operation': "文件夹被删除",
            'runningTime': time
        })
            self.iniUpdateFuncPoint({
            'filename': what,
            'operation': "文件夹被删除",
            'runningTime': time
        })
            # sqldata.filemonitor(what, '文件夹被删除', time, F.Random)
            if threataware.Mail.setmail:            # 邮件提示
                threataware.Smtp(str(what) + "-文件夹被删除-" + str(time))
            else:
                pass


        else:
            print(what,"文件被删除",time)
            self.socketio.emit('file monitoringg receiving data in table', {
            'filename': what,
            'operation': "文件夹被删除",
            'runningTime': time
        })
            self.iniUpdateFuncPoint({
            'filename': what,
            'operation': "文件夹被删除",
            'runningTime': time
        })
            # sqldata.filemonitor(what, '文件被删除', time, F.Random)
            if threataware.Mail.setmail:            # 邮件提示
                threataware.Smtp(str(what) + "-文件被删除-" + str(time))
            else:
                pass



    def on_modified(self, event):
        what = event.src_path
        what = what.split("/")[-1]
        time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if event.is_directory:
            print(what,"文件夹被修改",time)
            self.socketio.emit('file monitoringg receiving data in table', {
            'filename': what,
            'operation': "文件夹被修改",
            'runningTime': time
        })
            self.iniUpdateFuncPoint({
            'filename': what,
            'operation': "文件夹被修改",
            'runningTime': time
        })
            # sqldata.filemonitor(what, '文件夹被修改', time, F.Random)
            if threataware.Mail.setmail:            # 邮件提示
                threataware.Smtp(str(what) + "-文件夹被修改-" + str(time))
            else:
                pass

        else:
            print(what,"文件被修改",time)
            self.socketio.emit('file monitoringg receiving data in table', {
            'filename': what,
            'operation': "文件夹被修改",
            'runningTime': time
        })
            self.iniUpdateFuncPoint( {
            'filename': what,
            'operation': "文件夹被修改",
            'runningTime': time
        })
            # sqldata.filemonitor(what, '文件被修改', time, F.Random)
            if threataware.Mail.setmail:            # 邮件提示
                threataware.Smtp(str(what) + "-文件被修改-" + str(time))
            else:
                pass


def MonitorFile(path='/root/testshell', socketio=None, iniUpdateFuncPoint=None):                  # 其实是threading.Thread的子类，通过observer.start()使之运行在一个线程中，不会阻塞主进程运行，然后可以调用observer.stop()来停止该线程

    print(F.filemonitor_flag)
    if F.filemonitor_flag == 0:
        F.filemonitor_flag = 1
        F.Random = str(random.uniform(1, 999))
        global observer
        observer = Observer()
        event_handler = FileEventHandler(socketio=socketio, iniUpdateFuncPoint=iniUpdateFuncPoint)
        observer.schedule(event_handler, path, True)
        observer.start()
        print('文件监控开始')
    else:
        print('已经运行了')

def StopMonitor():
    F.filemonitor_flag = 0
    F.Random = '0'
    observer.stop()
    print('文件监控结束')
    print(F.filemonitor_flag)

if __name__ == '__main__':
    print(123)
    MonitorFile('/root/test')

