# coding=utf-8
import ctypes
import inspect
import random
import time
import psutil
import threading
from mysource import my_thread
# from mysource import sqldata
from mysource import threataware

class D:                # 使用此方法来达到，整个程序中同一变量名对应同一变量
    dynamicscan_flag = 0         # 用来判断，程序是否已经运行，防止点击多次，运行多次
    dynamicscan_start = True       # 用来判断是否结束子进程
    Random = '0'
    pro = []



def CheckProcess(data, socketio, iniUpdateFuncPoint):
    D.Random = str(random.uniform(1,999))
    print("生成随机数:%s"%D.Random)

    data = data.split(',')              # 获取黑名单
    dd = data.copy()            # 处理换行符号
    data.clear()
    for i in dd:
        i = i.strip('\n')
        data.append(i)
    print('黑名单',data)


    first = []  # 用来记录进程id，防止输出重复id
    while True:

        if D.dynamicscan_start:
            pids = psutil.pids()
            try:
                for pid in pids:
                    p = psutil.Process(pid)  # 根据进程ID获取进程信息
                    if p.name() in data:
                        if str(pid) in first:  # 比对PID
                            pass
                        else:
                            first.append(str(pid))

                            pn = p.name()  # 进程名称

                            pd = str(pid)  # 进程ID

                            time_pro = time.localtime(p.create_time())
                            time_pro = time.strftime("%Y/%m/%d %H:%M", time_pro)  # 进程产生的时间
                            # D.pro.append({'processNmae': str(pn), 'description': "可疑进程", 'pid': str(pd),
                                            #   'runningTime': str(time_pro)})
                            socketio.emit('process monitoring receiving data in table', { # 数据一条一条地发送
            'processName': str(pn),
            'description': "可疑进程",
            'pid': str(pd),
            'runningTime':str(time_pro)
            })
                            iniUpdateFuncPoint({ # 更新ini文件
            'processName': str(pn),
            'description': "可疑进程",
            'pid': str(pd),
            'runningTime':str(time_pro)
            })

                            print(pn, '可疑进程', pd, time_pro)

                            # sqldata.dynamicscan(pn, pd, time_pro, D.Random)

                            if threataware.Mail.setmail:
                                threataware.Smtp(str(pn) + '-可疑进程-' + str(pd) + '-' +str(time_pro))


                        continue
            except:
                pass

        else:
            D.dynamicscan_start = True
            D.dynamicscan_flag = 0  # 还原这些标志，方便下次使用
            D.Random = '0'
            for i in range(0, threading.active_count()):
                print("当前所有线程:%s"%(threading.enumerate()[i].name))        # 测试语句
                if threading.enumerate()[i].name == 'dynamic':  # 要结束的子线程的名字
                    t = threading.enumerate()[i]  # t 参数是要结束的子线程对象
                    print("stoped")
                    my_thread.stop_thread(t)
                    break
                else:
                    continue


def StartCheckPro(data, socketio, iniUpdateFuncPoint):          # 传入数据,data is String
    if D.dynamicscan_flag == 0:
        D.dynamicscan_flag = 1
        # D.result.clear()
        process = threading.Thread(target=CheckProcess,args=(data,socketio,iniUpdateFuncPoint,),name='dynamic')
        # process.daemon = True  # 设置主进程守护
        process.start()
    else:
        print('已经有一个进程在运行了')
        return 0

def CheckProcessStop():
    print('?????????????')
    D.dynamicscan_start = False
    print('!!!!!!!!!!!!!!')




if __name__ == '__main__':

    StartCheckPro('firefox')