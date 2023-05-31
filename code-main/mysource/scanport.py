import psutil,netaddr



def Start():
    result = []
    for session in psutil.net_connections(kind="all"):
        if session.laddr and session.raddr:
            sip = session.laddr.ip  # 源IP
            sport = session.laddr.port  # 源端口
            dip = session.raddr.ip  # 目的IP
            dport = session.raddr.port  # 目的端口
            status = session.status  # 会话状态
            if status == 'ESTABLISHED':  # 将状态的英文 替换为 中文
                status = '正在通信'
            elif status == 'LISTEN':
                status = '正在监听'
            elif status == 'CLOSE_WAIT':
                status = '结束等待'
            elif status == 'TIME_WAIT':
                status = '连接中断'
            elif status == 'FIN_WAIT2':
                status = '连接中断'
            elif status == 'FIN_WAIT1':
                status = '连接中断'
            elif status == 'SYN_SENT':
                status = '发送请求'
            else:pass

            try:
                pid = session.pid  # 进程号
                exe = psutil.Process((pid)).name()  # 进程名
                filter_dip = netaddr.IPAddress(dip)  # 格式化目的IP地址，用于后续判断是否是公网IP
                filter_sip = netaddr.IPAddress(sip)


                # 数据组装
                s = "{0:},{1:},{3:},{2:},{4:},{5:}".format(
                    'tcp',  # 协议(是固定的)
                    sport,  # 本地端口
                    dip,  # 目标ip
                    status,  # 端口状态
                    pid,  # 进程pid
                    exe.lower(),  # 进程名
                )
                print(s)
                result.append({'protocol':'tcp','port':sport,'state':status,'ip':dip,'processName':exe.lower(),'pid':pid})
            except Exception as e:
                print(e)
    return result

if __name__ == '__main__':
    Start()