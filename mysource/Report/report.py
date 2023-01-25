import time
import socket
import platform
from jinja2 import Environment, FileSystemLoader
import os

def generate_data(myObject): # 用于生成数据
    # 获取主机名
    hostname = platform.node()
    # 获取系统名称
    sys_name = platform.platform()
    # 获取本机IP地址
    local_ip = socket.gethostbyname(socket.gethostname())
    # 获取当前时间
    ctime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    data = {'host_name': hostname,
            'sys_name': sys_name,
            'ip_adders': local_ip,
            'curr_time': ctime,
            'path_name': myObject.get_pathtested(),
            'process': myObject.get_blackreuslt(),
            'monitors': myObject.get_fileresult(),
            'static': myObject.get_staticresult(),
            'intel': myObject.get_intellreuslt(),
            'history_date': myObject.get_historydate(),
            'history_data': myObject.get_historydata()}
    
    return data

def create_report(myObject): # 用于生成报表

    data = generate_data(myObject)

    env = Environment(loader=FileSystemLoader(
        os.path.join(os.path.dirname(os.path.abspath(__file__)))
    ))

    template = env.get_template('template.html')

    # 生成随机文件名
    file_name = 'report_' + str(time.time()) + '.html'

    with open(
        os.path.join(os.path.dirname(os.path.abspath(__file__)),'../../report/'+file_name)
        , 'w+', encoding='utf-8') as f:
        out = template.render(host_name=data['host_name'],
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
        f.write(out)
        f.close()
    print('生成报告成功！', file_name)

if __name__ == '__main__':
    create_report()