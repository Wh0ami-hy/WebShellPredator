# coding=utf-8
import random
import re

import chardet
# from mysource import sqldata

nodes = []  # 存放顶点信息，
edge_list = []  # 存放边的信息


class Log:
    Random = '0'
    white = []  # 白名单
    result = []
def CheckLog(log_path):
    # 加载日志
    with open(log_path, 'rb') as f1:
        encod = chardet.detect(f1.read())['encoding']

    contents = []  # 存放日志记录

    f2 = open(log_path, 'r', encoding=encod)

    while True:
        if f2.readline() == '':
            break
        else:
            contents.append(f2.readline())  # 把URL访问记录分条存放

    # 匹配日志中的URL，清洗整理数据

    all_url1 = []  # 提取出URL1，起始地址
    all_url2 = []  # 提取出URL2，重定向后指向的地址

    for content in contents:

        log_url1 = re.search(r'(\s/[^\s]*)', content)
        log_url2 = re.search(r'[a-zA-z]+://[^\s]*', content)

        if log_url1 != None and log_url2 != None:  # 如果有页面的跳转情况，就记录URL
            all_url1.append('http://192.168.204.128' + log_url1.group(0).strip(' '))
            all_url2.append(log_url2.group(0).strip('"'))
        elif log_url1 == None and log_url2 != None:  # 如果没有页面跳转的情况，存为 空
            all_url1.append('nothing')
            all_url2.append(log_url2.group(0).strip('"'))
        elif log_url2 == None and log_url1 != None:
            all_url2.append('nothing')  # 添加一个另类顶点，指向该顶点的顶点都是孤立的点
            all_url1.append('http://192.168.204.128' + log_url1.group(0).strip(' '))

    # print(all_url1)
    # print(all_url2)

    # 找出图的所有顶点
    for node in all_url1:
        if node != 'nothing' and node not in nodes:
            nodes.append(node)

    for node in all_url2:
        if node != 'nothing' and node not in nodes:
            nodes.append(node)

    # 找出图的所有边
    for url1, url2 in zip(all_url1, all_url2):
        edge = (url1, url2)
        edge_list.append(edge)

    # print(nodes)
    # print(edge_list)

    for i, item in enumerate(edge_list):  # 将边的关系存储方式由元组转为列表
        edge_list[i] = list(item)

    for i in nodes:
        for j, item in enumerate(edge_list):  # 通过索引值修改列表中的元素

            if i == item[0]:
                edge_list[j][0] = nodes.index(i) + 1  # 设顶点从1开始
            elif i == item[1]:
                edge_list[j][1] = nodes.index(i) + 1
            elif 'nothing' == item[1]:
                edge_list[j][1] = 0  # 没有关联的顶点设为 0

    # print(edge_list)


def LoadVoid(data):  # 加载白名单
    Log.white.clear()
    try:
        for i in range(1,len(data.split(','))):
            Log.white.append(data.split(',')[i].replace('\n',''))
    except:
        pass
    else:
        return Log.white


def MainLog(data='/root/access.log',socketio=None):                 # 主函数


    Log.Random = str(random.uniform(1,999))

    log_path = data.split(',')[0]  # 获取日志路径
    url_num = 0
    class Undigraph:  # 定义一个无向图类
        def __init__(self, v):
            self.vertex = v
            self.edge = 0
            self.adj_list = [i for i in range(v)]
            self.v_edges = [[] for _ in range(v)]

        def num_of_vertices(self):
            return self.vertex

        def num_of_edges(self):
            return self.edge

        def add_edge(self, x: int, y: int):
            """Cuz this is a undirected  graph, x -> v is equals to v -> x"""
            if y not in self.v_edges[x]:
                self.v_edges[x].append(y)
            if x not in self.v_edges[y]:
                self.v_edges[y].append(x)
            self.edge += 1

        def get_edges_of(self, v):
            return self.v_edges[v]

    CheckLog(log_path)  # 调用日志处理模块

    UG = Undigraph(len(nodes) + 1)  # 设置顶点总数

    for i in edge_list:  # 设置边的关系

        UG.add_edge(i[0], i[1])

    totalVolume=len(nodes)
    processVloume=0
    pointsActSend=0.25

    for i in range(1, len(nodes) + 1):

        if len(UG.get_edges_of(i)) == 1 and UG.get_edges_of(i) == [0]:

            if nodes[i - 1] in Log.white:
                pass

            else:
                url_num = url_num + 1
                print('页面独立性较高')           # 说明
                print(nodes[i-1])       # 可疑文件名
                # sqldata.loganalyse(nodes[i-1],Log.Random)
                Log.result.append({'url': nodes[i-1], 'explain': '危险页面文件'})
        
        processVloume += 1
        if processVloume / totalVolume >= pointsActSend:
            socketio.emit('log analysis amount of progress',pointsActSend*100)
            pointsActSend += 0.25


    return Log.result

if __name__ == '__main__':
    MainLog('/root/access.log')
