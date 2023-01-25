import configparser

# 一些ini文件操作的集合，避免在视图层把代码弄得太乱
class IniFileOperations:
    def __init__(self, path=None): # 在这里传入ini文件路径
        self.config = configparser.ConfigParser() # Configparser实例化
        self.path = path
        self.config.read(path) # 读取ini文件

    # 从列表中构建字典的列表，返回字典的列表，接受参数为字典键组成的元组, 列表
    def create_listeddict(self, dataInTuple, dataInList):
        listedDict = []
        for item in dataInList:
            tempList = item.split(',')
            tempDict = {}
            index = 0
            for key in dataInTuple:
                tempDict[key] = tempList[index]
                index += 1
            listedDict.append(tempDict)
        return listedDict

    # 获取黑名单，返回值数据类型为：列表
    def get_blacklist(self):
        blackList = self.config['blackList']['processname'].split(',')
        return blackList
    
    # 获取黑名单，返回值数据类型为：字符串
    def get_blacklist_vstr(self):
        return self.config['blackList']['processname']

    # 获取白名单，返回值数据类型为：列表
    def get_whitelist(self):
        whiteList = self.config['whiteList']['urls'].split(',')
        return whiteList
    
    # 获取白名单，返回值数据类型为：字符串
    def get_whitelist_vstr(self):
        return self.config['whiteList']['urls']

    # 获取flask配置，返回值数据类型为：字典 {'port': xx ,'address' : xx}
    def get_flaskconfig(self):
        flaskConfig = {}
        flaskConfig['port'] = self.config['flaskConfig']['port']
        flaskConfig['address'] = self.config['flaskConfig']['address']
        return flaskConfig

    # 获取监控或扫描路径，返回值数据类型为：字符串
    def get_pathtested(self):
        return self.config['path']['path_name']

    # 获取静态检测结果，返回值数据类型为：列表
    def get_staticresult(self):
        staticResult = self.config['detection']['static'].split(',')
        return list(map(int, staticResult))

    # 获取智能检测结果，返回值数据类型为：列表
    def get_intellreuslt(self):
        intellResult = self.config['detection']['intel'].split(',')
        return list(map(int, intellResult))
    
    # 获取历史记录的日期，返回值数据类型为：列表
    def get_historydate(self):
        return self.config['history']['date'].split(',')
    
    # 获取历史记录的数据，返回值数据类型为：列表
    def get_historydata(self):
        historyData = self.config['history']['data'].split(',')
        return list(map(int, historyData))
    
    # 获取进程监控结果，返回值数据类型：字典的列表
    def get_blackreuslt(self):
        if self.config['blackResult']['list1'] == '':
            return self.create_listeddict(('进程名称','说明','PID','运行时间'), [' , , , '])
        else:
            blackResultListedString = self.config['blackResult']['list1'].split('|')
            return self.create_listeddict(('进程名称','说明','PID','运行时间'),blackResultListedString)
    
    # 获取文件监控结果，返回值数据类型：字典的列表
    def get_fileresult(self):
        if  self.config['fileResult']['list2'] == '':
            return self.create_listeddict(('文件','操作','运行时间'), [' , , '])
        else:
            fileResultListedString = self.config['fileResult']['list2'].split('|')
            return self.create_listeddict(('文件','操作','运行时间'), fileResultListedString)
    
    # 获取用户密码摘要，接收用户名，返回摘要值
    def get_passwordSummary(self,username):
        return self.config['users'][username]
    
    # 写入黑名单，接受数据类型为：字符串
    def set_blacklist(self, dataInString):
        self.config.set('blackList', 'processname', dataInString)
        self.config.write(open(self.path, 'w'))

    # 写入白名单，接受数据类型为：字符串
    def set_whitelist(self, dataInString):
        self.config.set('whiteList', 'urls', dataInString)
        self.config.write(open(self.path, 'w'))
    
    # 写入扫描或监控路径，接受数据类型为：字符串
    def set_pathtested(self, dataInString):
        self.config.set('path', 'path_name', dataInString)
        self.config.write(open(self.path, 'w'))
    
    # 写入静态检测结果，接受两个参数，各为整型,normal为正常文件数，target为危险文件数
    def set_staticresult(self, normal=0, target=0):
        result = '{},{}'.format(normal,target)
        self.config.set('detection', 'static', result)
        self.config.write(open(self.path, 'w'))
    
    # 写入智能检测结果，接受两个参数，各为整型,normal为正常文件数，target为危险文件数
    def set_intellresult(self, normal=0, target=0):
        result = '{},{}'.format(normal,target)
        self.config.set('detection', 'intel', result)
        self.config.write(open(self.path, 'w'))

    # 更新历史，接入两个参数，htime为时间字符串，hdata为检测数值，整型
    def update_history(self, htime='', hdata=0):
        historyDate = self.config['history']['date']
        historyData = self.config['history']['data']
        self.config.set('history', 'date', "{},{}".format(historyDate,htime))
        self.config.set('history', 'data', "{},{}".format(historyData,hdata))
        self.config.write(open(self.path, 'w'))
    
    # 更新进程监控结果，接受一个字典
    def update_blackresult(self, dataInDict):
        newResult = '{},{},{},{}'.format(dataInDict['processName'],dataInDict['description'],dataInDict['pid'],dataInDict['runningTime'])
        oldResult = self.config['blackResult']['list1']
        if oldResult.strip() == '':
            self.config.set('blackResult', 'list1', "{}".format(newResult))
        else:
            self.config.set('blackResult', 'list1', "{}|{}".format(oldResult,newResult))
        self.config.write(open(self.path, 'w'))
    
    # 更新文件监控结果，接受一个字典
    def update_fileresult(self, dataInDict):
        newResult = '{},{},{}'.format(dataInDict['filename'],dataInDict['operation'],dataInDict['runningTime'])
        oldResult = self.config['fileResult']['list2']
        if oldResult.strip() == '':
            self.config.set('fileResult', 'list2', "{}".format(newResult))
        else:
            self.config.set('fileResult', 'list2', "{}|{}".format(oldResult,newResult))
        self.config.write(open(self.path, 'w'))
    
    # 清空进程监控结果
    def clean_blackresult(self):
        self.config.set('blackResult', 'list1', '')
        self.config.write(open(self.path, 'w'))
    
    # 清空文件监控结果
    def clean_fileresult(self):
        self.config.set('fileResult', 'list2', '')
        self.config.write(open(self.path, 'w'))

if __name__ == '__main__':
    iniFileOperation = IniFileOperations('../initial.ini')
