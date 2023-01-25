# coding=utf-8
import time
import threading
from mysource import sqldata

# 定义你要周期运行的函数
class update:
    mypath = '/root/test'


while True:
        sqldata.updatetree(mypath=update.mypath)
        time.sleep(5)
# if __name__ == '__main__':
#     UpdateStart()