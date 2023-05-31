# coding=utf-8
import collections
import json
import math
import os
import random
import re
import time
import chardet

# the all result save in the end
class Static:
    num = 0
    all = 0
    Random = ''      # 设置随机数
    results1 = []
    results2 = []


# 匹配规则(关键字、高危函数、恶意字符、加密特点)
rulelist = [
    '(\$_(GET|POST|REQUEST)\[.{0,15}\]\s{0,10}\(\s{0,10}\$_(GET|POST|REQUEST)\[.{0,15}\]\))',
    '((eval|assert)(\s|\n)*\((\s|\n)*\$_(POST|GET|REQUEST)\[.{0,15}\]\))',
    '(eval(\s|\n)*\(base64_decode(\s|\n)*\((.|\n){1,200})',
    '(function\_exists\s*\(\s*[\'|\"](popen|exec|proc\_open|passthru)+[\'|\"]\s*\))',
    '((exec|shell\_exec|passthru)+\s*\(\s*\$\_(\w+)\[(.*)\]\s*\))',
    '(\$(\w+)\s*\(\s.chr\(\d+\)\))',
    '(\$(\w+)\s*\$\{(.*)\})',
    '(\$(\w+)\s*\(\s*\$\_(GET|POST|REQUEST|COOKIE|SERVER)+\[(.*)\]\s*\))',
    '(\$\_(GET|POST|REQUEST|COOKIE|SERVER)+\[(.*)\]\(\s*\$(.*)\))',
    '(\$\_\=(.*)\$\_)',
    '(\$(.*)\s*\((.*)\/e(.*)\,\s*\$\_(.*)\,(.*)\))',
    '(new com\s*\(\s*[\'|\"]shell(.*)[\'|\"]\s*\))',
    '(echo\s*curl\_exec\s*\(\s*\$(\w+)\s*\))',
    '((fopen|fwrite|fputs|file\_put\_contents)+\s*\((.*)\$\_(GET|POST|REQUEST|COOKIE|SERVER)+\[(.*)\](.*)\))',
    '(\(\s*\$\_FILES\[(.*)\]\[(.*)\]\s*\,\s*\$\_(GET|POST|REQUEST|FILES)+\[(.*)\]\[(.*)\]\s*\))',
    '(\$\_(\w+)(.*)(eval|assert|include|require|include\_once|require\_once)+\s*\(\s*\$(\w+)\s*\))',
    '((include|require|include\_once|require\_once)+\s*\(\s*[\'|\"](\w+)\.(jpg|gif|ico|bmp|png|txt|zip|rar|htm|css|js)+[\'|\"]\s*\))',
    '(eval\s*\(\s*\(\s*\$\$(\w+))',
    '((eval|assert|include|require|include\_once|require\_once|array\_map|array\_walk)+\s*\(\s*\$\_(GET|POST|REQUEST|COOKIE|SERVER|SESSION)+\[(.*)\]\s*\))',
    '(preg\_replace\s*\((.*)\(base64\_decode\(\$)'

]


def regex(path='/root/testshell', socketio=None):

    Static.num = 0
    Static.all = 0
    Static.results1.clear()
    Static.Random = str(random.uniform(1,999))           # 生成一个随机数
    numberOfFilesTested = 0
    numberOfFiles = 0
    percentInFit = 0

    for root, dirs, files in os.walk(path): # 统计目录下一共有多少文件
        numberOfFiles += len(files)

    for root, dirs, files in os.walk(path):  # 遍历所给目录下的所有文件（包括子目录中的文件）

        for filespath in files:  # 获取文件路径
            try:
                if os.path.getsize(os.path.join(root, filespath)) < 1024000:  # 1MB
                    path = os.path.join(root, filespath)

                    Static.all = Static.all + 1
                    with open(path, 'rb') as f:  # 对文件编码的判断，以对应的编码打开文件，防止乱码
                        encod = chardet.detect(f.read())['encoding']

                    with open(path, 'r', encoding=encod) as file:
                        filestr = file.read()

                    for rule in rulelist:  # 开始特征匹配
                        try:
                            result = re.compile(rule).findall(filestr)
                            if result:
                                Static.num = Static.num + 1
                                Static.results1.append({"filename": os.path.join(root, filespath), "code": str(result[0][0:200]),
                                                       "latestTime": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(
                                                           os.path.getmtime(os.path.join(root, filespath))))}
                                                       )
                                print(os.path.join(root, filespath),  # 对单元格赋值
                                      str(result[0][0:200]),
                                      time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(
                                          os.path.getmtime(
                                              os.path.join(root, filespath))))
                                      )
                                # sqldata.staticscan_1(os.path.join(root, filespath),  # 插数据
                                #                           str(result[0][0:200]),
                                #                           time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(
                                #           os.path.getmtime(
                                #               os.path.join(root, filespath)))), Static.Random)

                                break

                        except:
                            pass
            except:
                pass
            numberOfFilesTested += 1
            if(numberOfFilesTested / numberOfFiles >= percentInFit):
                percentInFit += 0.25
                socketio.emit('regular matching amount of progress',numberOfFilesTested / numberOfFiles * 100) # 向前端发送进度

    print("总量\n", Static.all)
    print("数量\n", Static.num)
    return Static


def Entropy(path='/root/testshell', socketio=None):
    # Static.num = 0
    # Static.all = 0
    Static.results2.clear()
    Static.Random = str(random.uniform(1, 999))  # 生成一个随机数
    numberOfFiles = 0
    numberOfFilesTested = 0
    percentInFit = 0
    for root, dirs, files in os.walk(path):
        numberOfFiles += len(files)

    for root, dirs, files in os.walk(path):  # 遍历所给目录下的所有文件（包括子目录中的文件）

        for filespath in files:  # 获取文件路径
            try:
                if os.path.getsize(os.path.join(root, filespath)) < 1024000:  # 1MB
                    file_path = os.path.join(root, filespath)

                    # Static.all = Static.all + 1

                    with open(file_path, 'rb') as f:  # 对文件编码的判断，以对应的编码打开文件，防止乱码
                        encod = chardet.detect(f.read())['encoding']

                    with open(file_path, 'r', encoding=encod) as file:
                        filestr = file.read()

                    try:
                        counter_char = collections.Counter(filestr)  # 计算信息熵
                        entropy = 0
                        for c, ctn in counter_char.items():
                            _p = float(ctn) / len(filestr)
                            entropy += -1 * _p * math.log(_p, 2)
                        # 把结果的信息，以字典的形式存入列表
                        Static.results2.append({"filename": str(file_path), "entropy": str(round(entropy, 2)),"latestTime":str(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(
                            os.path.getmtime(os.path.join(root, filespath)))))})
                        print('可疑文件')  # 说明一栏
                        print('文件' + '\t' + file_path)
                        print('熵值%.2f' % (round(entropy, 2)))
                        print('修改时间:' + time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(
                            os.path.getmtime(os.path.join(root, filespath)))))

                        # sqldata.staticscan_2(file_path, round(entropy, 2), time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(
                        #     os.path.getmtime(os.path.join(root, filespath)))), Static.Random)


                    except:
                        pass
            except:
                pass

            numberOfFilesTested += 1
            if(numberOfFilesTested / numberOfFiles >= percentInFit):
                percentInFit += 0.25
                socketio.emit('information entropy amount of progress',numberOfFilesTested / numberOfFiles * 100)
    try:
        Static.results2.sort(key=lambda item: item["entropy"])  # 按熵值由高到低排序
        Static.results2.reverse()
        # for i in range(0,len(Static.results2)):
          #   sqldata.staticscan_2(Static.results2[i]['filename'], Static.results2[i]['value'], Static.results2[i]['time'], Static.Random)
        # print("总量\n", Static.all)
        # print("数量\n", Static.num)
    except:
        pass

    return Static

if __name__ == '__main__':
    # regex()
    Entropy()
