# coding=utf-8
import random

import joblib
import gc
import os
import re
import subprocess
from mysource import sqldata

#说明：
    #代码第 49行加载：text_classify_TF_IDF.pkl，改路径
    #代码第 79行加载：text_classify_model.pkl，改路径
    #代码第 67行输出文件名
    #代码第 91行输出文件opcode
    #代码第 92行输出检测结果

    #做一个选择文件夹的按钮(结果传给dir变量)，做一个启动按钮(调用recursion_load_php_file_opcode()函数)
#

class Smart:
    Random = '0'
    result = []
    normal = 0
    target = 0


def load_php_opcode(full_path):     #获取php opcode 信息

    try:
        cmd = "php -dvld.active=1 -dvld.execute=0 " + full_path
        res = subprocess.getstatusoutput(cmd)
        output =  res[1]
        tokens = re.findall(r'\s(\b[A-Z_]+\b)\s', output)
        t = ' '.join(tokens)
        #print(t)
        return t
    except:
        return " "



def SmartScanStart(dir='/root/testshell', socketio=None, pklPath=''):        # 遍历目录文件,   递归获取 php opcde
    print("智能检测:开始")
    Smart.Random = str(random.uniform(1, 999))

    numberOfFiles = 0
    numberOfFilesTested = 0
    percentInFit = 0
    for root, dirs, files in os.walk(dir):
        numberOfFiles += len(files)

    for root, dirs, files in os.walk(dir):      # 传一个文件夹
        for filename in files:
            if filename.endswith('.php'):
                try:
                    full_path = os.path.join(root, filename)                    # 得到文件名
                    file_content = load_php_opcode(full_path)                   # 得到opcode
                    if file_content != '' and file_content != 'PHP':           # 判断opcode是否合理
                        opcode_content = file_content

                        # 以下是机器学习的部分
                        print('loading TF-IDF')
                        print(pklPath)
                        tv = joblib.load(os.path.join(pklPath,'text_classify_TF_IDF.pkl'))  # 加载模型路径
                        print('OK TF-IDF')

                        tran_text = []

                        def tran(text):  # 处理输入的opcode
                            text_become_list = []
                            text_become_list.append(text)
                            tran_text.append(tv.transform(text_become_list))

                        def fenlei(trantext, acess_token):
                            kind = acess_token.predict(trantext)
                            kind = list(kind)
                            return kind[0]

                        text_s = []


                        print(full_path)                #  文件名

                        text = opcode_content
                        while (text != ''):
                            text_s.append(text)
                            tran(text)
                            break

                        del tv
                        gc.collect()

                        print('load model')
                        acess_token = joblib.load(os.path.join(pklPath,"text_classify_model.pkl"))
                        print('ok model')

                        kind_s = []  # 类别结果
                        if (len(text_s) != 0):
                            for i in tran_text:
                                kind = fenlei(i, acess_token)
                                kind_s.append(kind)

                        if (len(text_s) != 0):
                            for i in range(0, len(text_s)):

                                print(str(text_s[i])[6:200])         # 相应文件的opcode
                                print(str(kind_s[i]))         # 文件检测结果
                                res = '可疑文件' if str(kind_s[i]) == 'black' else '正常文件'      # 文件检测结果
                                sqldata.smartscan(full_path,str(text_s[i])[6:200],res,Smart.Random)
                                Smart.result.append({'filename': full_path, 'opcode': str(text_s[i])[6:200], 'result' : res})

                except:
                    continue
            
            numberOfFilesTested += 1
            if(numberOfFilesTested / numberOfFiles >= percentInFit):
                percentInFit += 0.25
                socketio.emit('intelligent detection amount of progress',numberOfFilesTested / numberOfFiles * 100)
    Smart.target = len(Smart.result)
    Smart.normal = numberOfFiles - Smart.target
    return Smart



if __name__ == '__main__':
    SmartScanStart()