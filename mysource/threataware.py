# coding=utf-8
import smtplib
import socket
from email.mime.text import MIMEText
# from mysource import sqldata

# mail_content = "您的重要文件被修改"          # 设置邮件的内容

class Mail:
    setmail = False                       # 默认不开邮箱提醒功能
    sendmail = ''                    # 存放接收者的邮箱
    usr = ''


def SetMail(data):              # 设置发送邮件的开关
    Mail.usr = data.split(',')[0]
    Mail.sendmail = data.split(',')[1]
    Mail.setmail = True
    print(Mail.setmail)

    print('用户 %s ，邮箱 %s'%(Mail.usr,Mail.sendmail))
    sqldata.threataware(Mail.usr,Mail.sendmail)

def Smtp(mail_content):           # 发送邮件内容
    if Mail.setmail:
        print('成功发送邮件')
        hostname = socket.gethostname()  # 获取服务器名称
        try:
            content = MIMEText(mail_content, 'plain', 'utf-8')  # 第一个参数：邮件的内容
            # 第二个参数：邮件内容的格式，普通的文本，可以使用:plain,如果想使内容美观，可以使用:html；
            #  第三个参数：设置内容的编码，这里设置为:utf-8

            reveivers = Mail.sendmail              # 接收邮件的邮箱
            content['To'] = reveivers  # 设置邮件的接收者，多个接收者之间用逗号隔开
            content['From'] = str("My_Server：" + hostname)  # 邮件的发送者,最好写成str("这里填发送者")，不然可能会出现乱码
            content['Subject'] = '服务器威胁提示'  # 邮件的标题

            smtp_server = smtplib.SMTP_SSL("smtp.qq.com", 465)

            smtp_server.login("...@qq.com", "...")  # 第一个参数：发送者的邮箱账号 第二个参数：对应邮箱账号的密码

            smtp_server.sendmail("...@qq.com", Mail.sendmail,
                                content.as_string())  # 第一个参数：发送者的邮箱账号；第二个参数是个列表类型，每个元素为一个接收者；第三个参数：邮件内容

            smtp_server.quit()  # 关闭邮件

        except:
            pass
    else:
        pass
if __name__ == '__main__':
    hostname = socket.gethostname()  # 获取服务器名称
    Mail.setmail = True
    Mail.sendmail = '....@qq.com'
    Smtp('test666')