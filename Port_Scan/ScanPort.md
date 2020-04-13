# 端口扫描  
---
## 原理  
    这次扫描采用的是TCP Connect扫描。 
	正常情况下，要想成功建立一次TCP连接，需要进行三次握手。 
	若想要判断一个端口是否是开放的状态，可以尝试与目标设备的端口进行tcp连接。 
	若是成功建立连接，则表示目标端口开放。 
	若是建立连接失败，则表示目标端口未开放。 
## 代码  
	import getopt 
	import threading 
	import sys 
	from time import time,ctime 
	from socket import * 
 
	max_thread = 10  #设置同时在运行的线程数最多为10个 
 
	#打印正确的输入格式 
	def useage(): 
	    print() 
	    print("Useage:") 
	    print("    python myscan.py -s <开始扫描端口号> -e <结束扫描端口号> -h <目的ip>") 
	    print() 
    
	class scan(threading.Thread): 
	    def __init__(self, host, port): 
	        threading.Thread.__init__(self) #实例化一个线程对象 
	        self.host = host 
	        self.port = port 
	        try: 
	            self.sk = socket(AF_INET, SOCK_STREAM) #建立套接字 
	        except: 
	            print("socket error") 
	            sys.exit(1) 
	        self.sk.settimeout(0.1) #设置超时的时间限制为0.1秒 
	
	    def run(self): #定义线程的具体操作 
	        try: 
	            self.sk.connect((self.host, self.port)) #尝试同目标端口建立正常的TCP连接 
	        except:  #建立连接失败 说明该端口未开放则无操作 
	            pass 
	        else:  #建立连接成功 说明该端口开放则输出端口开放的提示 
	            print("%s\t%d OPEN %s" % (ctime(time()),self.port, getservbyport(self.port)))
	            self.sk.close() #关闭套接字 
	
	class Scanner: 
	    def __init__(self): 
	        try: 
	            #列表sys.argv[]存储输入的参数
	            opts, argvs = getopt.getopt(sys.argv[1:],"s:e:h:")
	            #opts 为分析出的格式信息,是带-选项的参数
	            #argvs 为不属于格式信息的剩余的命令行参数
	        except getopt.GetoptError: #输入错误参数的处理
	            useage()
	            sys.exit(1)
	                
	        for opt, argv in opts:
	            if opt == '-s': #-s后面的参数为开始扫描的端口号
	                try:
	                    self.start = int(argv)
	                except ValueError: #若参数错误则打印错误信息和格式提示信息
	                    print("Invaild option: -s"+argv)
	                    useage()
	                    sys.exit(1)
	                        
	            elif opt == "-e": #-e后面的参数为结束扫描的端口号
	                try:
	                    self.end = int(argv)
	                except ValueError:
	                    print("Invaild option: -e "+argv)
	                    useage()
	                    sys.exit(1)                        
	            elif opt == "-h": #-h后面的参数为扫描目标的ip地址
	                self.host = argv
	        
	        if self.start > self.end: #检查端口号范围是否合理
	            print("Port range error")
	            useage()
	            sys.exit(1)
	
	        try:
	            gethostbyname(self.host)
	            #返回的是 主机名（host） 的IPv4 的地址格式
	            #如果传入的参数是IPv4 的地址格式，则返回值跟参数一样
	            #这个函数不支持IPv6 的域名解析
	        except: #无法解析则输出错误信息
	            print("Hostname '%s' unknown" % self.host)
	                
	        self.do_scan(self.host, self.start, self.end)
	
	    def do_scan(self, host, start, end):
	        self.port = start
	        while self.port <= end:
	            #保证正在运行的进程数量不超过设定的最大值
	            while threading.activeCount() < max_thread: 
	                scan(host, self.port).start() #开始执行该线程
	                self.port += 1
	
	Scanner()
## 说明 
- 类Scanner是用来处理输入，从中识别出扫描端口所需要的参数（开始扫描的端口号、结束扫描的端口号、目标设备的IP地址）；并且利用循环控制调用线程实现单个端口的扫描。 
- 类scan用于实例化线程线程实现单个端口的扫描，这样可以提高扫描效率。对于每一个端口，若是成功建立连接，则表示目标端口开放，输出该端口号以及其对应的服务。若是建立连接失败，则表示目标端口未开放，不进行任何操作。 
## 运行结果（命令行） 
	E:\网络攻防>python myscan.py -s 1 -e 1024 -h 14.215.177.39
        80  is OPEN     The port's service is http
        443  is OPEN    The port's service is https

	E:\网络攻防>python myscan.py -s 1 -e 1024 -h baidu.com
	        80  is OPEN     The port's service is http
	        443  is OPEN    The port's service is https
	
	E:\网络攻防>python myscan.py -s 1 -e 1024 -h 192.168.0.100
	
	E:\网络攻防> 
## 运行结果分析   
- 第一次运行使用了百度的一个IP地址测试，结果显示端口号为80和443的端口状态为开放。 
- 80端口是为HTTP（HyperText Transport Protocol)即超文本传输协议开放的，此为上网冲浪使用次数最多的协议，主要用于WWW（World Wide Web）即万维网传输信息的协议。 
- 443端口即网页浏览端口，主要是用于HTTPS服务，是提供加密和通过安全端口传输的另一种HTTP。在一些对安全性要求较高的网站，比如银行、证券、购物等，都采用HTTPS服务，这样在这些网站上的交换信息，其他人抓包获取到的是加密数据，保证了交易的安全性。网页的地址以https://开始，而不是常见的http://。 
- 第二次运行使用了百度的域名进行测试，其结果与第一次测试结果相同。 
- 第三次使用了自己手机的IP地址，结果显示没有端口开放。 
- 因为系统所使用的端口范围是1~1024，所以三次测试的端口范围都是1~1024。 