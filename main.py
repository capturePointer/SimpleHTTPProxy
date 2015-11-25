#!/usr/bin/env python3.5

# 基于devunt/WARP轻度修改，感谢原作者
# 注释为我根据代码分析后自行添加，如果有错误还请指正
# 附：原作者协议
"""
Copyright (c) 2013 devunt
Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:
The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
"""

from socket import TCP_NODELAY  # socket
from traceback import print_exc  # 错误跟踪
import re   # 正则
import asyncio  # 异步
import logging 	# 日志
import functools  # 函数式工具

REGEX_HOST = re.compile(r'(.+?):([0-9]{1,5})')  # 获取目的地
REGEX_CONTENT_LENGTH = re.compile(
    r'\r\nContent-Length: ([0-9]+)\r\n',
     re.IGNORECASE)  # 获取载荷长度
REGEX_CONNECTION = re.compile(
    r'\r\nConnection: (.+)\r\n',
     re.IGNORECASE)  # 获取链接种类

clients = {}    # 已连接的客户端

# 设置logging参数
logging.basicConfig(
    level=logging.INFO,
     format='[%(asctime)s] {%(levelname)s} %(message)s')
logging.getLogger('asyncio').setLevel(logging.CRITICAL)
logger = logging.getLogger('httpproxy')

# 接受客户端


def accept_client(client_reader, client_writer, *, loop=None):
    ident = hex(id(client_reader))[-6:]  # ident为生成的客户端连接标识
    # 设置task = 异步包装器
    task = asyncio.async(
    process_proxy(
        client_reader,
        client_writer,
        loop=loop),
         loop=loop)
    # 存储客户端任务
    clients[task] = (client_reader, client_writer)

    # 可能是异步回调，处理链接完成，此处有问题不能彻底完成回调
    def client_done(task):
        del clients[task]   # 移除client
        client_writer.close()   # 关闭写入器
        logger.debug('[%s] Connection closed' % ident)  # 记录日志

    # 记录日志
    logger.debug('[%s] Connection started' % ident)
    task.add_done_callback(client_done)

async def process_proxy(client_reader, client_writer, *, loop=None):
    ident = str(hex(id(client_reader)))[-6:]    # 协程标识
    header = ''  # 数据头
    payload = b''  # 二进制数据
    try:
        RECV_MAX_RETRY = 3  # 最多重试次数
        recvRetry = 0  # 当前重试次数
        while True:
            line = await client_reader.readline()  # 异步读一行
            if not line:    # 如果没读出数据
                if len(header) == 0 and recvRetry < RECV_MAX_RETRY:  # 头没读完并且还能重试
                    # handle the case when the client make connection but
                    # sending data is delayed for some reasons
                    recvRetry += 1  # 次数+1
                    await asyncio.sleep(0.2, loop=loop)    # 异步等待
                    continue
                else:
                    break
            if line == b'\r\n':  # 头读取完毕
                break
            if line != b'':  # 头不为空继续读
                header += line.decode()
        m = REGEX_CONTENT_LENGTH.search(header)  # 正则查找数据长度
        if m:   # 有数据时触发
            cl = int(m.group(1))  # 读取数据长度分离出数字
            while (len(payload) < cl):  # 循环读数据直到读完
                payload += await client_reader.read(1024)
    except: # 异常处理打印堆栈
        print_exc()
    if len(header) == 0:    # 头部为空的情况下提示空请求然后忽略
        logger.debug('[%s] !!! Task reject (empty request)' % ident)
        return
    req = header.split('\r\n')[:-1]		# 头部分离后去除最后一片
    if len(req) < 4:    # 似乎是不能识别的请求（判断http头的长度为4要不就抛弃，不确定）
        logger.debug('[%s] !!! Task reject (invalid request)' % ident)
        return
    # 空格分离解析头数据
    head = req[0].split(' ')
    if head[0] == 'CONNECT': # https隧道
        try:
            logger.info('BYPASSING <%s %s> (SSL connection)' % (head[0], head[1]))
            m = REGEX_HOST.search(head[1])  # 正则提取HOST
            host = m.group(1)	# 分离HOST
            port = int(m.group(2))	# 分离端口号
            # 开启异步读写
            req_reader, req_writer = await asyncio.open_connection(host, port, ssl=False, loop=loop)
            # 通知客户端链接建立
            client_writer.write(b'HTTP/1.1 200 Connection established\r\n\r\n')
            # 单纯的流量转发协程
            async def relay_stream(reader, writer):
                try:
                    while True:
                        line = await reader.read(1024)
                        if len(line) == 0:
                            break
                        writer.write(line)
                except:
                    print_exc()
            # 两个任务互相触发
            tasks = [
                asyncio.ensure_future(relay_stream(client_reader, req_writer), loop=loop),
                asyncio.ensure_future(relay_stream(req_reader, client_writer), loop=loop),
            ]
            await asyncio.wait(tasks, loop=loop)
        except TimeoutError:
            logger.info('TIMEOUT <%s %s> (SSL connection)' % (host, port))
        except IOError:
            logger.info('IOERROR <%s %s> (SSL connection)' % (host, port))
        except:
            print_exc()
        finally:
            return  # 提前跳出
        # https处理完毕
    # 其他非https普通请求
    phost = False   # 接收方HOST
    sreq = []   # 新的请求header
    sreqHeaderEndIndex = 0  # header结束位置
    for line in req[1:]:    # 逐行从header里拆信息，跳过第一行
        headerNameAndValue = line.split(': ', 1)    # 拆分头key和value
        if len(headerNameAndValue) == 2:
            headerName, headerValue = headerNameAndValue    # 有key有value
        else:
            headerName, headerValue = headerNameAndValue[0], None   # 有key没value

        if headerName.lower() == "host":
            phost = headerValue # 拆分获取host
        elif headerName.lower() == "connection":
            if headerValue.lower() in ('keep-alive', 'persist'):    # 如果是http-keepalive则改为关闭连接
                # 并不支持keep-alive模式
                sreq.append("Connection: close")    
            else:
                sreq.append(line)   # 其他connection头原样写回
        elif headerName.lower() != 'proxy-connection':  # 剔除proxy-connetcion选项
            sreq.append(line)
            if len(line) == 0 and sreqHeaderEndIndex == 0:# 有空行而且没结束，就写入结束位置
                sreqHeaderEndIndex = len(sreq) - 1
    if sreqHeaderEndIndex == 0:# 没空行情况下直接写结束位置
        sreqHeaderEndIndex = len(sreq)

    m = REGEX_CONNECTION.search(header) # 正则查找connection
    if not m:	# 没找到就在最后加一个close的链接需求
        sreq.insert(sreqHeaderEndIndex, "Connection: close")

    if not phost:	# 没写host的认为发给自己
        phost = '127.0.0.1'
    path = head[1][len(phost)+7:]   # 获取path，伪装成客户端

    logger.info('PROXYING <%s %s>' % (head[0], head[1]))

    # 新的请求头
    sreq.insert(0,' '.join([head[0], path, head[2]])) 
    # 写入HOST
    sreq.insert(1,'Host: %s' % phost)
    # 正则检测是否使用特定端口
    m = REGEX_HOST.search(phost)
    if m:
        host = m.group(1)
        port = int(m.group(2))
    else:
        host = phost
        port = 80
        # host为单纯的主机地址，port为端口
    try:
        # 创建一个异步请求,此处为标准转发
        req_reader, req_writer = await asyncio.open_connection(host, port, flags=TCP_NODELAY, loop=loop)
        req_writer.writelines(list(map(lambda x: (x + '\r\n').encode(), sreq)))#写新请求header
        req_writer.write(b'\r\n')
        await req_writer.drain()
        # 写入载荷
        if payload != b'':
            req_writer.write(payload)
            req_writer.write(b'\r\n')
        await req_writer.drain()

        try:
            # 读取响应并发还给客户端
            while True:
                buf = await req_reader.read(1024)
                if len(buf) == 0:
                    break
                client_writer.write(buf)
        except:
            print_exc()
    except TimeoutError:
        logger.info('TIMEOUT <%s %s>' % (host, port))
    except IOError:
        logger.info('IOERROR <%s %s>' % (host, port))    
    except:
        print_exc()

    client_writer.close()

# 异步协程启动代理
async def start_proxy_server(host, port, *, loop = None):
    try:
        # 绑定loop参数到accept函数上
        accept = functools.partial(accept_client, loop=loop)
        # 异步启动asyncio的socket服务器
        server = await asyncio.start_server(accept, host=host, port=port, loop=loop) 
    except OSError as ex:
        logger.critical('!!! Failed to bind server at [%s:%d]: %s' % (host, port, ex.args[1]))
        raise
    else:
        logger.info('Server bound at [%s:%d].' % (host, port))
        return server

# 直接运行该文件
if __name__ == '__main__':
    loop = asyncio.get_event_loop() # 获取asyncio的主循环
    try:
        # 循环运行server
        loop.run_until_complete(start_proxy_server('127.0.0.1', 8806))
        loop.run_forever()
    except OSError:
        pass
    except KeyboardInterrupt:
        print('bye')
    finally:
        loop.close()    # 关闭循环
