#!/usr/bin/python
#coding:utf-8
from pwn import *
import sys
import random
import string
from multiprocessing import Pool

elf_path="/home/ctf/server"
context.log_level = "CRITICAL"
is_local=False

get_payload = "GET /%s HTTP/1.1 \r\n" \
               "Host: afang\r\n" \
               "Accept-Encoding: gzip\r\n" \
               "Accept: text/html\r\n" \
               "Connection: close"

post_payload = "POST /%s HTTP/1.1 \r\n" \
               "Host: afang\r\n" \
               "Accept-Encoding: gzip\r\n" \
               "Accept: text/html\r\n" \
               "Connection: close\r\n\r\n%s"

def checkindex(host,port):
    
    p = remote(host,port,timeout=20)
    payload = get_payload % "index.html"
    p.send(payload)
    buf = p.recvuntil('<script src="js/custom.js"></script>')
    assert '<script src="js/custom.js"></script>' in buf
    p.close()

def checkmysql(host,port):

    p = remote(host,port,timeout=20)
    payload = post_payload % ("product.html" ,"a=1&b=2&id=3")
    p.send(payload)
    buf = p.recvuntil("LG Gram")
    assert 'LG Gram' in buf
    p.close()
    p = remote(host,port,timeout=20)
    payload = post_payload % ("cart.html", "a=1&cargo=123")
    p.send(payload)
    buf = p.recvuntil("202cb962ac59075b964b07152d234b70")
    assert '202cb962ac59075b964b07152d234b70' in buf
    p.close()

def checklogin(host,port):

    p = remote(host,port,timeout=20) 
    check_str = "login.html?a=1&b=2&username=admin&password=adminaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaanimda&menu=request&para=" + "cart.html".encode("hex")
    payload = get_payload % check_str
    p.send(payload)
    buf = p.recvuntil("HTTP/1.1")
    assert 'HTTP/1.1' in buf
    p.recvuntil("HTTP/1.1")
    p.close()

def check(host,port):
    #print "start"
    io=None
    try:
        # if is_local:
        #     #io = process(elf_path)
        #     io = remote('192.168.11.132',2333)
        #     #print io.pid
        #     #raw_input()
        # else:
        #     io = remote(host, port, timeout=20)
        checkindex(host,port)
        checkmysql(host,port)
        checklogin(host,port)
        # check_student(io)
        # io.sendline('4')
        # io.recvuntil('choose your id:\n')
        return 1
    except KeyboardInterrupt:
        raise
    except Exception as e:
        #print e
        if io:
            io.close()
        return 0

def check_all(isdebug=False):
    if isdebug:
        print(check('127.0.0.1',2323))
    else:
        if len(sys.argv) != 3:
            print 'error'
            print 'python do_check_library.py port ip1,ip2'
            return
        port = int(sys.argv[1])
        iplist = sys.argv[2].split(',')
        pool = Pool(processes=21)
        result_list = []
        for ip in iplist:
            result_list.append(pool.apply_async(check, (ip,port,)))
            time.sleep(0.1)
        pool.close()
        pool.join()
        result_list = map(lambda x:x.get(), result_list)
        print ".".join(str(res) for res in result_list)


if __name__ == '__main__':
    isdebug=False
    if is_local:
        isdebug=True
    check_all(isdebug)
