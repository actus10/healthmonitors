#!/usr/bin/python
'''

 \# Exit with 0 means UP
 \# Exit with -1 means DOWN

This health monitor is an example of how to check a server and then report
to a UDP service the status of the Node.

ACOS configuration example:
health monitor foo
    method external program foo port 80


'''
import json
import logging
import os
import httplib
import socket
import sys

logging.basicConfig(filename='/a10data/var/log/messages',
                    level=6, format='%(asctime)s %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p')


host = os.environ['HM_SRV_IPADDR']
port = int(os.environ['HM_SRV_PORT'])

DOWN = -1
UP = 0
STATUS = DOWN


https = False
method = 'get'
path = "/foo/bar"
headers = {"host": "www.foo.com"}
data = None
response_text = "hello world"
status = 200

'''
Options: Both, text or status
'''
state_rule = 'both'
udp_notify = True
udp_dst_ip = "1.2.3.4"
udp_dst_port = 5000



def udp_send(message):
    if len(udp_dst_ip) < 7 and udp_dst_ip is not None:
        logging.log("IP ADDRESS to SHORT.")
    if udp_dst_port is None:
        logging.log("UDP Notify Port Not Configured.")
    if not udp_dst_port > 0 and not udp_dst_port < 65535:
        logging.log("UDP Notify Port not in Range.")

    try:
       sock = socket.socket(socket.AF_INET,  # Internet
                         socket.SOCK_DGRAM)  # UDP
    except BaseException as e:
        logging.log(e.message)
    try:
       sock.sendto(message, (udp_dst_ip, udp_dst_port))
    except:
        logging.log("External hm script failed to configure" + __name__)


def HMCheck():
    
    if https is None and str(port) != str(80):
        url = "http://" + host + ":", + str(port) + path
    elif https is not None and str(port) == str(443):
        url = "https://" + host + path
    elif https is not None and port is not 443:
        url = "https://" + host + ":", + str(port) + path
    else:
        url = "http://" + host
    
    try:
        conn = httplib.HTTPConnection(host, port=port)
        conn.request(method, url, body=data, headers=headers)
        resp = conn.getresponse()
        HTTP_STATUS = resp.status 
        resp_text = resp.read()
    except:
        STATUS = DOWN

    if state_rule is None:
        if len(response_text) is None and status is None:
            if len(resp_text) > 0 and HTTP_STATUS is not None:
                STATUS = UP
            else:
                STATUS = DOWN
        elif len(response_text) is not None and status is None:
            if response_text in resp_text:
                STATUS = UP
            else:
                STATUS = DOWN
        elif len(response_text) is None and status is not None:
            if HTTP_STATUS == 200:
                STATUS = UP
            else:
                STATUS = DOWN
    else:
        if state_rule.lower() == 'both':
            if status == HTTP_STATUS:
                if response_text in resp_text:
                    STATUS = UP
                else:
                    STATUS = DOWN
            else:
                STATUS = DOWN
        elif state_rule is 'status':
            if HTTP_STATUS == status:
                STATUS = UP
            else:
                STATUS = DOWN
        elif state_rule == 'text':
            if len(response_text) == 0:
                if len(resp_text) > 0 and HTTP_STATUS is not None:
                    STATUS = UP
                else:
                    STATUS = DOWN
            elif response_text in resp_text:
                STATUS = UP
            else:
                STATUS = DOWN
        else:
            STATUS = DOWN

    message = json.dumps({
        "host": host,
        "port": port,
        "method": method,
        "https": https,
        "url": path,
        "status": STATUS,
        "response": resp_text[0,128],
        "http_status_code":HTTP_STATUS
    })
    if udp_notify is True:
        udp_notify(message)
    if STATUS == UP:
        sys.exit(0)
    else:
        sys.exit(-1)


if __name__ == "__main__ ":
    try:
        HMCheck()

    except BaseException as e:
        logging.log(e.message)
