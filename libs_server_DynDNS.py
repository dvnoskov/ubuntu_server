import binascii
from http.server import BaseHTTPRequestHandler
import base64
import urllib.parse
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from cr_dyndns_db import DynDNS, User
import threading
from config import route_DB
import re, json


def UPDATE_DYNDNS():
    engine = create_engine(route_DB)
    Session = sessionmaker(bind=engine)
    session = Session()
    query = session.query(DynDNS)

    update = {}
    while True:

        work = query.filter(DynDNS.STATUS == 'USER').count()
        if work >= 1:
            menu = session.query(DynDNS).filter(DynDNS.STATUS == 'USER').first()
            work_no = query.filter(DynDNS.dyndns_id == menu.dyndns_id)
            a1 = (int(menu.RDATA[0:2], 16))
            a2 = (int(menu.RDATA[2:4], 16))
            a3 = (int(menu.RDATA[4:6], 16))
            a4 = (int(menu.RDATA[6:8], 16))
            ip = str(a1) + "." + str(a2) + "." + str(a3) + "." + str(a4)
            update[(hex2str(menu.NAME).decode('utf-8'))] = ip  #
            work_no.update({DynDNS.STATUS: ("SYN")})
            session.commit()

        else:
            break

    sys = query.filter(DynDNS.STATUS == 'SYN')
    sys.update({DynDNS.STATUS: ("USER")})
    session.commit()
    session.close()

    return update


def str2hex(s):
    return binascii.hexlify(bytes(str.encode(s)))


def hex2str(h):
    return binascii.unhexlify(h)


class MyTCPHandler(BaseHTTPRequestHandler):
    def stop_DB(self):
        self.session.commit()
        self.session.close()
     #   self._lock.release()

    def do_DB(self):
        engine = create_engine(route_DB)
        self.Session = sessionmaker(bind=engine)
        self.session = self.Session()
        self.Base = declarative_base()
     #   self._lock = threading.Lock()
     #   self._lock.acquire()
        return self.session, self.Base, self.Session   # self._lock.acquire

    def do_HEAD(self):
        self.send_header('Content-type', 'text/html')
        self.send_header('X-User-Status', 'vip')
        self.end_headers()

    def do_AUTHHEAD(self):
        self.send_response(401)
        text = "badauth"
        self.send_header('WWW-Authenticate', 'Basic realm="DynDNS API Access"')
        self.send_header('X-UpdateCode', 'A')
        self.send_header('Content-type', 'text/html')
        self.send_header('Content-Length', len(text))
        self.end_headers()
        self.wfile.write(text.encode("utf-8"))

    def do_POST(self):
        self.send_response(200)
        text = "badagent"
        self.send_header("Content-type", "text/html")
        self.send_header('X-UpdateCode', 'A')
        self.send_header('Content-Length', len(text))
        self.do_HEAD()
        self.wfile.write(text.encode("utf-8"))

    def do_GET(self):
      #  print(self.path)
      #  print(self.headers)
        # if  self.headers["Host"] == "dimon49.ml" :
        if self.headers["Host"] == "dimon49.ml" or self.headers["Host"] == "members.dyndns.org" \
                or self.headers["Host"] == "193.254.196.206" or self.headers["Host"] == "192.168.1.180":
            if self.path[0:11] == "/nic/update":
                if self.headers['Authorization'] == None:
                    self.do_AUTHHEAD()
                else:
                    if self.headers.get('Authorization')[0:6] == 'Basic ':
                        self.do_Authorization()
                    else:
                        self.do_AUTHHEAD()


            elif self.path == "/nic/test":
                self.send_response(200)
                text = "work"
                self.send_header('Content-Length', len(text))
                self.send_header('Pragma', 'no-cache')
                self.send_header('Cache-Control', 'no-cache')
                self.do_HEAD()
                self.wfile.write(text.encode("utf-8"))

            elif self.path == "/nic/status":
                self.send_response(200)
                text = json.dumps(UPDATE_DYNDNS())
                self.send_header('Content-Length', len(text))
                self.send_header('Pragma', 'no-cache')
                self.send_header('Cache-Control', 'no-cache')
                self.do_HEAD()
                self.wfile.write(text.encode("utf-8"))
            else:
                pass

        else:
            self.send_response(404)  # no route
            text = "404"
            self.send_header('X-UpdateCode', 'X')
            self.send_header('Content-Length', len(text))
            self.do_HEAD()
            self.wfile.write(text.encode("utf-8"))


    def do_Authorization(self):
        aut_in = (base64.b64decode((self.headers["Authorization"][6:])).decode('utf-8'))
        autoriz = aut_in.split(":")
        self.user = autoriz[0]
        login = autoriz[1]
        self.do_DB()
        query = self.session.query(User)
        filt0 = query.filter(User.username == self.user or User.password == login).first()
        if filt0 is None:
            self.stop_DB()
            self.do_AUTHHEAD()
        else:
            filt1 = query.filter(User.password == login or User.username == self.user).first()
            if filt1 is None:
                self.stop_DB()
                self.do_AUTHHEAD()
            else:
                self.stop_DB()
                self.do_Requst_get()


    def do_Requst_get(self):
        if self.user != "admin":
            parse = dict(urllib.parse.parse_qsl(qs=self.requestline, keep_blank_values=True))
            for k in parse.keys():
                if ("".join(re.compile(r'myip').findall(k))) == "myip":
                    myip_in_parse = parse.get(k)
                    if myip_in_parse == "":
                        myip_in = self.client_address[0]
                    else:
                        myip_in = myip_in_parse.split(" ")[0]

                elif ("".join(re.compile(r'hostname').findall(k))) == "hostname":
                    homename_in = parse.get(k)
                    homnam_in = homename_in.split(" ")[0]

                else:
                    pass


            ip = myip_in.split(".")
            s = [int(ip[0]), int(ip[1]), int(ip[2]), int(ip[3])]
            rdata_in = str(binascii.hexlify(bytes(bytearray(s))))[2:10]
            homenam_in = (binascii.hexlify(bytes(str.encode(homnam_in)))).decode('utf-8')
            self.do_DB()
            query = self.session.query(DynDNS)
            filt2 = query.filter(
                DynDNS.NAME == homenam_in or DynDNS.USER == self.user and DynDNS.RDATA == rdata_in).first()
            if filt2 is None:
                self.stop_DB()
                self.send_response(200)
                text = 'dnserr'
                self.send_header('X-UpdateCode', 'A')
                self.send_header('Content-Length', len(text))
                self.do_HEAD()
                self.wfile.write(text.encode("utf-8"))
            else:
                filt3 = query.filter(
                    DynDNS.USER == self.user or DynDNS.NAME == homenam_in and DynDNS.RDATA == rdata_in).first()
                if filt3 is None:
                    self.stop_DB()
                    self.send_response(200)
                    text = 'nohost'
                    self.send_header('X-UpdateCode', 'A')
                    self.send_header('Content-Length', len(text))
                    self.do_HEAD()
                    self.wfile.write(text.encode("utf-8"))
                else:
                    filt4 = query.filter(
                        DynDNS.USER == self.user or DynDNS.RDATA == rdata_in and DynDNS.NAME == homenam_in).first()
                    if filt4 is None:
                        self._lock = threading.Lock()
                        self._lock.acquire()
                        filt5 = query.filter(DynDNS.USER == self.user, DynDNS.NAME == homenam_in)
                        filt5.update({DynDNS.RDATA: rdata_in})
                        self._lock.release()
                        self.stop_DB()
                        self.send_response(200)
                        text = "good   " + str(myip_in)
                        self.send_header('X-UpdateCode', 'A')
                        self.send_header('Content-Length', len(text))
                        self.do_HEAD()
                        self.wfile.write(text.encode("utf-8"))
                    else:
                        self.stop_DB()
                        self.send_response(200)
                        text = "nochg"
                        self.send_header('X-UpdateCode', 'A')
                        self.send_header('Content-Length', len(text))
                        self.do_HEAD()
                        self.wfile.write(bytes(text.encode("utf-8")))  # 2 povtora

        else:
            self.do_AUTHHEAD()

