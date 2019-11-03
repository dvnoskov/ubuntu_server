import requests


#url = "http://kiksecurity.ml/nic/update"

#url = "http://members.dyndns.org/nic/update"
#url = 'http://checkip.dyndns.com'


data = {
            "hostname" : 'test.dnsalias.com',
            "myip"     : '90.99.98.166',
             "wildcard": 'NOCHG',
             "mx"      : 'NOCHG',
             "backmx"  : 'NO'
        }

data2 = {
            "hostname" : 'kik04.kiksecurity.ml',
            "myip"     : '192.168.1.117',
             "wildcard": 'NOCHG',
             "mx"      : 'NOCHG',
             "backmx"  : 'NO'
        }

data1 = {
            "hostname" : 'kik01.dynhost.ml',
            "myip"     : '192.168.1.140',
             "wildcard": 'NOCHG',
             "mx"      : 'NOCHG',
             "backmx"  : 'NO'
        }
#url="http://dimon49.ml/nic/status"
#url="http://192.168.1.180/nic/status"  #
url="http://dimon49.ml/nic/test"
#url="http://192.168.1.180/nic/test"  #
r = requests.get(url)
#r = requests.get(url,auth=("KiK","12345KiK"))
#url="http://192.168.1.180/nic/update"  #
#url="http://193.254.196.206/nic/update"  #
#url="http://dimon49.ml/nic/update"  #
#r = requests.get(url,data=data,auth=("test","test"))
#r = requests.get(url,params=data1,auth=("KiK","12345KiK"))
#r = requests.get(url,params=data1,auth=("admin","12345KiK"))


print("status_code ",r.status_code )
print(r.text)
