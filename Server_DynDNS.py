import socket,time
import selectors
import libserver_dyn_dns
import logging.handlers
from config import port_DYN_DNS,host_DNS



sel = selectors.DefaultSelector()


def accept_wrapper(sock):
    conn, addr = sock.accept()  # Should be ready to read
    print("accepted connection from", addr)
    conn.setblocking(False)
    message = libserver_dyn_dns.Message(sel, conn, addr)
    sel.register(conn, selectors.EVENT_READ, data=message)


lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
lsock.bind((host_DNS, port_DYN_DNS))
lsock.listen()
print("listening on", (host_DNS, port_DYN_DNS))
lsock.setblocking(False)
sel.register(lsock, selectors.EVENT_READ, data=None)

try:
    while True:
        loger = logging.getLogger()
        loger.setLevel(logging.DEBUG)
        h = logging.handlers.RotatingFileHandler("listen_dyn_dns_log.out", 300, 10)
        loger.addHandler(h)

        events = sel.select(timeout=None)
        for key, mask in events:
            if key.data is None:
                accept_wrapper(key.fileobj)
            else:
                message = key.data
                try:
                    message.process_events(mask)
                except Exception:
                    loger.debug("incoming message :" + str(message) + time.ctime())
                    loger.debug(logging.exception(IndexError))
                    message.close()

finally:
    sel.close()