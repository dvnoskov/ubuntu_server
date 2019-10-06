import binascii
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from cr_dyndns_db import DynDNS
from config import route_DB



def str2hex(s):
    return binascii.hexlify(bytes(str.encode(s)))

def hex2str(h):
    return binascii.unhexlify(h)



def Server_failure(List_db_dns_out):

    List_db_dns_out["RCODE"] = "0101"  # Code answer(0,1,2,3,4,5,6-15) Server failure
    List_db_dns_out["ANCOUNT"] = "0000"  # Code answer 1  one  count db
    Header_1 = List_db_dns_out.get("QR") + List_db_dns_out.get("OPCODE") + List_db_dns_out.get(
        "AA") + List_db_dns_out.get("TC") \
               + List_db_dns_out.get("RD")
    Header_2 = List_db_dns_out.get("RA") + List_db_dns_out.get("Z") + List_db_dns_out.get("RCODE")
    Header_1_1 = Header_1[0:4]
    Header_1_2 = Header_1[4:8]
    Header_2_1 = Header_2[0:4]
    Header_2_2 = Header_2[4:8]
    List_db_dns_out["Header"] = str(int((Header_1_1), 2)) + str(int((Header_1_2), 2)) \
                                + str(int((Header_2_1), 2)) + str(int((Header_2_2), 2))
    List_db_dns_out["NAME"] = "C00C"  # format Message compression 44
    List_db_dns_out["TYPE"] = "0001"
    List_db_dns_out["CLASS"] = "0001"
    List_db_dns_out["TTL"] = "0000"
    List_db_dns_out["RDLENGTH"] = "0004"
    List_db_dns_out["RDATA"] = "00000000"
    message_db_dns_out = List_db_dns_out.get("ID") + List_db_dns_out.get("Header") + List_db_dns_out.get("QDCOUNT") \
                         + List_db_dns_out.get("ANCOUNT") + List_db_dns_out.get("NSCOUNT") \
                         + List_db_dns_out.get("ARCOUNT") + List_db_dns_out.get("QNAME") + List_db_dns_out.get("QTYPE") \
                         + List_db_dns_out.get("QCLASS") + List_db_dns_out.get("NAME") + List_db_dns_out.get("TYPE") \
                         + List_db_dns_out.get("CLASS") + List_db_dns_out.get("TTL") + List_db_dns_out.get("RDLENGTH") \
                         + List_db_dns_out.get("RDATA")
    return message_db_dns_out



def answer_no_name(List_db_dns_out):

    List_db_dns_out["RCODE"] = "0011"  # Code answer(0,1,2,3,4,5,6-15) Server failure
    List_db_dns_out["ANCOUNT"] = "0000"  # Code answer 1  one  count db
    Header_1 = List_db_dns_out.get("QR") + List_db_dns_out.get("OPCODE") + List_db_dns_out.get("AA") + List_db_dns_out.get("TC") \
               + List_db_dns_out.get("RD")
    Header_2 = List_db_dns_out.get("RA") + List_db_dns_out.get("Z") + List_db_dns_out.get("RCODE")
    Header_1_1 = Header_1[0:4]
    Header_1_2 = Header_1[4:8]
    Header_2_1 = Header_2[0:4]
    Header_2_2 = Header_2[4:8]
    List_db_dns_out["Header"] = str(int((Header_1_1), 2)) + str(int((Header_1_2), 2)) \
                                + str(int((Header_2_1), 2)) + str(int((Header_2_2), 2))
    List_db_dns_out["NAME"] = "C00C"  # format Message compression 44
    List_db_dns_out["TYPE"] = "0001"
    List_db_dns_out["CLASS"] = "0001"
    List_db_dns_out["TTL"] = "0000"
    List_db_dns_out["RDLENGTH"] = "0004"
    List_db_dns_out["RDATA"] = "00000000"
    message_db_dns_out = List_db_dns_out.get("ID") + List_db_dns_out.get("Header") + List_db_dns_out.get("QDCOUNT") \
                         + List_db_dns_out.get("ANCOUNT") + List_db_dns_out.get("NSCOUNT") \
                         + List_db_dns_out.get("ARCOUNT") + List_db_dns_out.get("QNAME") + List_db_dns_out.get("QTYPE") \
                         + List_db_dns_out.get("QCLASS") + List_db_dns_out.get("NAME") + List_db_dns_out.get("TYPE") \
                         + List_db_dns_out.get("CLASS") + List_db_dns_out.get("TTL") + List_db_dns_out.get("RDLENGTH") \
                         + List_db_dns_out.get("RDATA")
    return message_db_dns_out

def answer_A_name(requst,List_db_dns_out):

    List_db_dns_out["RCODE"] = "0000"  # Code answer(0,1,2,3,4,5,6-15)
    List_db_dns_out["ANCOUNT"] = requst.ANCOUNT  # Code answer 1  one  count db
    Header_1 = List_db_dns_out.get("QR") + List_db_dns_out.get("OPCODE") + List_db_dns_out.get(
        "AA") + List_db_dns_out.get("TC") + List_db_dns_out.get("RD")
    Header_2 = List_db_dns_out.get("RA") + List_db_dns_out.get("Z") + List_db_dns_out.get("RCODE")
    Header_1_1 = Header_1[0:4]
    Header_1_2 = Header_1[4:8]
    Header_2_1 = Header_2[0:4]
    Header_2_2 = Header_2[4:8]
    List_db_dns_out["Header"] = str(int((Header_1_1), 2)) + str(int((Header_1_2), 2)) \
                                + str(int((Header_2_1), 2)) + str(int((Header_2_2), 2))
    List_db_dns_out["NAME"] = "C00C"  # format Message compression 44
    List_db_dns_out["TYPE"] = requst.TYPE
    List_db_dns_out["CLASS"] = requst.CLASS
    List_db_dns_out["TTL"] = requst.TTL
    List_db_dns_out["RDLENGTH"] = requst.RDLENGTH
    List_db_dns_out["RDATA"] = requst.RDATA
    message_db_dns_out = List_db_dns_out.get("ID") + List_db_dns_out.get("Header") + List_db_dns_out.get("QDCOUNT") \
                         + List_db_dns_out.get("ANCOUNT") + List_db_dns_out.get("NSCOUNT") \
                         + List_db_dns_out.get("ARCOUNT") + List_db_dns_out.get("QNAME") + List_db_dns_out.get("QTYPE") \
                         + List_db_dns_out.get("QCLASS") + List_db_dns_out.get("NAME") + List_db_dns_out.get("TYPE") \
                         + List_db_dns_out.get("CLASS") + List_db_dns_out.get("TTL") + List_db_dns_out.get("RDLENGTH") \
                         + List_db_dns_out.get("RDATA")

    return message_db_dns_out


def answer_A_name_records(List_db_dns_in, requst,List_db_dns_out):

    List_db_dns_out["RCODE"] = "0000"  # Code answer(0,1,2,3,4,5,6-15)
    List_db_dns_out["ANCOUNT"] = requst.ANCOUNT  # Code answer 1  one  count db
    Header_1 = List_db_dns_out.get("QR") + List_db_dns_out.get("OPCODE") + List_db_dns_out.get(
        "AA") + List_db_dns_out.get("TC") + List_db_dns_out.get("RD")
    Header_2 = List_db_dns_out.get("RA") + List_db_dns_out.get("Z") + List_db_dns_out.get("RCODE")
    Header_1_1 = Header_1[0:4]
    Header_1_2 = Header_1[4:8]
    Header_2_1 = Header_2[0:4]
    Header_2_2 = Header_2[4:8]
    List_db_dns_out["Header"] = str(int((Header_1_1), 2)) + str(int((Header_1_2), 2)) \
                                + str(int((Header_2_1), 2)) + str(int((Header_2_2), 2))
    List_db_dns_out["NAME"] = "C00C"  # format Message compression 44
    List_db_dns_out["TYPE"] = requst.TYPE
    List_db_dns_out["CLASS"] = requst.CLASS
    List_db_dns_out["TTL"] = requst.TTL
    List_db_dns_out["RDLENGTH"] = requst.RDLENGTH
    List_db_dns_out["RDATA"] = requst.RDATA
    List_db_dns_out["arcaunt"] = List_db_dns_in["arcaunt"]
    message_db_dns_out = List_db_dns_out.get("ID") + List_db_dns_out.get("Header") + List_db_dns_out.get("QDCOUNT") \
                         + List_db_dns_out.get("ANCOUNT") + List_db_dns_out.get("NSCOUNT") \
                         + List_db_dns_out.get("ARCOUNT") + List_db_dns_out.get("QNAME") + List_db_dns_out.get("QTYPE") \
                         + List_db_dns_out.get("QCLASS") + List_db_dns_out.get("NAME") + List_db_dns_out.get("TYPE") \
                         + List_db_dns_out.get("CLASS") + List_db_dns_out.get("TTL") + List_db_dns_out.get("RDLENGTH") \
                         + List_db_dns_out.get("RDATA") + List_db_dns_out["arcaunt"]
    return message_db_dns_out



def answer_SOA(List_db_dns_out):

    List_db_dns_out["RCODE"] = "0000"  # Code answer(0,1,2,3,4,5,6-15)
    List_db_dns_out["ARCOUNT"] = "0000"
    List_db_dns_out["ANCOUNT"] = "0000"
    List_db_dns_out["NSCOUNT"] = "0001"  # numba write name servis available
    Header_1 = List_db_dns_out.get("QR") + List_db_dns_out.get("OPCODE") + List_db_dns_out.get("AA") \
               + List_db_dns_out.get("TC") + List_db_dns_out.get("RD")
    Header_2 = List_db_dns_out.get("RA") + List_db_dns_out.get("Z") + List_db_dns_out.get("RCODE")
    Header_1_1 = Header_1[0:4]
    Header_1_2 = Header_1[4:8]
    Header_2_1 = Header_2[0:4]
    Header_2_2 = Header_2[4:8]
    List_db_dns_out["Header"] = str(int((Header_1_1), 2)) + str(int((Header_1_2), 2)) \
                                + str(int((Header_2_1), 2)) + str(int((Header_2_2), 2))
    List_db_dns_out["MNAME"] = "C00C"  # format Message compression 44
    #dmytri vik noskov gmail com
    List_db_dns_out["RNAME"] = "000600010000003b0026036e7300c00c0a686f73746d6173746572732d646d797472692076696b20" \
                               "6e6f736b6f7620676d61696c20636f6d00"
    List_db_dns_out["SERIAL"] = "7858E045" # 2019090501 yyyy mm dd nn
    List_db_dns_out["REFRESH"] = "00001c20" #7200
    List_db_dns_out["RETRY"] = "00000E10"  #3600
    List_db_dns_out["EXPIRE"] = "00093A80" #604800
    List_db_dns_out["MINIMUM"] = "00000E10" #3600
    message_db_dns_out = List_db_dns_out.get("ID") + List_db_dns_out.get("Header") + List_db_dns_out.get("QDCOUNT") \
                         + List_db_dns_out.get("ANCOUNT") + List_db_dns_out.get("NSCOUNT") \
                         + List_db_dns_out.get("ARCOUNT") + List_db_dns_out.get("QNAME") + List_db_dns_out.get("QTYPE") \
                         + List_db_dns_out.get("QCLASS") + List_db_dns_out.get("MNAME") + List_db_dns_out.get("RNAME") \
                         + List_db_dns_out.get("SERIAL") + List_db_dns_out.get("REFRESH") + List_db_dns_out.get("RETRY") \
                         + List_db_dns_out.get("EXPIRE") + List_db_dns_out.get("MINIMUM")
    print(message_db_dns_out)
    return message_db_dns_out


def DB_DNS_in(in_message):
    # distionary incoming message
    #
    engine = create_engine(route_DB)
    Session = sessionmaker(bind=engine)
    session = Session()
    query = session.query(DynDNS)
    #

    List_db_dns_in = {}
    List_db_dns_in["ID"] = in_message[0:4]
    id4 = ("{0:4b}".format(int(in_message[4:5], 16)) + "{0:4b}".format(int(in_message[5:6], 16)) +
           '{0:4b}'.format(int(in_message[6:7], 16)) + '{0:4b}'.format(int(in_message[7:8], 16)))

    i = 0
    id4_1 = {}
    while i <= 15:
        if id4[i] == "1":
            id4_1[i] = "1"
            i = i + 1
        else:
            id4_1[i] = "0"
            i = i + 1

    List_db_dns_in["QR"] = id4_1[0]
    List_db_dns_in["OPCODE"] = id4_1[1] + id4_1[2] + id4_1[3] + id4_1[4]
    List_db_dns_in["AA"] = id4_1[5]
    List_db_dns_in["TC"] = id4_1[6]
    List_db_dns_in["RD"] = id4_1[7]
    List_db_dns_in["RA"] = id4_1[8]
    List_db_dns_in["Z"] = id4_1[9] + id4_1[10] + id4_1[11]
    List_db_dns_in["RCODE"] = id4_1[12] + id4_1[13] + id4_1[14] + id4_1[15]
    List_db_dns_in["QDCOUNT"] = in_message[8:12]
    List_db_dns_in["ANCOUNT"] = in_message[12:16]
    List_db_dns_in["NSCOUNT"] = in_message[16:20]
    List_db_dns_in["ARCOUNT"] = in_message[20:24]

    if List_db_dns_in["Z"] != "000":
        List_db_dns_in["AD"] = List_db_dns_in["Z"][1]
        List_db_dns_in["CD"] = List_db_dns_in["Z"][2]
    else:
        List_db_dns_in["AD"] = "0"
        List_db_dns_in["CD"] = "0"
    i = (int((in_message[24:26]), 16))
    y = i

    while True:
        if (in_message[(26 + y * 2):(28 + y * 2)]) == "00":
            z = y
            List_db_dns_in["QNAME"] = in_message[24:28 + y * 2]
            break
        else:
            i = (int((in_message[(26 + y * 2):(28 + y * 2)]), 16))
            y = y + i + 1

    List_db_dns_in["QTYPE"] = in_message[(28 + z * 2):(32 + z * 2)]
    List_db_dns_in["QCLASS"] = in_message[(32 + z * 2):(36 + z * 2)]
    arcount_start = (36 + z * 2)
    List_db_dns_in["arcaunt"] = in_message[arcount_start:]
    List_db_dns_in["List_db_dns_in"] = in_message
    l = (int((List_db_dns_in.get("QNAME")[0:2]), 16))
    qname = (List_db_dns_in.get("QNAME")[2: 2 + l * 2])
    while True:
        if (List_db_dns_in.get("QNAME")[2 + l * 2:4 + l * 2]) == "00":
            break
        else:
            m = int(List_db_dns_in.get("QNAME")[2 + l * 2:4 + l * 2], 16)
            qname = qname + "2e" + (List_db_dns_in.get("QNAME")[4 + l * 2:4 + (l + m) * 2])
            l = l + m + 1


    List_db_dns_out = {}
    List_db_dns_out["ID"] = List_db_dns_in["ID"]
    List_db_dns_out["QR"] = "1"  # 0-requst , 1 answer
    List_db_dns_out["OPCODE"] = List_db_dns_in["OPCODE"]  # 0- standart requst and variant
    List_db_dns_out["AA"] = List_db_dns_in["AA"]  # Code answer
    List_db_dns_out["TC"] = List_db_dns_in["TC"]  # TrunCation
    List_db_dns_out["RD"] = "0"  # Recursion
    List_db_dns_out["RA"] = "0"  # Recursion Available
    List_db_dns_out["Z"] = List_db_dns_in["Z"]  # Reservation
    List_db_dns_out["QDCOUNT"] = List_db_dns_in["QDCOUNT"]  # 1-requst
    List_db_dns_out["NSCOUNT"] = List_db_dns_in["NSCOUNT"]  # numba write name servis available  #default 0000
    List_db_dns_out["ARCOUNT"] = List_db_dns_in["ARCOUNT"]  # numba write recurs additionally
    List_db_dns_out["QNAME"] = List_db_dns_in["QNAME"]
    List_db_dns_out["QTYPE"] = List_db_dns_in["QTYPE"]
    List_db_dns_out["QCLASS"] = List_db_dns_in["QCLASS"]

    if List_db_dns_in["OPCODE"] == "0000" and List_db_dns_in["QDCOUNT"] == "0001" and List_db_dns_in["QCLASS"] == "0001":
        requst = session.query(DynDNS).filter(DynDNS.NAME == qname).first()
        if List_db_dns_in["ARCOUNT"] == "0000":
            if List_db_dns_in["QTYPE"] == "0001":  # A format
                if requst is not None:
                    message_db_dns_out_f = answer_A_name(requst, List_db_dns_out)  # yes A
                else:
                    message_db_dns_out_f = answer_no_name(List_db_dns_out)  # no A
                    if List_db_dns_in["RD"] == "1":
                        pass
                    else:
                        pass

            else:
                if List_db_dns_in["QTYPE"] == "0110":  # SOA format
                    if requst is not None:
                        message_db_dns_out_f = answer_SOA(List_db_dns_out)
                    else:
                        message_db_dns_out_f = Server_failure(List_db_dns_out)

        else:
            # List_db_dns_in["ARCOUNT"] != "0000":
            #  CD+AD + records
            if requst is not None:
                if List_db_dns_in["QTYPE"] == "0001":  # A format
                    message_db_dns_out_f = answer_A_name_records(List_db_dns_in, requst, List_db_dns_out)  # yes A+records
                elif List_db_dns_in["QTYPE"] == "0110":  # SOA format
                    message_db_dns_out_f = answer_SOA(List_db_dns_out)
                else:
                    pass
            else:
                message_db_dns_out_f = answer_no_name(List_db_dns_out)  # no A

    else:
        message_db_dns_out_f = Server_failure(List_db_dns_out)

    session.commit()
    session.close()
    return message_db_dns_out_f

