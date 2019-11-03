import binascii
import socket


def str2hex(s):
    return binascii.hexlify(bytes(str.encode(s)))


def hex2str(h):
    return binascii.unhexlify(h)


def send_udp_message(message, address, port):
    """send_udp_message sends a message to UDP server

    message should be a hexadecimal encoded string
    """
    server_address = (address, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(binascii.unhexlify(message), server_address)
        sock.settimeout(1)
        data, _ = sock.recvfrom(1024)
    except socket.error:
        sock.close()
        print('socket error')
    else:
        sock.close()
        return binascii.hexlify(data).decode("utf-8")


def List_callback():
    # distionary answer dns server
    #
    # print(response)
    List_in = {}
    List_in["ID"] = response[0:4]
    id4 = ("{0:4b}".format(int(response[4:5], 16)) + "{0:4b}".format(int(response[5:6], 16)) +
           '{0:4b}'.format(int(response[6:7], 16)) + '{0:4b}'.format(int(response[7:8], 16)))

    i = 0
    id4_1 = {}
    while i <= 15:
        if id4[i] == "1":
            id4_1[i] = "1"
            i = i + 1
        else:
            id4_1[i] = "0"
            i = i + 1

    List_in["QR"] = id4_1[0]
    List_in["OPCODE"] = id4_1[1] + id4_1[2] + id4_1[3] + id4_1[4]
    List_in["AA"] = id4_1[5]
    List_in["TC"] = id4_1[6]
    List_in["RD"] = id4_1[7]
    List_in["RA"] = id4_1[8]
    List_in["Z"] = id4_1[9] + id4_1[10] + id4_1[11]
    List_in["RCODE"] = id4_1[12] + id4_1[13] + id4_1[14] + id4_1[15]
    List_in["QDCOUNT"] = response[8:12]
    List_in["ANCOUNT"] = response[12:16]
    List_in["NSCOUNT"] = response[16:20]
    List_in["ARCOUNT"] = response[20:24]
    i = (int((response[24:26]), 16))
    y = i

    while True:
        if (response[(26 + y * 2):(28 + y * 2)]) == "00":
            z = y
            List_in["QNAME"] = response[24:28 + y * 2]
            break
        else:
            i = (int((response[(26 + y * 2):(28 + y * 2)]), 16))
            y = y + i + 1

    if List_in["Z"] != "000":
        List_in["AD"] = List_in["Z"][1]
        List_in["CD"] = List_in["Z"][2]
    else:
        List_in["AD"] = "0"
        List_in["CD"] = "0"

    List_in["QTYPE"] = response[(28 + z * 2):(32 + z * 2)]
    List_in["ARCOUNT_new"] = "0001"
    if List_in["QTYPE"] == "0001":
        List_in["QCLASS"] = response[(32 + z * 2):(36 + z * 2)]
        id3 = bin(int(response[(36 + z * 2):(40 + z * 2)], 16))
        if id3[2:4] == "11":
            List_in["NAME"] = response[(36 + z * 2):(40 + z * 2)]
        else:
            List_in["NAME"] = response[(36 + z * 2):(40 + z * 2)]  # AttributeError
            List_in["Att_Error"] = 'Att_Error'

        List_in["TYPE"] = response[(40 + z * 2):(44 + z * 2)]
        List_in["CLASS"] = response[(44 + z * 2):(48 + z * 2)]
        List_in["TTL"] = response[(48 + z * 2):(56 + z * 2)]
        if response[(56 + z * 2):(60 + z * 2)] == "0004":
            List_in["RDLENGTH"] = response[(56 + z * 2):(60 + z * 2)]
        else:
            List_in["RDLENGTH"] = response[(56 + z * 2):(60 + z * 2)]  # AttributeError
            List_in["Att_Error"] = 'Att_Error'
        if List_in["ANCOUNT"] == "0001":
            List_in["RDDATA"] = response[(60 + z * 2):(68 + z * 2)]
            arcount_start = (68 + z * 2)
        elif List_in["ANCOUNT"] == "0002":
            List_in["RDDATA"] = response[(60 + z * 2):(100 + z * 2)]
            arcount_start = (100 + z * 2)
        elif List_in["ANCOUNT"] == "0003":
            List_in["RDDATA"] = response[(60 + z * 2):(140 + z * 2)]
            arcount_start = (140 + z * 2)
        elif List_in["ANCOUNT"] == "0004":
            List_in["RDDATA"] = response[(60 + z * 2):(180 + z * 2)]
            arcount_start = (180 + z * 2)
        elif List_in["ANCOUNT"] == "0005":
            List_in["RDDATA"] = response[(60 + z * 2):(220 + z * 2)]
            arcount_start = (220 + z * 2)
        else:
            pass
        if List_in["ARCOUNT"] != "0000":
            List_in["arcaunt"] = response[arcount_start:]
            if len(List_in["arcaunt"]) <= 40:
                List_in["ARCOUNT_new"] = "0000"
            else:
                List_in["type_cover"] = List_in["arcaunt"][0:4]
                List_in["arlgorithm"] = List_in["arcaunt"][4:6]
                List_in["labels"] = List_in["arcaunt"][6:8]
                List_in["orig_ttl"] = List_in["arcaunt"][8:16]
                List_in["sig_exp"] = List_in["arcaunt"][18:26]
                List_in["sig_ince"] = List_in["arcaunt"][26:34]
                List_in["key_tag"] = List_in["arcaunt"][34:38]
                List_in["sig_name"] = ""
                i = 0
                while True:
                    if List_in["arcaunt"][38 + i:40 + i] == "00":
                        i = i + 2
                        break
                    else:
                        try:
                            List_in["sig_name"] = List_in["sig_name"] + "".join(
                                hex2str(List_in["arcaunt"][38 + i:40 + i]).decode('utf-8'))
                            i = i + 2
                        except UnicodeDecodeError:
                            i = i + 2

                List_in["signature"] = List_in["arcaunt"][38 + i:]


        else:
            pass
    elif List_in["QTYPE"] == "0110" and List_in["NSCOUNT"] == "0001":  # 'SOA (6) 0110'
        List_in["LIST_IN"] = response
        List_in["QCLASS"] = response[(32 + z * 2):(36 + z * 2)]
        start_list = int((28 + y * 2)) + 12
        List_in["SOA"] = response[start_list:]
        List_in["NAME"] = response[(36 + z * 2):(40 + z * 2)]  # MNAME
        List_in["RNAME"] = List_in["SOA"][:-40]
        List_in["SERIAL"] = List_in["SOA"][-40:-32]
        List_in["REFRESH"] = List_in["SOA"][-32:-24]
        List_in["RETRY"] = List_in["SOA"][-24:-16]
        List_in["EXPIRE"] = List_in["SOA"][-16:-8]
        List_in["MINIMUM"] = List_in["SOA"][-8:]

    else:
        pass

    List_in["LIST_IN"] = response
    return List_in


def List_read_in(List_in):
    # Decode answer distionary answer dns server
    #
    for i in List_in.values():
        if i == "Att_Error":
            print('Error DNS name ,not ip adress')

    print("--------------------------------------------------------------------------------------------------------")
    print("")
    print("")
    print("ID      :" + "  indification request                                          " + List_in.get("ID"))
    print("        QR :" + "  request(0) or answer(1)                                    " + List_in.get("QR"))
    print("        OPCODE :" + "Code status(0-st.req,1-inv.req,2-stat.ser,3-15-reserv)   " + List_in.get("OPCODE"))
    print("        AA :" + "  indification request                                       " + List_in.get("AA"))
    print("        TC :" + "  TrunCation                                                 " + List_in.get("TC"))
    print("        RD :" + "  Recursion Desired                                          " + List_in.get("RD"))
    print("        RA :" + "  Recursion Available                                        " + List_in.get("RA"))
    print("        Z  :" + "  Reservation                                                " + List_in.get("Z"))
    print("        AD  :" + "  AD RFC 2136, 2535                                         " + List_in.get("AD"))
    print("        CD  :" + "  CD RFC 2136, 2535                                         " + List_in.get("CD"))
    print("        RCODE   :" + " Code answer(0,1,2,3,4,5,6-15)                          " + List_in.get("RCODE"))
    print("QDCOUNT :" + " quantity element answer                                        " + List_in.get("QDCOUNT"))
    print("ANCOUNT :" + " quantity resurs answer                                         " + List_in.get("ANCOUNT"))
    print("NSCOUNT :" + " quantity record server recurs                                  " + List_in.get("NSCOUNT"))
    print("ARCOUNT :" + " quantity record server recurs additionally                     " + List_in.get("ARCOUNT"))
    print("--------------------------------------------------------------------------------------")
    l = (int((List_in.get("QNAME")[0:2]), 16))
    qname = (List_in.get("QNAME")[2: 2 + l * 2])
    while True:
        if (List_in.get("QNAME")[2 + l * 2:4 + l * 2]) == "00":
            break
        else:
            m = int(List_in.get("QNAME")[2 + l * 2:4 + l * 2], 16)
            qname = qname + "2e" + (List_in.get("QNAME")[4 + l * 2:4 + (l + m) * 2])
            l = l + m + 1

    print("QNAME :" + " domain name                                                      " + hex2str(qname).decode(
        'utf-8'))
    print("QTYPE :" + " type request                                                     " + List_in.get("QTYPE"))
    print("QCLASS:" + " type class request                                               " + List_in.get("QCLASS"))
    id4 = bin(int(List_in.get("NAME"), 16))
    stpname = int(id4[4:18], 2)
    name_lend = int(List_in.get("LIST_IN")[0 + stpname * 2:2 + stpname * 2], 16)
    start_ind = 2 + stpname * 2
    stop_ind = 2 + stpname * 2 + name_lend * 2
    name = List_in.get("LIST_IN")[start_ind:stop_ind]
    s = 2
    nam_lend = int(List_in.get("LIST_IN")[stop_ind:2 + stop_ind], 16)

    while True:
        if nam_lend == 00:
            break

        else:
            start_ind = s + stop_ind
            stop_ind = s + stop_ind + nam_lend * 2
            name = name + "2e" + (List_in.get("LIST_IN")[start_ind:stop_ind])
            nam_lend = int(List_in.get("LIST_IN")[stop_ind:2 + stop_ind], 16)

    print("NAME :" + " Name                                                              " + hex2str(name).decode(
        'utf-8'))
    if List_in["QTYPE"] == "0001":
        print("TYPE :" + " Type                                                              " + List_in.get("TYPE"))
        print("CLASS :" + " Class                                                            " + List_in.get("CLASS"))
        print(
            "RDLENGTH :" + " lend RDDATA                                                   " + List_in.get("RDLENGTH"))
        print("TTL :" + " Time    sek                                                        " + str(
            int(List_in.get("TTL"), 16)))
        if int(List_in.get("ANCOUNT")) == 1:
            print("RDDATA :" + "   IP ADRESS" + "                                                     " + ".".join(
                (str(int((List_in.get("RDDATA")[0:2]), 16)),
                 (str(int((List_in.get("RDDATA")[2:4]), 16))),
                 (str(int((List_in.get("RDDATA")[4:6]), 16))),
                 (str(int((List_in.get("RDDATA")[6:8]), 16))))))
        else:
            if int(List_in.get("ANCOUNT")) >= 2:
                print("RDDATA :" + "   IP ADRESS" + "                                                     " + ".".join(
                    (str(int((List_in.get("RDDATA")[0:2]), 16)),
                     (str(int((List_in.get("RDDATA")[2:4]), 16))),
                     (str(int((List_in.get("RDDATA")[4:6]), 16))),
                     (str(int((List_in.get("RDDATA")[6:8]), 16))))))
                start = 2
                step = 0
                count = int(List_in.get("ANCOUNT"))
                while True:
                    if start > count:
                        break
                    else:
                        print("TTL :" + " Time    sek                                                        " + str(
                            int((List_in.get("RDDATA")[21 + step:28 + step]), 16)))
                        print(
                            "RDDATA :" + "   IP ADRESS" + "                                                     " + ".".join(
                                (str(int((List_in.get("RDDATA")[32 + step:34 + step]), 16)),
                                 (str(int((List_in.get("RDDATA")[34 + step:36 + step]), 16))),
                                 (str(int((List_in.get("RDDATA")[36 + step:38 + step]), 16))),
                                 (str(int((List_in.get("RDDATA")[38 + step:40 + step]), 16))))))

                        start = start + 1
                        step = step + 32
    elif List_in["QTYPE"] == "0110" and List_in["RCODE"] == "0000" and List_in["NSCOUNT"] =="0001":  # SOA
        RNAME_out = ''
        RNAME_out = RNAME_out + hex2str(str(List_in.get("RNAME")[0:16])).decode('utf-8')
        i = 16
        name_rname = str(List_in.get("RNAME"))
        name_rname_global = str(List_in.get("LIST_IN"))
        while i <= len(name_rname):
            if name_rname[i:i + 2] == "c0":

                if name_rname[i + 2:i + 4] == "0c":
                    RNAME_out = RNAME_out + hex2str(qname).decode('utf-8')
                    i = i + 4

                else:
                    start = int(name_rname[i + 2:i + 4], 16)
                    while True:
                        if name_rname_global[(start - 1):(start + 1)] != "00":
                            i = i + 4
                            break
                        else:
                            try:
                                RNAME_out = RNAME_out + (
                                hex2str(name_rname_global[(start - 1):(start + 1)]).decode('utf-8'))
                                start = start + 2
                            except UnicodeDecodeError:
                                start = start + 2
                                return start


            else:
                RNAME_out = RNAME_out + (hex2str(name_rname[i:i + 2]).decode('utf-8'))
                i = i + 2

        print("RNAME  :" + "                                         " + RNAME_out)
        print("SERIAL :" + "                                         " + List_in.get("SERIAL"))
        print("REFRESH :" + "                                        " + str(int(List_in.get("REFRESH"), 16)))
        print("RETRY :" + "                                          " + str(int(List_in.get("RETRY"), 16)))
        print("EXPIRE :" + "                                         " + str(int(List_in.get("EXPIRE"), 16)))
        print("MINIMUM :" + "                                        " + str(int(List_in.get("MINIMUM"), 16)))

    else:
        pass

    if List_in["QTYPE"] == "0001" and List_in["ARCOUNT"] != "0000" and List_in["ARCOUNT_new"]!="0000":

        print("type_cover:" + "                                                  " + List_in.get("type_cover"))
        print("arlgorithm:" + "    value algorithm                               " + List_in.get("arlgorithm"))
        print("labels:" + "                                                      " + List_in.get("labels"))
        print("orig_ttl:" + "  original ttl kodes                                " + List_in.get("orig_ttl"))
        print("sig_exp:" + "    time end word                                    " + List_in.get("sig_exp"))
        print("sig_ince:" + "                                                    " + List_in.get("sig_ince"))
        print("key_tag:" + "   Key Tag Field                                     " + List_in.get("key_tag"))
        print("sig_name:" + "                                                    " + str(List_in.get("sig_name")))
        print("signature:" + "     " + List_in.get("signature"))

    else:
        pass

    return


def List_call():
    # write message for request in DNS server
    #
    List_out_call = {}
    print('Enter a CD RFC 2136, 2535: (blank to  default CD = "0")')
    name = input()
    if name == '':
        name = "0"
        List_out_call["CD"] = "0"
        List_out_call["Z"] = "000"
        List_out_call["ARCOUNT"] = "0000"
        List_out_call["RD"] = "1"  # Recursion
    elif name == '1':
        List_out_call["CD"] = "1"
        List_out_call["Z"] = "001"
        List_out_call["ARCOUNT"] = "0001"
        List_out_call["RD"] = "0"  # Recursion
    print("Name input  CD :", name)

    List_out_call["ID"] = "AAAA"  # id request
    List_out_call["QR"] = "0"  # 0-requst , 1 answer
    List_out_call["OPCODE"] = "0000"  # 0- standart requst and variant
    List_out_call["AA"] = "0"  # Code answer
    List_out_call["TC"] = "0"  # TrunCation
    List_out_call["RA"] = "0"  # Recursion Available
    List_out_call["RCODE"] = "0000"  # Code answer(0,1,2,3,4,5,6-15)
    List_out_call["QDCOUNT"] = "0001"  # 1-requst
    List_out_call["ANCOUNT"] = "0000"  # Code answer
    List_out_call["NSCOUNT"] = "0000"  # numba write name servis available

    Header_1 = List_out_call.get("QR") + List_out_call.get("OPCODE") + List_out_call.get("AA") + List_out_call.get("TC") \
               + List_out_call.get("RD")
    Header_2 = List_out_call.get("RA") + List_out_call.get("Z") + List_out_call.get("RCODE")

    Header_1_1 = Header_1[0:4]
    Header_1_2 = Header_1[4:8]
    Header_2_1 = Header_2[0:4]
    Header_2_2 = Header_2[4:8]
    List_out_call["Header"] = str(int((Header_1_1), 2)) + str(int((Header_1_2), 2)) \
                              + str(int((Header_2_1), 2)) + str(int((Header_2_2), 2))

    print('Enter a name: (blank to  default example.com)')
    name = input()
    if name == '':
        name = "example.com"
    else:
        pass
    print("Name input :", name)
    name_hex = str2hex(name).decode('utf-8')
    start_in = 0
    lis_name_hex = ""
    for i in range(0, len(name_hex), 2):
        if name_hex[i: i + 2] == "2e":  # 2e toshka
            stop_in = i  # toshka
            sum_in = str(hex(int((stop_in - start_in) / 2)))
            if int(sum_in, 16) < 16:
                lis_name_hex = lis_name_hex + "".join(sum_in[0] + sum_in[2] + name_hex[start_in:stop_in])
                start_in = stop_in + 2
            else:
                lis_name_hex = lis_name_hex + "".join(sum_in[2] + sum_in[3] + name_hex[start_in:stop_in])
                start_in = stop_in + 2

    stop_in = len(name_hex)
    sum_in = str(hex(int((stop_in - start_in) / 2)))
    lis_name_hex = lis_name_hex + "".join(sum_in[0] + sum_in[2] + name_hex[start_in:stop_in]) + "00"
    List_out_call["QNAME"] = lis_name_hex
    print('Enter QTYPE: (blank to  default A (1) 0001)')
    print('SOA (6) 0110')
    print('AAAA (28) 001C')
    name = input()
    if name == '':
        name = "0001"
        List_out_call["QTYPE"] = "0001"  # write A
    elif name == "6":
        List_out_call["QTYPE"] = "0110"
    elif name == "28":
        List_out_call["QTYPE"] = "001C"
    print("Name QTYPE :", name)

    List_out_call["QCLASS"] = "0001"  # 1 internet

    message = List_out_call.get("ID") + List_out_call.get("Header") + List_out_call.get("QDCOUNT") + List_out_call.get(
        "ANCOUNT") + List_out_call.get("NSCOUNT") + List_out_call.get("ARCOUNT") + List_out_call.get(
        "QNAME") + List_out_call.get("QTYPE") + List_out_call.get("QCLASS")
    if List_out_call["CD"] == "1":
        List_out_call["A/C"] = "00"  # key autofication
        List_out_call["Z0"] = "0"  # reserv
        List_out_call["XT"] = "0"  # reserv
        List_out_call["Z1"] = "0"  # reserv
        List_out_call["Z2"] = "0"  # reserv
        List_out_call["NAMTYP"] = "00"  # user soa (00) key zono (01)
        List_out_call["Z3"] = "0"  # reserv
        List_out_call["Z4"] = "0"  # reserv
        List_out_call["Z5"] = "0"  # reserv
        List_out_call["Z6"] = "0"  # reserv
        List_out_call["SIG"] = "0000"
        List_out_call["FLAGS"] = str(int((List_out_call["A/C"] + "00"), 2)) + str(
            int(("00" + List_out_call["NAMTYP"]), 2)) \
                                 + str(int(("0000"), 2)) + str(int((List_out_call["SIG"]), 2))
        List_out_call["PROTOKOL"] = "29"  # "11" 3-dns securiti   29!
        List_out_call["ALGORITHM"] = "10"  # 10   01 rsa-md5
        List_out_call["P_KEY"] = "00000080000000"
        message = message + List_out_call.get("FLAGS") + List_out_call.get("PROTOKOL") + List_out_call.get("ALGORITHM") \
                  + List_out_call.get("P_KEY")
    else:
        pass

    return (message)


def ip_server():
    print('Enter DNS server: (blank to  default "8.8.8.8")')  # "127.0.0.1"
    ip_server = input()
    if ip_server == '':
        ip_server = "8.8.8.8"  # "127.0.0.1"
    else:
        pass
    print("DNS server adress :", ip_server)
    return (str(ip_server))


response = send_udp_message(List_call(), ip_server(), 53)
List_read_in(List_callback())


