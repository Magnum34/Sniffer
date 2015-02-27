#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import sys
from struct import *


def eth_addr(a):
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
    return b
def tcp_flags(flag,file1):
    flag = '{:08b}'.format(flag)
    print '\tStan połączenia : ',
    if file1 == True:
        f.write('\tStan połączenia : ')
    if '1' == flag[7]:
        print 'FIN ',
        if file1 == True:
            f.write('FIN\n')
        #zakońćzenie przekazu danych
    elif '1' == flag[6]:
        print 'SYN ',
        if file1 == True:
            f.write('SYN\n')
        #synchronizuje kolejne numery sekwecyjne 
    elif '1' == flag[5]:
        print 'RST ',
        if file1 == True:
            f.write('RST\n')
        #resetuje połączenie
    elif '1' == flag[4]:
        print 'PSH ',
        if file1 == True:
            f.write('PSH\n')
        # wymusza przesłanie pakietu
    elif '1' == flag[3]:
        print 'ACK ',
        if file1 == True:
            f.write('ACK\n')
        # informuje o istoności pola "numer potwierdzenia"
    elif '1' == flag[2]:
        print 'URG ',
        if file1 == True:
            f.write('URG\n')
        #informuje o istotności pole "Priorytet"
    elif '1' == flag[1]:
        print 'ECE ',
        if file1 == True:
            f.write('ECE\n')
        #flaga ustawiona przez odbiorcę w momencie otrzymania pakietu
    elif '1' == flag[0]:
        print 'CWR ',
        if file1 == True:
            f.write('CWR\n')
        #flaga potwierdzająca odebranie powiadomienia przez nadawcę, 
        #umożliwia odbiorcy zaprzestanie wysyłanie echa
    print ""
#ICMP TYPY
def icmp_type(types):
    print "\tNazwa Typu : ",
    if types == 0:
        print "Zwrot Echa "
    elif types == 3:
        print "nieosiągalność miejsca przeznaczenia"
    elif types == 4:
        print "tłumienie nadawcy"
    elif types == 5:
        print "zmień trasowanie"
    elif types == 6:
        print "alternatywny adres hosta"
    elif types == 8:
        print "żądanie echa"
    elif types == 9:
        print "ogłoszenie routera"
    elif types == 10:
        print "wybór routera"
    elif types == 30:
        print "śledzenie trasy"

try:
    #0x0003 jest ETH_P_ALL wszystkie rodzaje protokołów
    #pochodzi z if_ethernet.h biblioteki linuxowej
    s = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(0x0003))
except socket.error():
     print 'Socket could not be created. Error Code'
     sys.exit()
#odbieramy pakiety
val = False
file_open = False
display = raw_input('Czy wyświetlić dane pakietu t\\f: ')
print_file = raw_input('Czy nasłuchiwane dane zapisać do pliku t\\f: ')
if 't' == print_file.lower():
    name = raw_input('nazwa pliku : ')
    if name != '':
        f = open(name+'.txt','wt') 
        file_open = True
if 't' == display.lower():
    val = True
elif 'f' == display.lower():
    val = False
while True:
    packet = s.recvfrom(65565)
    packet = packet[0]
    eth_length = 14
    # Adres odbiorcy 6 bajtów
    # Adres Nadawcy 6 bajtów
    # typ ramki 2 bajty
    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH',eth_header)
    eth_protocol = socket.ntohs(eth[2])
    MAC_source = eth_addr(eth[1])
    MAC_receiver = eth_addr(eth[0])
    print "Nagłówek Ethernetowy (IEEE) "
    print 'MAC źróðłowy : ' +str(MAC_source)+ ' MAC docelowy : '+str(MAC_receiver)
    print ""
    if file_open == True:
        f.write("Nagłówek Ethernetowy (IEEE) \n")
        f.write('MAC źróðłowy : ' +str(MAC_source)+ ' MAC docelowy : '+str(MAC_receiver)+"\n")
        f.write("\n")
    #Protokół 0x0800 - IPv4 = dec = 8
    if eth_protocol == 8:
        ip_header = packet[eth_length:20+eth_length]
        #Przekształcanie formatu C na pythona struktura
        #B - unsigned char to intiger
        #H - unsigned short to intiger
        #Wypakowanie nagłówka 
        iph = unpack('!BBHHHBBH4s4s',ip_header)
        #print iph
        version_ihl = iph[0]
        #iph[0] - wersja oraz długość nagłówka
        version = version_ihl >> 4
        #0xF = 15
        #długośc nagłówka
        ihl = version_ihl & 0xF
        iph_length = ihl*4
        #Typ Usługi 
        type_service = iph[1]
        #całkowity rozmiar pakietu
        size_full = iph[2]
        #numer indyfikacyjny
        index = iph[3]    
        #czas Zycia - diagramu  TTL
        ttl = iph[5]
        #Protokół warswtwy wyższej
        protocol = iph[6]
        """
        1 - ICMP
        2 - IGMP
        6 - TCP
        8 - EGP
        17 - UDP
        """
        #Adresy nadawcy i odbiorcy
        # inet_ntoa - konwersja binarne na  stringi reprezentacje adresu IPv4
        checksum_ip = iph[7]
        source  = socket.inet_ntoa(iph[8])
        receiver = socket.inet_ntoa(iph[9])
        print "\tNagłówek IPv4"
        print '\tWersja : '+str(version) + ' Długość nagłówka :' + str(ihl) + ' TTL: '+str(ttl)+ ' Protokół : '+str(protocol)
        print '\tTyp Usługi: '+str(type_service)+ ' Całkowity Rozmiar pakietu: '+str(size_full)+' Suma Kontrolna: '+str(checksum_ip)
        print '\tNumer indetyfikacyjny: '+str(index)
        print '\tAdres źródłowy : '+str(source)+' Adres Docelowy : '+str(receiver)
        print ""
        if file_open == True:
            f.write("\tNagłówek IPv4\n")
            f.write('\tWersja : '+str(version) + ' Długość nagłówka :' + str(ihl) + ' TTL: '+str(ttl)+ ' Protokół : '+str(protocol)+"\n")
            f.write('\tAdres źródłowy : '+str(source)+' Adres Docelowy : '+str(receiver)+"\n")
            f.write("\n")
        #!!!!!!!!!!!!!!!!!!!!!!!!!!TCP!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        if protocol == 6:
            tcp_header = packet[iph_length+eth_length:iph_length+20+eth_length]
            tcph = unpack('!HHLLBBHHH',tcp_header)
            source_port = tcph[0]
            receiver_port = tcph[1]
            nr_sekwecyjny = tcph[2]
            nr_potwierdzenia = tcph[3]
            doff = tcph[4]
            length_tcp_head = doff >> 4
            print "\tNagłówek TCP"
            print '\tŹródłowy port : '+str(source_port)+' Docelowy Port : '+str(receiver_port)+' Numer sekwecyjny : '+str(nr_sekwecyjny)
            print '\tNumer potwierdzenia : '+str(nr_potwierdzenia)+' Rozmiar nagłówka : '+str(length_tcp_head)
            tcp_flags(tcph[5],False)
            print '\tSuma kontrolna: '+str(tcph[7])
            print ""
            if file_open == True:
                f.write("\tNagłówek TCP\n")
                f.write('\tŹródłowy port : '+str(source_port)+' Docelowy Port : '+str(receiver_port)+' Numer sekwecyjny : '+str(nr_sekwecyjny)+"\n")
                f.write('\tNumer potwierdzenia : '+str(nr_potwierdzenia)+' Rozmiar nagłówka : '+str(length_tcp_head*4)+"\n")
                tcp_flags(tcph[5],True)
                f.write('\tSuma kontrolna: '+str(tcph[7])+'\n')
                f.write("\n")
            if val:
                h_size = eth_length+iph_length+length_tcp_head*4
                data = packet[h_size:]
                
                data_hex = str(data)
                print 'DANE\n'
                if file_open == True:
                    f.write('DANE\n')
                for i in range(len(data_hex)):
                    value = ord(data_hex[i])
                    if value <= 126 and value >= 32:
                        print chr(value),
                        if file_open == True:
                            f.write(chr(value))
                    else:
                        print '.',
                        if file_open == True:
                            f.write('.')
                print '\nDANE HEX\n'
                if file_open == True:
                    f.write('\nDANE HEX\n')
                for i in range(len(data_hex)):
                    print hex(ord(data_hex[i])),
                    if file_open == True:
                        f.write(hex(ord(data_hex[i])))
                if file_open == True:
                    f.write('\n\n')
                print ""
                print ""
        #!!!!!!!!!!!!!!!!!!!!!!!UDP!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        elif protocol == 17:
            print "\tNagłówek UDP"
            udp_header = packet[iph_length+eth_length:iph_length+8+eth_length]
            udph = unpack('!HHHH',udp_header)
            port_source = udph[0]
            port_receiver = udph[1]
            length_udp = udph[2]
            #suma kontrolna
            checksum = udph[3]
            print "\tPort źródłowy : "+str(port_source)+' port docelowy :' +str(port_receiver)+' Rozmiar pakietu : '+str(length_udp)
            print '\tSuma kontrolna : '+str(checksum)
            if file_open == True:
                f.write("\tNagłówek UDP\n")
                f.write("\tPort źródłowy : "+str(port_source)+' port docelowy :' +str(port_receiver)+' Rozmiar pakietu : '+str(length_udp)+"\n")
                f.write('\tSuma kontrolna : '+str(checksum)+"\n")
                f.write("\n")
            print ""
            if val:
                h_size = eth_length+iph_length+length_udp
                data = packet[h_size:]
                #print data
                hex_data = str(data)
                print 'DANE\n'
                if file_open == True:
                    f.write('DANE\n')
                for i in range(len(hex_data)):
                    value = ord(hex_data[i])
                    if value <= 126 and value >= 32:
                        print chr(value),
                        if file_open == True:
                            f.write(chr(value))
                    else:
                        print '.',
                        if file_open == True:
                            f.write('.')
                print '\nDANE HEX\n'
                if file_open == True:
                    f.write('\nDANE HEX\n')
                for i in range(len(hex_data)):
                    print hex(ord(hex_data[i])),
                    if file_open == True:
                        f.write( hex(ord(hex_data[i])))    
                print ""
                print ""
                if file_open == True:
                    f.write('\n\n')
        #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!ICMP!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        elif protocol == 1:
            print "\tNagłówek ICMP"
            icmp_header = packet[iph_length+eth_length:iph_length+eth_length+4]
            icmpH = unpack('!BBH',icmp_header)
            print '\tTyp : '+str(icmpH[0])+' Kod: '+str(icmpH[1])+' Suma kontrolna : '+str(icmpH[2])
            icmp_type(icmpH[0])
            if file_open == True:
                f.write("\tNagłówek ICMP\n")
                f.write('\tTyp : '+str(icmpH[0])+' Kod: '+str(icmpH[1])+' Suma kontrolna : '+str(icmpH[2])+'\n')
                f.write("\n")
        else:
            print "Inny protokół niż TCP/UDP/ICMP"
            print "protokół: "+str(protocol)+'\n'
    
    else:
        print "Inny protokół niż IPv4\n Protokół :  "+str(eth_protocol)+"\n"
