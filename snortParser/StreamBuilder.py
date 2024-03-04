#-*- coding:gbk -*-

from scapy.layers.inet import *
from scapy.utils import *


# 负责具体的TCP协议数据包构建
class TcpStreamBuilder:
    def __init__(self,client_ip = "192.168.100.5",client_port = 6552,client_mac = "d4:68:ba:91:28:b6",server_ip = "192.168.100.125",server_port = 6558,server_mac = "d4:68:ba:91:28:b9",tcp_init_seq = 0):
        self.client_ip = client_ip
        self.client_port = client_port
        self.client_mac = client_mac
        
        self.server_ip = server_ip
        self.server_port = server_port
        self.server_mac = server_mac

        self.server_seq = tcp_init_seq
        self.server_ack = tcp_init_seq
        self.client_seq = tcp_init_seq
        self.client_ack = tcp_init_seq
        
        self.respond_pcap = None
        self.total_packet_list = PacketList()

    #构建TCP三次握手流量包
    def handshake_builder(self)->PacketList:
        packet_list = PacketList()
        
        self.send_pcap = Ether(dst=self.server_mac)/IP(flags="DF",src=self.client_ip,dst=self.server_ip)/TCP(sport=self.client_port,dport=self.server_port,flags="S",seq=self.client_seq)
        packet_list.append(self.send_pcap)
        
        self.server_ack = self.client_seq + 1
        self.respond_pcap = Ether(dst = self.server_mac)/IP(flags="DF",src=self.server_ip,dst=self.client_ip)/TCP(sport=self.server_port,dport=self.client_port,flags="SA",ack = self.server_ack,seq=self.server_seq)
        packet_list.append(self.respond_pcap)
        
        self.client_ack = self.server_seq + 1
        self.client_seq = self.server_ack
        self.send_pcap = Ether(dst = self.server_mac)/IP(flags="DF",src=self.client_ip,dst=self.server_ip)/TCP(sport=self.client_port,dport=self.server_port,flags="A",ack = self.client_ack,seq=self.client_seq)
        packet_list.append(self.send_pcap)
        
        self.total_packet_list.append(packet_list)
        return packet_list
    
    #构建发送到服务端的单个流量包
    def send_to_server(self,send_data:bytearray):
        self.client_seq = self.server_ack
        if len(self.respond_pcap["TCP"].payload) == 0:
            self.client_ack = self.server_seq + 1
        else:
            self.client_ack = self.server_seq + len(self.respond_pcap["TCP"].payload)
            
        self.send_pcap = Ether(dst=self.server_mac)/IP(flags="DF",src=self.client_ip,dst=self.server_ip)/TCP(sport=self.client_port,dport=self.server_port,flags="A",seq=self.client_seq,ack=self.client_ack)/send_data        
        
        self.total_packet_list.append(self.send_pcap)
        return self.send_pcap
    
    #构建发送到客户端的单个流量包
    def send_to_client(self,recv_data:bytearray):
        self.server_seq = self.client_ack
        self.server_ack = self.client_seq + len(self.send_pcap["TCP"].payload)

        self.respond_pcap = Ether(dst = self.server_mac)/IP(flags="DF",src=self.server_ip,dst=self.client_ip)/TCP(sport=self.server_port,dport=self.client_port,flags="A",ack = self.server_ack,seq=self.server_seq)/recv_data
        self.total_packet_list.append(self.respond_pcap)
        return self.respond_pcap
        
    #构建双向TCP流量包
    def pcap_builder(self,send_data:bytearray,recv_data:bytearray,handshake:bool = True):
        packet_list = None
        if handshake == True:
            packet_list = self.handshake_builder()
        else:
            packet_list =  PacketList()
        
        packet_list.append(self.send_to_server(send_data))
        packet_list.append(self.send_to_client(recv_data))
            
        return packet_list
    
    #将数据包写入到文件中
    def pcap_writer(self,pcap_name:str , pcap_list = None):
        if pcap_list == None:
            wrpcap(pcap_name,self.total_packet_list)
        else:
            wrpcap(pcap_name,pcap_list)
            

# 负责具体的UDP协议数据包构建
class UdpStreamBuilder:    
    def __init__(self,client_ip = "192.168.100.5",client_port = "6552",client_mac = "d4:68:ba:91:28:b6",server_ip = "192.168.100.125",server_port = "6558",server_mac = "d4:68:ba:91:28:b9"):
        self.client_ip = client_ip
        self.client_port = client_port
        self.client_mac = client_mac
        
        self.server_ip = server_ip
        self.server_port = server_port
        self.server_mac = server_mac
        
        self.total_packet_list = PacketList()
        
    def send_to_server(self,send_data:bytearray):
        pcap = Ether(dst=self.server_mac)/IP(flags="DF",src=self.client_ip,dst=self.server_ip)/UDP(sport=self.client_port,dport=self.server_port)/send_data
        self.total_packet_list.append(pcap)
        return pcap

    def send_to_client(self,send_data:bytearray):
        pcap = Ether(dst=self.client_mac)/IP(flags="DF",src=self.server_ip,dst=self.client_ip)/UDP(sport=self.server_port,dport=self.client_port)/send_data
        self.total_packet_list.append(pcap)
        return pcap
    
    def pcap_builder(self,send_data:bytearray,recv_data:bytearray):
        pcap_list = PacketList()
        pcap_list.append(self.send_to_server(send_data))
        pcap_list.append(self.send_to_client(recv_data))
        return pcap_list

    def pcap_writer(self,pcap_name):
        wrpcap(pcap_name,self.total_packet_list)