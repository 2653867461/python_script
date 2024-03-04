#-*- coding:gbk -*-

from PayloadBuilder import *
from idstools import rule 
from xeger import Xeger
import random
import os
import re


def generate_random_str(randomlength=16):
  random_str =""
  base_str ="abcdefghigklmnopqrstuvwxyz"
  length =len(base_str) -1
  for i in range(randomlength):
    random_str +=base_str[random.randint(0, length)]
  return random_str

class SnortRuleParser:
    def __init__(self,_snort_rule:rule):
        self.snort_rule = _snort_rule
        
        self.index_beg = 0
        self.index_end = 0
        self.pre_location = 0
        
        self.location_type = None
        self.pcap_segment = None
        self.proto_type = None       
        self.Xeger = Xeger(limit=10)
        
    #����content��ǩ
    def parse_content_string(self,content_string:str)->bytearray:
        message = bytearray()
        binary_region = False
        continue_flag = False

        for index in range(0,len(content_string)):
            if continue_flag == True:
                continue_flag = False
                continue
        
            if content_string[index] == '|':
                if binary_region == False:
                    binary_region = True
                else:
                    binary_region = False
                continue
        
            if binary_region == True:
                if content_string[index] == ' ':
                    continue
                else:
                    continue_flag = True
                    message.append(int(content_string[index : index + 2],16))
                    continue

            message.append(bytes(content_string[index],encoding="utf-8")[0])
        return message  
    
    '''
    src_bytes:��д�������
    dst_bytes:��������������
    '''
    def cover_pcap(self,src_bytes,dst_bytes):
        #û��λ�ñ�ǩ����ʱ,Ĭ��д��ǰһ��ģʽ������
        if self.index_beg == 0:
            self.index_beg = len(dst_bytes) 
            
        if self.index_end == 0:    
            self.index_end = self.index_beg + len(src_bytes)
        
        dst_bytes[self.index_beg:self.index_end] = src_bytes 

        self.index_beg = 0
        self.index_end = 0
        self.pre_location = self.index_end     
        
        return dst_bytes

    #����ǰһ���ν���������
    def cover_pcap_wrapper(self,src_bytes):
        #��HTTPЭ��
        if self.location_type == None and self.proto_type != "HTTP":
            if self.proto_type == "TCP":
                self.tcp_payload = self.cover_pcap(src_bytes,self.tcp_payload)
            else:
                self.udp_payload = self.cover_pcap(src_bytes,self.udp_payload)
        
        #HTTPЭ��
        elif self.location_type == "http_status":
            self.http_status = src_bytes
        elif self.location_type == "http_method":
            self.http_method = src_bytes
        elif self.location_type == "http_uri":
            self.http_uri = self.cover_pcap(src_bytes,self.http_uri)
        elif self.location_type == "http_header":
            if src_bytes.find(b":") == -1:
                self.http_header.append([bytearray(generate_random_str(6),encoding="utf-8"),src_bytes])
            else:
                self.http_header.append(src_bytes.split(b":",1))
        #ȱʡ����
        elif self.location_type == "http_body" or self.location_type == None:
            self.http_body = self.cover_pcap(src_bytes,self.http_body)
        else:
            print("δ֪λ�ò���\n")
        self.location_type = None
        self.pcap_segment = None
    
    #ȷ��Э�����ͣ���ʼ����ر���
    def init_snort_parser(self):
        self.body_min = 0
        self.body_max = 0
        
        self.sid = None
        self.parent_sid = None
        
        if self.snort_rule.proto.lower() == "udp":
            self.proto_type = "UDP"
            self.udp_payload = bytearray()
        elif self.snort_rule.source_port.lower() == "$http_ports" or self.snort_rule.dest_port.lower() == "$http_ports":
            self.proto_type = "HTTP"
            self.http_method = bytearray()
            self.http_uri = bytearray()
            self.http_header = list()
            self.http_body = bytearray()
            self.http_status = b"200"
        elif self.snort_rule.proto.lower() == "tcp":
            self.proto_type = "TCP"
            self.tcp_payload = bytearray()
        else:
            print("δ֪Э������\n")
            return False
        return True
             
    #��ȡSnort������Ϣ
    def snort_parser(self) -> dict:
        if self.init_snort_parser() == False:
            return None
        
        try:
            for option in self.snort_rule.options:
                option_name = option["name"]
                option_value = option["value"]
            
                #ȥ�������ַ�"
                if option_value != None:
                    option_value = option_value.strip("\"")
                
                #content��ǩ��ʾһ��content�εĿ�ʼ��ǰһ��content�ν���
                if option_name == "content":
                    if self.pcap_segment != None:
                        self.cover_pcap_wrapper(self.pcap_segment)
                    self.pcap_segment = self.parse_content_string(option_value)
                    
                #pcre��ǩ��ʾһ���εĿ�ʼ��ǰһ��pcre�ν���
                elif option_name == "pcre":
                    if self.pcap_segment != None:
                        self.cover_pcap_wrapper(self.pcap_segment)
                    option_value = re.match("/(.+)/",option_value)
                    if option_value == None:
                        print("pcre��ǩ��������\n")
                        return None
                    self.pcap_segment = bytearray(self.Xeger.xeger(option_value.group(1)),encoding="utf-8")
                
                #��sid��ǩ���������һ���ν���
                elif option_name == "sid":
                    self.sid = option_value
                    if self.pcap_segment != None:
                        self.cover_pcap_wrapper(self.pcap_segment)
                        
            
                #����ͨ��contentλ�����η�
                elif option_name.lower() == "offset":
                    self.index_beg = int(option_value)
                elif option_name.lower() == "depth":
                    self.index_end = int(option_value)
                elif option_name.lower() == "distance":
                    self.index_beg = self.pre_location + int(option_value)    
                elif option_name.lower() == "within":
                    self.index_end = self.pre_location + int(option_value)    
            
                #�������ݶδ�С
                elif option_name.lower() == "dsize":
                    if option_value.find("<>") != -1 :
                        self.body_min,self.body_max = option_value.split("<>")
                        self.body_min = int(self.body_min)
                        self.body_max = int(self.body_max)
                    elif option_value.find(">") != -1 :
                        self.body_min,_ = option_value.split(">")
                        self.body_min = int(self.body_min)
                    elif option_value.find("<") != -1 :
                        _,self.body_max = option_value.split("<")
                        self.body_max = int(self.body_max)
                    else:
                        self.body_max = self.body_min = int(option_value)
                
                #����httpЭ����ص�content���η�
                elif option_name.lower() == "http_method":
                    self.location_type = "http_method"
                elif option_name.lower() == "http_only_uri":
                    self.location_type = "http_uri"
                elif option_name.lower() == "http_header":
                    self.location_type = "http_header"
                elif option_name.lower() == "http_client_body":
                    self.location_type = "http_body"
                elif option_name.lower() == "http_stat_code":
                    self.location_type = "http_status"

                #����������
                elif option_name.lower() == "flow":
                    if option_value == "to_server,established":
                        self.flow_direct = "->"
                    else:
                        self.flow_direct = "<-"
                
                #����������
                elif option_name.lower() == "flowbits":
                    if option_value.startswith("set") or option_value.startswith("isset"):
                        action,psid = option_value.split(",")
                        self.parent_psid = psid.rsplit("_",1)[1]
                
                #�������账���content���η�
                elif option_name in ["nocase","msg","holetype-id","ruletype","rev"]:
                    continue
            
                #δ֪content���η�
                else:
                    print("��֧�ֵ�snort��ǩ:{}\n".format(option_name))
                    return None
                
        except Exception as error:
            print("����ʧ�� ������Ϣ:{}\n".format(str(error)))
            return None

        if self.proto_type == "HTTP":
            return {"parent_sid":self.parent_sid,"sid":self.sid,"proto_type":self.proto_type,"flow_direct":self.flow_direct,"paylod_size":{"body_min":self.body_min,"body_max":self.body_max},"payload_info":{"http_status":self.http_status,"http_method":self.http_method,"http_uri":self.http_uri,"http_header":self.http_header,"http_body":self.http_body}}
        elif self.proto_type == "TCP":
            return {"parent_sid":self.parent_sid,"sid":self.sid,"proto_type":self.proto_type,"flow_direct":self.flow_direct,"paylod_size":{"body_min":self.body_min,"body_max":self.body_max},"payload_info":{"tcp_payload":self.tcp_payload}}
        else:
            return {"parent_sid":self.parent_sid,"sid":self.sid,"proto_type":self.proto_type,"flow_direct":self.flow_direct,"paylod_size":{"body_min":self.body_min,"body_max":self.body_max},"payload_info":{"udp_payload":self.udp_payload}}

  

def parse_snort_rule_file(file_name:str,save_path:str)->list:
    #�洢��ʽ���򹹽��������Ϣ
    rule_links = dict()    
    #�洢��ʽ����ĸ�����SID
    rule_root = dict()

    rule_list = rule.parse_file(file_name)
    for snort_rule in rule_list:
        #�������򣬻�ȡ�������ݰ��غ�����Ĳ���
        payload_param = SnortRuleParser(snort_rule).snort_parser()
        
        if payload_param == None:
            print("�������ʧ�� ��������:{}\n".format(snort_rule.raw))
            continue
        
        sid =  payload_param["sid"]     
        psid = payload_param["parent_sid"]
        #�ж��Ƿ�������flowbits��ǣ�û����ֱ�ӳ��Թ������ݰ�
        if psid != None :
            #set��־
            if psid == sid:
                rule_root[sid] = psid
                rule_links[sid] = list()
                rule_links[sid].append(payload_param)
            #isset��־
            else:
                #���ǰ�ع����������Ƿ�ɹ�
                if rule_root.get(psid,None) != None:
                    rule_root[sid] = rule_root[psid]
                    rule_links[rule_root[sid]].append(payload_param)
                else:
                    print("����������ȱʧ ȱʧ�ڵ�SID:{}\n".format(psid))
        else:
            print("��ʼ������ SID:{}".format(payload_param["sid"]))
            pcap_builder(os.path.join(save_path,payload_param["sid"]+".pcap"),payload_param)

    #��ʽ��������ݰ������ӳٵ����
    for root_sid,payload_param_list in rule_links.items():
        if len(payload_param_list) == 1:
            print("��ʽ���������ȱʧ SID:{}".format(root_sid))
            continue
        print("��ʼ������ʽ�� SID:{}".format(root_sid))
        multi_pcap_builder(os.path.join(save_path,root_sid+".pcap"),payload_param_list)

rule_file_path = "D:\\QYWX\\WXWork\\1688856330430650\\Cache\\File\\2024-01\\Test.rules"
save_path = "D:\\QYWX\\WXWork\\1688856330430650\\Cache\\File\\2024-03\\PythonApplication1\\pcap"

parse_snort_rule_file(rule_file_path,save_path)