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
        
    #解析content标签
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
    src_bytes:待写入的数据
    dst_bytes:现有数据体内容
    '''
    def cover_pcap(self,src_bytes,dst_bytes):
        #没有位置标签限制时,默认写在前一个模式串后面
        if self.index_beg == 0:
            self.index_beg = len(dst_bytes) 
            
        if self.index_end == 0:    
            self.index_end = self.index_beg + len(src_bytes)
        
        dst_bytes[self.index_beg:self.index_end] = src_bytes 

        self.index_beg = 0
        self.index_end = 0
        self.pre_location = self.index_end     
        
        return dst_bytes

    #保存前一个段解析的数据
    def cover_pcap_wrapper(self,src_bytes):
        #非HTTP协议
        if self.location_type == None and self.proto_type != "HTTP":
            if self.proto_type == "TCP":
                self.tcp_payload = self.cover_pcap(src_bytes,self.tcp_payload)
            else:
                self.udp_payload = self.cover_pcap(src_bytes,self.udp_payload)
        
        #HTTP协议
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
        #缺省处理
        elif self.location_type == "http_body" or self.location_type == None:
            self.http_body = self.cover_pcap(src_bytes,self.http_body)
        else:
            print("未知位置参数\n")
        self.location_type = None
        self.pcap_segment = None
    
    #确定协议类型，初始化相关变量
    def init_snort_parser(self):
        self.body_min = 0
        self.body_max = 0
        
        self.sid = None
        self.set_sid = None
        self.isset_sid = None
        
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
            print("未知协议类型\n")
            return False
        return True
             
    #提取Snort规则信息
    def snort_parser(self) -> dict:
        if self.init_snort_parser() == False:
            return None
        
        try:
            for option in self.snort_rule.options:
                option_name = option["name"]
                option_value = option["value"]
            
                #去除干扰字符"
                if option_value != None:
                    option_value = option_value.strip("\"")
                
                #content标签表示一个content段的开始和前一个content段结束
                if option_name == "content":
                    if self.pcap_segment != None:
                        self.cover_pcap_wrapper(self.pcap_segment)
                    self.pcap_segment = self.parse_content_string(option_value)
                    
                #pcre标签表示一个段的开始和前一个pcre段结束
                elif option_name == "pcre":
                    if self.pcap_segment != None:
                        self.cover_pcap_wrapper(self.pcap_segment)
                    option_value = re.match("/(.+)/",option_value)
                    if option_value == None:
                        print("pcre标签解析错误\n")
                        return None
                    self.pcap_segment = bytearray(self.Xeger.xeger(option_value.group(1)),encoding="utf-8")
                
                #以sid标签代表这最后一个段结束
                elif option_name == "sid":
                    self.sid = option_value
                    if self.pcap_segment != None:
                        self.cover_pcap_wrapper(self.pcap_segment)
                        
            
                #处理通用content位置修饰符
                elif option_name.lower() == "offset":
                    self.index_beg = int(option_value)
                elif option_name.lower() == "depth":
                    self.index_end = int(option_value)
                elif option_name.lower() == "distance":
                    self.index_beg = self.pre_location + int(option_value)    
                elif option_name.lower() == "within":
                    self.index_end = self.pre_location + int(option_value)    
            
                #解析数据段大小
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
                
                #处理http协议相关的content修饰符
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

                #解析流方向
                elif option_name.lower() == "flow":
                    if option_value == "to_server,established":
                        self.flow_direct = "->"
                    else:
                        self.flow_direct = "<-"
                
                #解析规则流
                elif option_name.lower() == "flowbits":
                    if option_value.startswith("set"):
                        action,psid = option_value.split(",")
                        self.set_sid = psid.rsplit("_",1)[1]
                        
                    elif option_value.startswith("isset"):
                        action,psid = option_value.split(",")
                        self.isset_sid = psid.rsplit("_",1)[1]
                
                #跳过无需处理的content修饰符
                elif option_name in ["nocase","msg","holetype-id","ruletype","rev"]:
                    continue
            
                #未知content修饰符
                else:
                    print("不支持的snort标签:{}\n".format(option_name))
                    return None
                
        except Exception as error:
            print("解析失败 错误信息:{}\n".format(str(error)))
            return None

        if self.proto_type == "HTTP":
            return {"set_sid":self.set_sid,"isset_sid":self.isset_sid,"sid":self.sid,"proto_type":self.proto_type,"flow_direct":self.flow_direct,"paylod_size":{"body_min":self.body_min,"body_max":self.body_max},"payload_info":{"http_status":self.http_status,"http_method":self.http_method,"http_uri":self.http_uri,"http_header":self.http_header,"http_body":self.http_body}}
        elif self.proto_type == "TCP":
            return {"set_sid":self.set_sid,"isset_sid":self.isset_sid,"sid":self.sid,"proto_type":self.proto_type,"flow_direct":self.flow_direct,"paylod_size":{"body_min":self.body_min,"body_max":self.body_max},"payload_info":{"tcp_payload":self.tcp_payload}}
        else:
            return {"set_sid":self.set_sid,"isset_sid":self.isset_sid,"sid":self.sid,"proto_type":self.proto_type,"flow_direct":self.flow_direct,"paylod_size":{"body_min":self.body_min,"body_max":self.body_max},"payload_info":{"udp_payload":self.udp_payload}}

  

def parse_snort_rule_file(file_name:str,save_path:str)->list:
    #存储流式规则构建包相关信息
    rule_links = dict()    
    #存储流式规则的根规则SID
    rule_root = dict()

    rule_list = rule.parse_file(file_name)
    for snort_rule in rule_list:
        #解析规则，获取构建数据包载荷所需的参数
        payload_param = SnortRuleParser(snort_rule).snort_parser()
        
        if payload_param == None:
            print("规则解析失败 规则内容:{}\n".format(snort_rule.raw))
            continue
        
        sid =  payload_param["sid"]     
        set_sid = payload_param["set_sid"]
        isset_sid = payload_param["isset_sid"]
        
        #判断是否设置了flowbits标记，没有则直接尝试构建数据包

        #set标志
        if isset_sid == None and set_sid != None:
            rule_root[set_sid] = set_sid
            rule_links[set_sid] = list()
            rule_links[set_sid].append(payload_param)
        #isset标志
        elif isset_sid != None:
            #检测前沿规则规则解析是否成功
            if rule_root.get(isset_sid,None) != None:
                rule_root[sid] = rule_root[isset_sid]
                rule_links[rule_root[sid]].append(payload_param)
            else:
                print("规则链存在缺失 缺失节点SID:{}\n".format(isset_sid))
        else:
            print("开始构建包 SID:{}".format(payload_param["sid"]))
            pcap_builder(os.path.join(save_path,payload_param["sid"]+".pcap"),payload_param)

    #流式规则的数据包构建延迟到最后
    for root_sid,payload_param_list in rule_links.items():
        name = str(max([int(sid) for sid,psid in rule_root.items() if psid==root_sid])) + ".pcap"
        if len(payload_param_list) == 1:
            print("流式规则规则链缺失 SID:{}".format(root_sid))
            continue
        print("开始构建流式包 SID:{}".format(root_sid))
        multi_pcap_builder(os.path.join(save_path,name),payload_param_list)

rule_file_path = ""
save_path = ""

parse_snort_rule_file(rule_file_path,save_path)
