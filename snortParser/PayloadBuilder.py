#-*- coding:gbk -*-

from StreamBuilder import *

#根据给定的HTTP参数，构建TCP协议中的HTTP载荷，再调用TcpStreamBuilder建包
class HttpPcapBuilder():
    status_map_table = {
    "200":b"OK",
    "404":b"NOT FIND"
    }
    
    @staticmethod
    def GetHttpStatusDesc(StatusCode:str)->bytearray:
        return HttpPcapBuilder.status_map_table.get(StatusCode,b"UnKonwnHttpStatus")    
    
    def __init__(self,client_ip = "192.168.100.5",client_port = 6552,client_mac = "d4:68:ba:91:28:b6",server_ip = "192.168.100.125",server_port = 6558,server_mac = "d4:68:ba:91:28:b9",tcp_init_seq = 0,_default_uri = b"/",_default_method = b"GET",_default_status=b"200",_default_payload = b"TestTraffic"):

        self.default_http_uri = _default_uri
        self.default_http_method = _default_method
        self.default_http_status = _default_status

        self.default_send_payload = _default_payload
        self.default_recv_payload = _default_payload
        
        self.default_http_request_header = [[b"Connection",b"keep-alive"]]
        self.default_http_respond_header = [[b"Connection",b"keep-alive"]]
        
        self.default_http_request_data = self.HttpRequestHeaderBuilder(self.default_http_method,self.default_http_uri,self.default_http_request_header) + _default_payload
        self.default_http_respond_data = self.HttpRespondHeaderBuilder(self.default_http_status,self.default_http_respond_header) + _default_payload
        
        self.pcap_builder_client = TcpStreamBuilder(client_ip,client_port,client_mac,server_ip,server_port,server_mac,tcp_init_seq)

    #构建请求头
    def HttpRequestHeaderBuilder(self,http_method:bytearray,http_uri:bytearray,http_header:list)-> bytearray:
        http_request_header = http_method + b" " + http_uri + b" " + b"HTTP/1.1\r\n"
        for key,value in http_header:
            http_request_header += key + b": " + value + b"\r\n"
        http_request_header += b"\r\n"
        return http_request_header
        
    #构建响应头
    def HttpRespondHeaderBuilder(self,status:bytearray,http_header:list)-> bytearray:
        http_respond_header = b"HTTP/1.1" + b" " + status + b" " + HttpPcapBuilder.GetHttpStatusDesc(str(status,encoding="utf-8"))
        for key,value in http_header:
            http_respond_header += key + b":" + value + b"\r\n"
        http_respond_header += b"\r\n"
        return http_respond_header
    
    '''

    payload_param   由rule_parse模块snort_parser函数返回
    {
        "proto_type":self.proto_type
        "flow_direct":self.flow_direct
        "paylod_size":
            {
                "body_min":self.body_min
                "body_max":self.body_max
            }
        "payload":
            {
                "http_status":self.http_status
                "http_method":self.http_method
                "http_uri":self.http_uri
                "http_header":self.http_header
                "http_body":self.http_body
             }
    }
    '''
    
    #通过给定参数构建HTTP请求数据
    def parse_http_respond_payload_param(self,payload_param:dict):
        data = self.default_recv_payload if len(payload_param["payload_info"]["http_body"]) == 0 else payload_param["payload_info"]["http_body"] 
        http_status = payload_param["payload_info"]["http_status"] if len(payload_param["payload_info"]["http_status"]) != 0 else self.default_http_status
        http_header = payload_param["payload_info"]["http_header"] if len(payload_param["payload_info"]["http_header"]) != 0 else self.default_http_respond_header
        return self.HttpRespondHeaderBuilder(http_status,http_header) + data
        
    
    #通过给定参数构建HTTP返回数据
    def parse_http_request_payload_param(self,payload_param:dict):
        data = bytearray()
        http_uri =self.default_http_uri if len(payload_param["payload_info"]["http_uri"]) == 0 else payload_param["payload_info"]["http_uri"]
        if http_uri[0] != b'/':
            http_uri = b'/' + payload_param["payload_info"]["http_uri"]
            
        http_method = self.default_http_method if len(payload_param["payload_info"]["http_method"]) == 0 else payload_param["payload_info"]["http_method"]
        http_header = payload_param["payload_info"]["http_header"] if len(payload_param["payload_info"]["http_header"]) != 0 else self.default_http_request_header
        if payload_param["payload_info"]["http_method"] == b"POST" or len(payload_param["payload_info"]["http_body"]) != 0:
            data = self.default_send_payload if len(payload_param["payload_info"]["http_body"]) == 0 else payload_param["payload_info"]["http_body"] 
        
        return self.HttpRequestHeaderBuilder(http_method,http_uri,http_header) + data


    def parse_payload_param(self,payload_param:dict):
        if payload_param["flow_direct"] =="->":
            http_data = self.parse_http_request_payload_param(payload_param)
        else:
            http_data = self.parse_http_respond_payload_param(payload_param)
        #数据包大小检查

        dsize_min = payload_param["paylod_size"]["body_min"]
        dsize_max = payload_param["paylod_size"]["body_max"]
        cur_size = len(http_data)
        
        if dsize_min != 0:
            if cur_size < dsize_min:
                http_data += bytearray(dsize_min - cur_size)
        if dsize_max != 0 :
            if cur_size > dsize_max:
                print("数据包大小参数有误")
                http_data = None
            
        return http_data

    def pcap_builder(self,file_name:str,payload_param:dict) -> bool:
        payload = self.parse_payload_param(payload_param)
        if payload != None:
            if payload_param["flow_direct"] == "->":
                self.pcap_builder_client.pcap_builder(payload,self.default_http_respond_data)
            else:
                self.pcap_builder_client.pcap_builder(self.default_http_request_data,payload)
            self.pcap_builder_client.pcap_writer(file_name)
            return True
        return False
    
    def multi_pcap_builder(self,file_name:str,payload_param_list:list) -> bool:
        self.pcap_builder_client.handshake_builder()
        for payload_param in payload_param_list:
            payload = self.parse_payload_param(payload_param)
            if payload != None:
                if payload_param["flow_direct"] == "->":
                    self.pcap_builder_client.pcap_builder(payload,self.default_http_respond_data,False)
                else:
                    self.pcap_builder_client.pcap_builder(self.default_http_request_data,payload,False)
            else:
                return False
        self.pcap_builder_client.pcap_writer(file_name)
        return True
    
class TcpPcapBuilder:
    def __init__(self,client_ip = "192.168.100.5",client_port = 6552,client_mac = "d4:68:ba:91:28:b6",server_ip = "192.168.100.125",server_port = 6558,server_mac = "d4:68:ba:91:28:b9",tcp_init_seq = 0,default_send_payload = b"TestTraffic_HelloServer",default_recv_payload = b"TestTraffic_HelloClient"):
        self.pcap_builder_client = TcpStreamBuilder(client_ip,client_port,client_mac,server_ip,server_port,server_mac,tcp_init_seq)
        self.default_send_payload = default_send_payload
        self.default_recv_payload = default_recv_payload
        
    def parse_payload_param(self,payload_param:dict):
        payload = payload_param["payload_info"]["tcp_payload"]
        
        dsize_min = payload_param["paylod_size"]["body_min"]
        dsize_max = payload_param["paylod_size"]["body_max"]
        cur_size = len(payload)
        if dsize_min != 0:
            if cur_size < dsize_min:
                payload += bytearray(dsize_min - cur_size)
        if dsize_max != 0 :
            if cur_size > dsize_max:
                print("数据包大小参数有误")
                payload = None
                
        return payload
    
    def pcap_builder(self,file_name:str,payload_param:dict)->bool:
        payload = self.parse_payload_param(payload_param)
        if payload == None:
            return False
        
        if payload_param["flow_direct"] == "->":
            self.pcap_builder_client.pcap_builder(payload,self.default_recv_payload)
        else:
            self.pcap_builder_client.pcap_builder(self.default_send_payload,payload)
        
        self.pcap_builder_client.pcap_writer(file_name)
        return True
        
    def multi_pcap_builder(self,file_name:str,payload_param_list:list):
        self.pcap_builder_client.handshake_builder()
        
        for payload_param in payload_param_list:
            payload = self.parse_payload_param(payload_param)
            
            if payload == None:
                return False

            if payload_param["flow_direct"] == "->":
                self.pcap_builder_client.pcap_builder(payload,self.default_recv_payload,False)
            else:
                self.pcap_builder_client.pcap_builder(self.default_send_payload,payload,False)
        
        self.pcap_builder_client.pcap_writer(file_name)
        return True 

class UdpPcapBuilder:
    def __init__(self,client_ip = "192.168.100.5",client_port = 6552,client_mac = "d4:68:ba:91:28:b6",server_ip = "192.168.100.125",server_port = 6558,server_mac = "d4:68:ba:91:28:b9"):
        self.pcap_builder_client = UdpStreamBuilder(client_ip,client_port,client_mac,server_ip,server_port,server_mac)
        self.default_send_payload = b"Hello Server"
        self.default_recv_payload = b"Hello Client"
        
    def parse_payload_param(self,payload_param:dict):
        payload = payload_param["payload_info"]["udp_payload"]
        
        dsize_min = payload_param["paylod_size"]["body_min"]
        dsize_max = payload_param["paylod_size"]["body_max"]
        cur_size = len(payload)
        if dsize_min != 0:
            if cur_size < dsize_min:
                payload += bytearray(dsize_min - cur_size)
        if dsize_max != 0 :
            if cur_size > dsize_max:
                print("数据包大小参数有误")
                payload = None
                
        return payload
    
    def pcap_builder(self,file_name:str,payload_param:dict)->bool:
        payload = self.parse_payload_param(payload_param)
        if payload == None:
            return False
        
        if payload_param["flow_direct"] == "->":
            self.pcap_builder_client.pcap_builder(payload,self.default_recv_payload)
        else:
            self.pcap_builder_client.pcap_builder(self.default_send_payload,payload)
        
        self.pcap_builder_client.pcap_writer(file_name)
        return True
    
    def multi_pcap_builder(self,file_name:str,payload_param_list:list):
        
        for payload_param in payload_param_list:
            payload = self.parse_payload_param(payload_param)
            
            if payload == None:
                return False

            if payload_param["flow_direct"] == "->":
                self.pcap_builder_client.pcap_builder(payload,self.default_recv_payload)
            else:
                self.pcap_builder_client.pcap_builder(self.default_send_payload,payload)
        
        self.pcap_builder_client.pcap_writer(file_name)
        return True 

def pcap_builder(file_name:str,payload_param:dict):
    proto = payload_param["proto_type"]
    if proto == "HTTP":
        HttpPcapBuilder().pcap_builder(file_name,payload_param)
    elif proto == "TCP":
        TcpPcapBuilder().pcap_builder(file_name,payload_param)
    elif proto == "UDP":
        UdpPcapBuilder().pcap_builder(file_name,payload_param)
        
def multi_pcap_builder(file_name:str,payload_param_list:list):
    proto = payload_param_list[0]["proto_type"]
    if proto == "HTTP":
        HttpPcapBuilder().multi_pcap_builder(file_name,payload_param_list)
    elif proto == "TCP":
        TcpPcapBuilder().multi_pcap_builder(file_name,payload_param_list)
    elif proto == "UDP":
        UdpPcapBuilder().multi_pcap_builder(file_name,payload_param_list)

