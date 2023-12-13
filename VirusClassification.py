# -*- coding: gbk -*-

'''
����IDA,Bindiff����������ʹ�����������ű�

��Ҫ���û�������
BINDIFF_PATH��C:\Program Files\BinDiff\bin
IDA_PATH��C:\Users\Sangfor\Desktop\tool\IDA_Pro_v7.5_Portable

�޸�diec_path����Ϊdiec·��

binexport�����Ż��޸�

'''

from bindiff import BinDiff
from binexport import ProgramBinExport
import hashlib
import os
import json
import subprocess
import magic
import shutil

diec_path = "H:\\tool\\DetectItEasy 3.01\\DetectItEasy 3.01\\diec.exe"

packer_class = set(["upx","asprotect","nspack","aspack","telock","armadillo","pecompact","nullsoft","vmprotect","safengine shielden"])
tag_class = set(["mfc"])

def CalFileMd5(file_path):
    hash = None
    try:
        with open(file_path,'rb') as fp:
            md5_obj = hashlib.md5()
            md5_obj.update(fp.read())
            hash = md5_obj.hexdigest()
    except Exception as error:
        print(error)
    return hash

def GetSoftwareCompilerInfo(software_path):
    output = None
    try:   
        proc = subprocess.Popen([diec_path, os.path.join(software_path)], stdout=subprocess.PIPE)
        output = str(proc.communicate()[0]).lower()
    except Exception as error:
        print(error)
    return output

def FormatFuncName(func_name:str):
    result = list()
    func_addr = int(func_name.split('_')[1],16)
    return "sub_" + hex(func_addr)[2:].upper()
            
def CheckPathExists(path):
    if os.path.exists(path) == False:
        os.mkdir(path)
        
def CopyFile(src_path,dst_path):
    if src_path != dst_path and os.path.exists(src_path) and os.path.exists(dst_path):
        try:
            shutil.copyfile(src_path,dst_path)
        except :
            pass

def RenameFile(old_name,new_name):
    if old_name != new_name and os.path.exists(old_name) == True and os.path.exists(new_name) == False:
        try:
            os.rename(old_name,new_name)
        except:
            pass
        

def GetFileCollection(root_path,result_path,isCheck = True):
    file_collection = list()
    virus_info = dict()

    for file_name in os.listdir(root_path):
        file_path = os.path.join(root_path,file_name)
        
        if not os.path.isfile(file_path):
            continue
        
        if file_name.endswith("BinExport") or file_name.endswith("diff_result") or file_name.endswith("json"):
            continue

        file_hash = CalFileMd5(file_path)
        if file_hash == None :
            continue
        
        file_size = os.path.getsize(file_path)

        if isCheck == True:
            if magic.from_file(file_path).find("PE") == -1:
                virus_info[file_hash] = "InvalidPe"
                os.remove(file_path)
                continue

            if file_name != file_hash:
                if os.path.exists(os.path.join(root_path,file_hash)) == True:
                    os.remove(os.path.join(root_path,file_hash))
                os.rename(file_path,os.path.join(root_path,file_hash))
                
            compiler_info = GetSoftwareCompilerInfo(os.path.join(root_path,file_hash))
        
            #�жϼӿ����
            isPack = False
            for pack_str in packer_class:
                if compiler_info.find(pack_str) != -1:
                    virus_info[file_hash] = pack_str
                    if os.path.exists(os.path.join(root_path,file_hash)) == True:
                        os.remove(os.path.join(root_path,file_hash))
                    isPack = True
                
            #�ж�����ı�����
            for tag in tag_class:
                if compiler_info.find(tag) != -1:
                    virus_info[file_hash] = tag
                
            if isPack == False:  
                file_collection.append({"file_hash":file_hash,"file_size":file_size})
        else:
            file_collection.append({"file_hash":file_hash,"file_size":file_size})
            
    if isCheck == True:
        with open(os.path.join(result_path,"PackerResult.json"),mode="w") as fp:
            json.dump(virus_info,fp,sort_keys = True,indent = 4)
    
    return [file_info["file_hash"] for file_info in sorted(file_collection,key=lambda info:info["file_size"])]


def SampleClassification(root_path,result_path,temp_path):
    classification_collection = dict()
    forward_class_result = dict()
    class_result = list()
    virus_matched = list()    

    CheckPathExists(result_path)
    CheckPathExists(temp_path)
    
    file_collection = GetFileCollection(root_path,result_path)
    primary_maxinum = len(file_collection)
    print("��������{}".format(primary_maxinum))
    
    diff_times = 0
    for primary_index in range(primary_maxinum):
        for secondary_index in range(primary_index + 1,primary_maxinum):
            diff_result = None
            
            primary_hash = file_collection[primary_index]
            secondary_hash = file_collection[secondary_index]

            primary_path = os.path.join(root_path,primary_hash)
            secondary_path = os.path.join(root_path,secondary_hash)
            
            if primary_hash in virus_matched or secondary_hash in virus_matched:
                continue
            
            primary_size = os.path.getsize(primary_path)
            secondary_size = os.path.getsize(secondary_path)
            
            max = 0
            min = 0
            if primary_size > secondary_size:
                max = primary_size
                min = secondary_size
            else:
                max = secondary_size
                min = primary_size
            
            if max - min > 2 * 1024 * 1024:
                continue
            
            diff_times = diff_times + 1
            print("{} vs {}\t{}".format(primary_hash,secondary_hash,diff_times))
            
            diff_result = BinDiff.from_binary_files(primary_path,secondary_path,temp_path)

            if diff_result == None:
                if os.path.exists(secondary_path + ".BinExport") == True:
                    os.remove(secondary_path + ".BinExport")
                virus_matched.append(secondary_hash)
                continue
            
            if float(diff_result.similarity) >= 0.8 and float(diff_result.confidence) >= 0.8:
                func_match_result = list()
                virus_matched.append(secondary_hash)
                
                for func_match in diff_result.function_matches:
                    if func_match.name2.startswith("sub") and func_match.name1.startswith("sub") and float(func_match.similarity) >= 0.8 and float(func_match.confidence) >= 0.8:
                        if len(diff_result.primary.fun_names[FormatFuncName(func_match.name1)].blocks) <= 3:
                            continue
                        func_match_result.append({"name1":func_match.name1,"name2":func_match.name2,"algorithm":func_match.algorithm,"similarity":func_match.similarity,"confidence":func_match.confidence})
                
                classification_collection["{}_{}".format(primary_hash,secondary_hash)] = func_match_result

                if not primary_hash in forward_class_result:
                    forward_class_result[primary_hash] = list()
                forward_class_result[primary_hash].append(secondary_hash)   
               
    ##�����ᴿ
    for primary_hash,secondary_hash_list in forward_class_result.items():
        trait = set()
        func_trait = dict()
        
        collect_path = os.path.join(result_path,primary_hash)
        CheckPathExists(collect_path)

        CopyFile(os.path.join(root_path,primary_hash),os.path.join(collect_path,primary_hash))

        for secondary_hash in secondary_hash_list:
            name_1_list = [match_result["name1"] for match_result in classification_collection["{}_{}".format(primary_hash,secondary_hash)]]
            if len(trait) == 0:
                trait = set(name_1_list)
            else:
                trait = trait & set(name_1_list)
                
            CopyFile(os.path.join(root_path,secondary_hash),os.path.join(collect_path,secondary_hash))


        for primary_trait in trait:
            func_trait[primary_trait] = dict()
            for secondary_hash in secondary_hash_list:
                for secondary_trait in classification_collection["{}_{}".format(primary_hash,secondary_hash)]:
                    if secondary_trait["name1"] == primary_trait:
                        func_trait[primary_trait][secondary_hash] = secondary_trait["name2"]
                
        secondary_hash_list.append(primary_hash)
        class_result.append({"primary_hash":primary_hash,"hash_list":secondary_hash_list,"func_trait":func_trait})
    

    with open(os.path.join(result_path,"ClassResult.json"),mode="w",encoding = "utf-8") as fp:
        json.dump(class_result,fp,sort_keys = True,indent = 4)


virus_root_path = input("�������������·��\n")
SampleClassification(virus_root_path,os.path.join(virus_root_path,"result"),os.path.join(virus_root_path,"temp"))

