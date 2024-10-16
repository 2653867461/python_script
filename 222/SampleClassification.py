# -*- coding: utf-8 -*-

#pip install python-bindiff  python-magic python-magic-bin

import os
import json

import util
import packer

def FormatFuncName(func_name:str):
    func_addr = int(func_name.split('_')[1],16)
    return "sub_" + hex(func_addr)[2:].upper()
            
        
def GetFileCollection(root_path,result_path,isCheck = True):
    file_type_list = ["pe","elf","so"]
    file_collection = list()
    virus_info = dict()

    for file_name in os.listdir(root_path):
        file_path = os.path.join(root_path,file_name)
        
        if os.path.isdir(file_path):
            continue
        
        if file_name.endswith("BinExport") or file_name.endswith("diff_result") or file_name.endswith("json"):
            continue

        file_hash = util.CalFileMd5(file_path)
        if file_hash == None :
            continue

        if file_name != file_hash:
            util.RenameFileWarp(file_path,os.path.join(root_path,file_hash))
            file_path = os.path.join(root_path,file_hash)      

        file_size = os.path.getsize(file_path)

        if isCheck == True:
            compiler_info = packer.AdjustPacker(file_path)
            if compiler_info == None :
                continue

            file_type = compiler_info["file_type"].lower()
            if not any([file_type.find(type_name)!=-1 for type_name in file_type_list]):
                continue

            if compiler_info["unpack_result"] == True:
                compiler_info = packer.AdjustPacker(file_path)
                if compiler_info == None:
                    continue

            if compiler_info["packer_type"] == None:  
                file_collection.append({"file_hash":file_hash,"file_size":file_size})

            virus_info[file_hash] = compiler_info
        else:
            file_collection.append({"file_hash":file_hash,"file_size":file_size})
            
    if isCheck == True:
        with open(os.path.join(result_path,"PackerResult.json"),mode="w",encoding="utf-8") as fp:
            json.dump(virus_info,fp,sort_keys = True,indent = 4)
    
    return [file_info["file_hash"] for file_info in sorted(file_collection,key=lambda info:info["file_size"])],virus_info

def SampleClassification(root_path,result_path,temp_path,isCheck=True):
    classification_collection = dict()
    forward_class_result = dict()
    class_result = list()
    matched_hash = list()

    util.CheckPathExists(result_path)
    util.CheckPathExists(temp_path)
    
    file_collection,virus_info = GetFileCollection(root_path,result_path,isCheck)
    primary_maxinum = len(file_collection)
    print("样本总数{}".format(primary_maxinum))
    
    packer.AnalysicIdapro([os.path.join(root_path,file_hash) for file_hash in file_collection])

    for primary_index in range(primary_maxinum):
        wait_process_path = []
        primary_hash = file_collection[primary_index]
        primary_path = os.path.join(root_path,primary_hash)

        if primary_hash in matched_hash:
            continue

        for secondary_index in range(primary_index + 1,primary_maxinum):

            secondary_hash = file_collection[secondary_index]
            secondary_path = os.path.join(root_path,secondary_hash)
            
            if secondary_hash in matched_hash:
                continue

            if isCheck == True:
                if packer.CommonFileType(virus_info[primary_hash],virus_info[secondary_hash]):
                    wait_process_path.append(secondary_path)
            else:
                wait_process_path.append(secondary_path)

        result_list = packer.CompareIdapro(primary_path,wait_process_path,temp_path)
        for primary_path,secondary_path,result,func_match_result in result_list:
            if result:
                matched_hash.append(secondary_hash) 
                classification_collection["{}_{}".format(primary_hash,secondary_hash)] = func_match_result

                if not primary_hash in forward_class_result:
                    forward_class_result[primary_hash] = list()
                forward_class_result[primary_hash].append(secondary_hash)
            
               
    ##数据提纯
    for primary_hash,secondary_hash_list in forward_class_result.items():
        trait = set()
        func_trait = dict()
        
        collect_path = os.path.join(result_path,primary_hash)
        util.CheckPathExists(collect_path)
        util.CopyFileWarp(os.path.join(root_path,primary_hash),os.path.join(collect_path,primary_hash))

        for secondary_hash in secondary_hash_list:
            name_1_list = [match_result["name1"] for match_result in classification_collection["{}_{}".format(primary_hash,secondary_hash)]]
            if len(trait) == 0:
                trait = set(name_1_list)
            else:
                trait = trait & set(name_1_list)
                
            util.CopyFileWarp(os.path.join(root_path,secondary_hash),os.path.join(collect_path,secondary_hash))


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

if __name__ == "__main__":
    virus_root_path = input("输入待分类样本路径\n")
    SampleClassification(virus_root_path,os.path.join(virus_root_path,"result"),os.path.join(virus_root_path,"temp"))
