# -*- coding: gbk -*-

#pip install python-bindiff  python-magic python-magic-bin

'''
基于IDA,Bindiff的样本分类和代码特征归类脚本

需要配置环境变量
BINDIFF_PATH：C:\Program Files\BinDiff\bin
IDA_PATH：C:\Users\Sangfor\Desktop\tool\IDA_Pro_v7.5_Portable

'''

from bindiff import BinDiff
from binexport import ProgramBinExport
import os
import json
import asyncio

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
            virus_info[file_hash] = compiler_info["compiler_type"]
        else:
            file_collection.append({"file_hash":file_hash,"file_size":file_size})
            
    if isCheck == True:
        with open(os.path.join(result_path,"PackerResult.json"),mode="w",encoding="utf-8") as fp:
            json.dump(virus_info,fp,sort_keys = True,indent = 4)
    
    return [file_info["file_hash"] for file_info in sorted(file_collection,key=lambda info:info["file_size"])],virus_info

async def analysic_idapro(file_path_list):
    async def AnalysicIdapro(file_path):
        ProgramBinExport.from_binary_file(file_path,override = False)
    
    coroutine_list = []
    for file_path in file_path_list:
        coroutine_list.append(asyncio.create_task(AnalysicIdapro(file_path)))

    await asyncio.gather(*coroutine_list)

def SampleClassification(root_path,result_path,temp_path):
    classification_collection = dict()
    forward_class_result = dict()
    class_result = list()
    virus_matched = list()    

    util.CheckPathExists(result_path)
    util.CheckPathExists(temp_path)
    
    file_collection,virus_info = GetFileCollection(root_path,result_path)
    primary_maxinum = len(file_collection)
    print("样本总数{}".format(primary_maxinum))
    
    analysic_idapro([os.path.join(root_path,file_hash) for file_hash in file_collection])

    diff_times = 0
    for primary_index in range(primary_maxinum):
        for secondary_index in range(primary_index + 1,primary_maxinum):
            diff_result = None
            
            primary_hash = file_collection[primary_index]
            secondary_hash = file_collection[secondary_index]

            primary_path = os.path.join(root_path,primary_hash)
            secondary_path = os.path.join(root_path,secondary_hash)
            
            if primary_hash in virus_matched or secondary_hash in virus_matched or packer.CommonFileType(virus_info[primary_hash],virus_info[secondary_hash])==False:
                continue
            
            diff_times = diff_times + 1
            print("{} vs {}\t{}".format(primary_hash,secondary_hash,diff_times))
            
            diff_result = BinDiff.from_binary_files(primary_path,secondary_path,os.path.join(temp_path,"{}_{}.diff_result".format(primary_hash,secondary_hash)))
            if diff_result == None:
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


virus_root_path = input("输入待分类样本路径\n")
SampleClassification(virus_root_path,os.path.join(virus_root_path,"result"),os.path.join(virus_root_path,"temp"))
