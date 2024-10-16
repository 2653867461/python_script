# -*- coding: utf-8 -*-
import os
import util
import json
from bindiff import BinDiff
from binexport import ProgramBinExport
import multiprocessing

diec_path = r"C:\Users\HP\Desktop\tool\die_win64_portable_3.10_x64\diec.exe"
upx_path = r"C:\Users\HP\Desktop\tool\upx-4.2.3-win64\upx.exe"


tag_class = set([".net","go","rust"])

def unpack_upx(file_path,upx_path = upx_path):
    result = util.PopenWarp(upx_path, "-d",file_path)
    if result == None:
        return False
    return result.find("Packed 1 file.") != -1

'''
{
    "detects": [
        {
            "filetype": "PE64",
            "offset": "0",
            "parentfilepart": "Header",
            "size": "3339264",
            "values": [
                {
                    "info": "",
                    "name": "Microsoft Linker",
                    "string": "Linker: Microsoft Linker(14.29.30153)",
                    "type": "Linker",
                    "version": "14.29.30153"
                },
                {
                    "info": "C++",
                    "name": "Microsoft Visual C/C++",
                    "string": "Compiler: Microsoft Visual C/C++(19.29.30153)[C++]",
                    "type": "Compiler",
                    "version": "19.29.30153"
                },
                {
                    "info": "Dynamic linking",
                    "name": "Microsoft C/C++ Runtime",
                    "string": "Library: Microsoft C/C++ Runtime[Dynamic linking]",
                    "type": "Library",
                    "version": ""
                },
                {
                    "info": "",
                    "name": "Qt",
                    "string": "Library: Qt(5.X)",
                    "type": "Library",
                    "version": "5.X"
                },
                {
                    "info": "",
                    "name": "Visual Studio",
                    "string": "Tool: Visual Studio(2019, v16.11)",
                    "type": "Tool",
                    "version": "2019, v16.11"
                },
                {
                    "info": "NRV,brute",
                    "name": "UPX",
                    "string": "Packer: UPX(4.23)[NRV,brute]",
                    "type": "Packer",
                    "version": "4.23"
                }
            ]
        }
    ]
}
'''
def GetCompilerInfo(file_path,diec_path = diec_path):
    result = util.PopenWarp(diec_path, "--json",file_path)
    return json.loads(result)["detects"][0] if result!=None else None

def AdjustPacker(file_path,diec_path=diec_path,try_unpack=True):
    unpack_class = {"upx":unpack_upx}
    result = {"file_type":None,"packer_type":None,"all_info":None,"unpack_result":False,"file_tag":None}

    packer_info = GetCompilerInfo(file_path,diec_path)
    if packer_info == None:
        return None
    
    result["file_type"] = packer_info.get("filetype",None)

    if result["file_type"] == None:
        return None

    for item in packer_info.get("values",[]):
        if item["type"].lower() == "packer":
            packer_name = item["name"]
            result["packer_type"] = packer_name.lower()
            if unpack_class.get(packer_name,None) != None and try_unpack and unpack_class[packer_name](file_path):
                result["unpack_result"] = True
        elif item["type"] == "Library":
            libiary_name = item["name"]
            for tag in tag_class:
                if libiary_name.find(tag) != -1:
                    result["file_tag"] = tag

    result["all_info"] = packer_info
    return result
    

def _AnalysicIdapro(file_path):
    ProgramBinExport.from_binary_file(file_path,override = False)

def AnalysicIdapro(file_path_list):
    process_pool = multiprocessing.Pool(processes=8)
    for file_path in file_path_list:
        process_pool.apply_async(_AnalysicIdapro,args=(file_path,))
    process_pool.close()
    process_pool.join()

def FormatFuncName(func_name:str):
    func_addr = int(func_name.split('_')[1],16)
    return "sub_" + hex(func_addr)[2:].upper()
            
   

def _CompareIdapro(primary_file,secondary_file,temp_path):
    diff_result = BinDiff.from_binary_files(primary_file,secondary_file,os.path.join(temp_path,"{}_{}.diff_result".format(os.path.basename(primary_file),os.path.basename(secondary_file))))
    func_match_result = list()
    result = False

    if float(diff_result.similarity) >= 0.8 and float(diff_result.confidence) >= 0.8:
        result = True
        for func_match in diff_result.function_matches:
            if func_match.name2.startswith("sub") and func_match.name1.startswith("sub") and float(func_match.similarity) >= 0.8 and float(func_match.confidence) >= 0.8:
                if len(diff_result.primary.fun_names[FormatFuncName(func_match.name1)].blocks) <= 3:
                    continue
                func_match_result.append({"name1":func_match.name1,"name2":func_match.name2,"algorithm":func_match.algorithm,"similarity":func_match.similarity,"confidence":func_match.confidence})
        
    return [os.path.basename(primary_file),os.path.basename(secondary_file),result,func_match_result]

def CompareIdapro(primary_file,secondary_file_list,temp_path):
    result = []
    process_pool = multiprocessing.Pool(processes=8)
    for file_path in secondary_file_list:
        result.append(process_pool.apply_async(_CompareIdapro,args=(primary_file,file_path,temp_path,)))
    process_pool.close()
    process_pool.join()

    return [item.get() for item in result if item and hasattr(item, 'get')]

def CommonFileType(compiler_type_l,compiler_type_r):
    if compiler_type_l["file_tag"] !=None and compiler_type_r["file_tag"]!=None:
        return compiler_type_l["file_tag"]==compiler_type_r["file_tag"]
    return True

