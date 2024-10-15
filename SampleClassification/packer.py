
import util
import json


diec_path = r"C:\Users\26538\Desktop\tools\die_win64_portable_3.10_x64\diec.exe"
upx_path = r"C:\Users\26538\Desktop\tools\upx-4.2.3-win64\upx.exe"


tag_class = set(["mfc"])

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
    unpack_class = {"UPX":unpack_upx}

    result = {"file_type":None,"packer_type":None,"compiler_type":[],"unpack_result":False}

    packer_info = GetCompilerInfo(file_path,diec_path)
    if packer_info == None:
        return None
    
    result["file_type"] = packer_info["filetype"]

    for item in packer_info["values"]:
        if item["type"] == "Packer":
            packer_name = item["name"]
            result["packer_type"] = packer_name
            if unpack_class.get(packer_name,None) != None and try_unpack and unpack_class[packer_name](file_path):
                result["unpack_result"] = True

    result["compiler_type"] = result
    return result
    
def CommonFileType(compiler_type_l,compiler_type_r):
    return True



