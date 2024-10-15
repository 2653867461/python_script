import hashlib
import os
import subprocess
import shutil


def PopenWarp(file_path,*args,**kwargs):
    output = None
    try:   
        proc = subprocess.Popen(list(file_path, *args, **kwargs), stdout=subprocess.PIPE,encoding="utf-8")
        output = str(proc.communicate()[0]).lower()
    except Exception as error:
        print(error)
    return output

def CopyFileWarp(src_path,dst_path):
    if src_path != dst_path and os.access(src_path,os.R_OK) and os.access(os.path.dirname(dst_path),os.W_OK):
        shutil.copyfile(src_path,dst_path)


def RenameFileWarp(old_name,new_name):
    if old_name != new_name  and os.access(old_name,os.W_OK):
        DeleteFileWarp(new_name)

        if os.access(os.path.dirname(new_name),os.W_OK):
            os.rename(old_name,new_name)

def DeleteFileWarp(file_path):
    if os.access(file_path,os.W_OK):
        os.remove(file_path)

def CheckPathExists(file_path):
    if os.path.exists(file_path) == False and os.access(file_path,os.W_OK):
        os.mkdir(file_path)

def CalFileMd5(file_path):
    hash = None
    if not os.access(file_path,os.W_OK):
        return hash
    
    with open(file_path,'rb') as fp:
        hash_lib = hashlib.md5()
        hash_lib = hash_lib.update(fp.read())
        hash = hash_lib.hexdigest() 
    return hash
