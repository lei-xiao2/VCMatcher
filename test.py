import os
from solc_version_switcher import *
import subprocess
import json
import re

directory = "./DeFiHackLabs/2024"
count = 0
tool_directory = "/mnt/sdb/home/xiaolei/VCmatcher"
address_file = "/mnt/sdb/home/xiaolei/VCmatcher/vulnerable_contracts/2024/address.txt"
prev_size = 0
flag = True
count = 0

#收集指定年份的vulnerable contracts的函数签名
def collect(year):
    global count
    global flag
    #先去拿到当前年份的address.txt得到“地址-事件”的字典
    address_event = {}

    address_file = "/mnt/sdb/home/xiaolei/VCmatcher/vulnerable_contracts/" + year + "/address.txt"
    with open(address_file, "r", encoding="utf-8") as f:
        lines = f.readlines()
        for line in lines:
            splits = line.split("|--|")
            event = splits[-1][:-1]
            end = splits[0].find("#code")
            if end == -1:
                address = splits[0][splits[0].find("0x"):]
            else:
                address = splits[0][splits[0].find("0x"):end]

            if address.startswith("0x"):
                address_event[address] = event
    
    root_dir = "./vulnerable_contracts/2024"
    root_dir = os.path.abspath(root_dir)
    dir_list = os.listdir(root_dir)
    os.chdir(root_dir)

    for item in dir_list:
        if os.path.isdir(item):
            contract_name = item.split("_")[-1]
            address = item.split("_")[0]
            event = address_event[address]
            flag = True
            traverse_vc(item, contract_name, event, os.path.abspath(item))
            if flag:
                count += 1
                print("========", contract_name, "=========")
            os.chdir(root_dir)




#遍历指定vulnerable_contract
def traverse_vc(directory, contract_name, event, project_dir):
    global count
    global tool_directory
    global prev_size
    global flag

    os.chdir(directory)
    files = os.listdir()

    for file in files:
        if os.path.isdir(file):
            traverse_vc(file, contract_name, event, project_dir)
            os.chdir(os.pardir)
        elif file.endswith(".sol"):
            with open(file, "r", encoding="utf-8") as f:
                content = f.read()
                regx = "contract " + contract_name + " "
                if re.search(regx, content):
                    flag = False
                    abspath = os.path.abspath(file)
                    path = abspath[len(project_dir) + 1:]
                    
                    cmd = "python3 tool.py -pd " + project_dir + " -s " + path + " -cnames " + contract_name + " -as" + " -event '" + event + "'"
                    prev = os.getcwd()
                    os.chdir(tool_directory)
                    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    with open("event_func_dir.json", "r", encoding="utf-8") as f:
                        if len(json.loads(f.read())) == prev_size + 1:
                            prev_size += 1
                        else:
                            print(cmd)

                    os.chdir(prev)
                    # if result.returncode != 0:
                    #     print(cmd)
            

#遍历DeFiHackLabs数据集
def traverse(directory):
    os.chdir(directory)
    files = os.listdir()

    for file in files:
        if os.path.isdir(file):
            traverse(file)
            os.chdir(os.pardir)
        elif file == "info.json":
            info = None
            with open(file, "r", encoding="utf-8") as f:
                info = json.loads(f.read())
            if info["vulnerable contract"]:
                dir_path, _ = os.path.split(os.path.abspath(file))
                event = os.path.split(dir_path)[-1]
                with open(address_file, "a+", encoding="utf-8") as f:
                    f.write(info["vulnerable contract"] + "|--|" + event + "\n")
            


if __name__ == "__main__":
    with open("event_func_dir.json", "r", encoding="utf-8") as f:
        print(len(json.loads(f.read())))
    # collect("2024")
    # print(count, "个项目没有找到主合约")