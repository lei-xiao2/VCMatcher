import argparse
import json
import os
from time import sleep

import requests as rq


def make_dir(path):
    folders = []
    while not os.path.isdir(path):
        path, suffix = os.path.split(path)
        folders.append(suffix)
    for folder in folders[::-1]:
        path = os.path.join(path, folder)
        os.mkdir(path)


def is_json(myjson):
    try:
        json_object = json.loads(myjson)
    except ValueError:
        return False
    return True


send_headers = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
    "Connection": "keep-alive",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9",
}


def crawl_contract(rootdir, c_address, platform):
    root = rootdir
    contract_address = c_address
    eth_api_key = "GSR575A8XAYTWVZ9TK3H9VTS81HRQ6YRWV"
    bsc_api_key = "31CBGZX2T2D6GH7GRKAMSJA11Z18CQ8BQ4"
    arbi_api_key = "QIVHJEA4RFCKSJQFMT7GYUENHYP42K5M2N"
    base_api_key = "YKJI41WURZFRYMAVM1BZK1ITHIYI1AD78Q"

    if not platform:
        api_key = eth_api_key
    elif "bsc" in platform:
        api_key = bsc_api_key
    elif "eth" in platform:
        api_key = eth_api_key
    elif "arbi" in platform:
        api_key = arbi_api_key
    elif "base" in platform:
        api_key = base_api_key
    else:
        api_key = eth_api_key

    curl_link = (
        "https://api." + (platform if platform else "etherscan.io") + "/api?module=contract&action=getsourcecode&address="
        + c_address
        # + "&apikey=HPB1MEZ5YEJ7GZJF7ASQDJ4MPU7YEUTIUT"
        + "&apikey=" + api_key
    )
    print(curl_link)

    output = rq.get(curl_link, headers=send_headers)

    # sleep to avoid ban
    sleep(2)
    json_res = output.json()
    if "result" in json_res:
        source_code = json_res["result"][0]["SourceCode"]
        contract_name = json_res["result"][0]["ContractName"]
        if source_code:
            make_dir(root + contract_address + "_" + contract_name)
            if is_json(source_code):
                res = json.loads(source_code)
                for key in res:
                    print(key)
                    sol_file = open(
                        root + contract_address + "_" + contract_name + "/" + key, "w", encoding="UTF-8"
                    )
                    sol_file.write(res[key]["content"])
                    sol_file.close()
            elif source_code[0] == source_code[1] == "{":
                new_code = source_code[1:-1]
                res = json.loads(new_code)
                sources = res["sources"]
                for name in sources:
                    print(name)
                    _dir, _file = os.path.split(root + contract_address + "_" + contract_name + "/" + name)
                    print(_dir)
                    make_dir(_dir)
                    sol_file = open(
                        root + contract_address + "_" + contract_name + "/" + name, "w", encoding="UTF-8"
                    )
                    sol_file.write(sources[name]["content"])
                    sol_file.close()
            else:
                sol_file = open(
                    root + contract_address + "_" + contract_name + "/" + contract_address + ".sol",
                    "w",
                    encoding="UTF-8",
                )
                sol_file.write(source_code)
                sol_file.close()
        else:
            raise ValueError("这是一个值错误")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dir", type=str, help="output crawled file path, end with '/'"
    )
    parser.add_argument("--caddress", type=str, help="contract address")
    parser.add_argument("--platform", type=str, help="contract platform")
    args = parser.parse_args()
    crawl_contract(args.dir, args.caddress, args.platform)
