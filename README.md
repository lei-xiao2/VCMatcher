# VCMatcher

根据函数签名匹配漏洞合约。



## Tool

### Prerequisites

- Python >= 3.8

- evm >= 1.10.21.
  Download version 1.10.21 (tested) from [go-ethereum](https://geth.ethereum.org/downloads) and add executable bins in the `$PATH`.

  ```sh
  wget https://gethstore.blob.core.windows.net/builds/geth-alltools-linux-amd64-1.10.21-67109427.tar.gz
  tar -zxvf geth-alltools-linux-amd64-1.10.21-67109427.tar.gz
  cp geth-alltools-linux-amd64-1.10.21-67109427/evm /usr/local/bin/ #$PATH
  ```

- solc.
  Recommend solc-select to manage Solidity compiler versions.

  ```sh
  pip3 install solc-select
  ```

### Install

1. Python dependencies installation.

```sh
pip3 install -r requirements.txt
```

### Usage

#### Local

工具涉及几个参数：

- -pd: project directory，指定合约项目根目录，如果是单合约可不写
- -s: 指定合约路径，如果没写-pd，写相对于tool.py的路径。如果写了-pd，写相对于项目根目录的路径
- -cnames: 合约名
- -as: 自动切换solc版本
- -match: 代表此次执行匹配操作（这个记得写，否则无法正常匹配



示例1（不写-pd）：

```sh
python3 tool.py -s ./test/test.sol -cnames Test -as -match
```



示例2（写-pd）：

```sh
python3 tool.py -pd /mnt/sdb/home/xiaolei/VCmatcher/vulnerable_contracts/2024/0x9BDF251435cBC6774c7796632e9C80B233055b93_Saturn  -s contracts/Saturn.sol -cnames Saturn -as -match
```

此时“-s”后面的路径就以项目根目录为准
