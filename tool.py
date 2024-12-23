#!/usr/bin/env python

import argparse
import logging
import os
import re
import subprocess
import json
import global_params
from crawler.crawl import crawl_contract

from cfg_builder import sym_exec
from cfg_builder.utils import run_command
from inputter.input_helper import InputHelper
from inputter.solc_version_switcher import *
from inputter.input_helper_oyente import InputHelper as InputHelerOyente


def cmd_exists(cmd):
    """Check if the command is installed in the system's PATH.

    Args:
        cmd (str): The command to check.

    Returns:
        bool: True if the command is installed, False otherwise.
    """
    return (
        subprocess.call(
            "type " + cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        == 0
    )


def compare_versions(version1, version2):
    """Compare two given versions

    Args:
        version1 (_type_): one version
        version2 (_type_): the other version

    Returns:
        int: 0 if version1 is equal to version2,
             -1 if version1 is less than version2,
             1 if version1 is greater than version2
    """

    def normalize(v):
        return [int(x) for x in re.sub(r"(\.0+)*$", "", v).split(".")]

    version1 = normalize(version1)
    version2 = normalize(version2)
    return (version1 > version2) - (version1 < version2)


def has_dependencies_installed():
    """Checks whether all the necessary dependencies are installed

    Returns:
        bool: whether dependencies are installed
    """
    try:
        import z3
        import z3.z3util

        z3_version = z3.get_version_string()
        tested_z3_version = "4.8.13"
        if compare_versions(z3_version, tested_z3_version) > 0:
            logging.warning(
                "You are using an untested version of z3. %s is the officially tested version"
                % tested_z3_version
            )
    except Exception as e:
        logging.critical(e)
        logging.critical(
            "Z3 is not available. Please install z3 from https://github.com/Z3Prover/z3."
        )
        return False

    if not cmd_exists("evm"):
        logging.critical(
            "Please install evm from go-ethereum and make sure it is in the path."
        )
        return False
    else:
        cmd = "evm --version"
        out = run_command(cmd).strip()
        evm_version = re.findall(r"evm version (\d*.\d*.\d*)", out)[0]
        tested_evm_version = "1.10.21"
        if compare_versions(evm_version, tested_evm_version) > 0:
            logging.warning(
                "You are using evm version %s. The supported version is %s"
                % (evm_version, tested_evm_version)
            )

    if not cmd_exists("solc"):
        logging.critical(
            "solc is missing. Please install the solidity compiler and make sure solc is in the path."
        )
        return False
    else:
        cmd = "solc --version"
        out = run_command(cmd).strip()
        print("out: ", out)
        solc_version = re.findall(r"Version: (\d*.\d*.\d*)", out)[0]
        tested_solc_version = "0.8.16"
        if compare_versions(solc_version, tested_solc_version) > 0:
            logging.warning(
                "You are using solc version %s, The latest supported version is %s"
                % (solc_version, tested_solc_version)
            )

    return True


def run_solidity_analysis(inputs):
    """Run analysis for solidity input

    Args:
        inputs (_type_): input contracts

    Returns:
        Tuple[Dict[str, Dict[str, Any]], int]: analysis results and run status
            The analysis results are stored in a dictionary where the keys are the contract source files and the values are dictionaries.
            Each inner dictionary contains the analysis results for a specific contract source file, where the keys are the contract function names and the values are the results.
            The run status is an integer indicating the exit code of the analysis.
    """
    results = {}
    exit_code = 0

    # for our tool, we must find some key features
    for inp in inputs:
        logging.info("contract %s:", inp["contract"])

        sym_exec.run(
            disasm_file=inp["disasm_file"],
            source_map=inp["source_map"],
            slot_map=inp["slot_map"],
            source_file=inp["source"],
        )

       
    return results, 1


def analyze_solidity(input_type="solidity"):
    """
    entrance to analyze solidity and prepare MUST info from Inputter for feature_detector

    Args:
        input_type (str, optional): The type of input. Defaults to 'solidity'.

    Returns:
        integer: The exit status of the execution.
    """
    global args
    # print(global_params.SOLC_VERSION)
    # return
    if input_type == "solidity":
        helper = InputHelper(
            InputHelper.SOLIDITY,
            source=args.source,
            allow_paths=args.allow_paths,
            remap=args.remap,
            evm=args.evm,
            compilation_err=args.compilation_error,
        )

        switcher = SolidityVersionSwitcher(helper.target)
        if global_params.PROJECT_DIR:
            os.chdir(global_params.PROJECT_DIR)
        solidity_code = switcher.load_solidity_code()
        version_info = switcher.extract_solidity_version(solidity_code)
        
        if version_info.startswith('0.4') or version_info.startswith('0.5'):
            global_params.IS_LOW_VERSION = True
            helper = InputHelerOyente(InputHelerOyente.SOLIDITY,
            source=args.source,
            allow_paths=args.allow_paths,
            remap=args.remap,
            evm=args.evm,
            compilation_err=args.compilation_error,)
    else:
        return
    inputs = helper.get_inputs(global_params.TARGET_CONTRACTS)
    
    _, exit_code = run_solidity_analysis(inputs)
    helper.rm_tmp_files()

    return exit_code


def main():
    """Entrance for the analysis with input options"""
    # TODO: Implement -o switch.

    global args

    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)

    # supported arguments refer to Oyente
    group.add_argument(
        "-s",
        "--source",
        type=str,
        default="",
        help="local source file name. Solidity by default. Use -b to process evm instead. Use stdin to read from stdin.",
    )

    group.add_argument(
        "-caddress",
        "--contract-address",
        type=str,
        help="The address of the tested contract (Ethereum mainnet supported now).",
        dest="contract_address",
    )

    parser.add_argument(
        "-ap",
        "--allow-paths",
        help="Allow a given path for imports",
        action="store",
        dest="allow_paths",
        type=str,
    )

    parser.add_argument(
        "-rmp",
        "--remap",
        help="Remap directory paths",
        action="store",
        type=str,
        nargs="+",
        default="",
    )

    parser.add_argument(
        "-cnames",
        "--target-contracts",
        type=str,
        nargs="+",
        help="The name of targeted contracts. If specified, only the specified contracts in the source code will be processed. By default, all contracts in Solidity code are processed.",
    )

    parser.add_argument(
        "-fselector",
        "--target-fselector",
        type=str,
        help="The target function to be tested.",
    )

    parser.add_argument(
        "--version", action="version", version="WakeMint version 0.1.0 - Boom"
    )

    parser.add_argument(
        "-t", "--timeout", help="Timeout for Z3 in ms.", action="store", type=int
    )
    parser.add_argument(
        "-gl",
        "--gaslimit",
        help="Limit Gas",
        action="store",
        dest="gas_limit",
        type=int,
    )
    parser.add_argument(
        "-ll",
        "--looplimit",
        help="Limit number of loops",
        action="store",
        dest="loop_limit",
        type=int,
    )
    parser.add_argument(
        "-dl",
        "--depthlimit",
        help="Limit DFS depth",
        action="store",
        dest="depth_limit",
        type=int,
    )

    parser.add_argument(
        "-glt",
        "--global-timeout",
        help="Timeout for symbolic execution",
        action="store",
        dest="global_timeout",
        type=int,
    )
    parser.add_argument(
        "-addr",
        "--address",
        help="Mark contract address in the json output (-j)",
        action="store",
        dest="address",
        type=str,
    )

    parser.add_argument(
        "-sv",
        "--solc-version",
        help="Specify solc version",
        dest="solc_version",
        action="store",
        type=str,
    )

    parser.add_argument(
        "-e", "--evm", help="Do not remove the .evm file.", action="store_true"
    )
    parser.add_argument(
        "-j", "--json", help="Redirect results to a json file.", action="store_true"
    )
    parser.add_argument(
        "-p", "--paths", help="Print path condition information.", action="store_true"
    )
    parser.add_argument(
        "-db", "--debug", help="Display debug information", action="store_true"
    )
    parser.add_argument(
        "-r", "--report", help="Create .report file.", action="store_true"
    )
    parser.add_argument(
        "-v", "--verbose", help="Verbose output, print everything.", action="store_true"
    )
    parser.add_argument(
        "-pl",
        "--parallel",
        help="Run WakeMint in parallel. Note: The performance may depend on the contract",
        action="store_true",
    )
    parser.add_argument(
        "-ce",
        "--compilation-error",
        help="Display compilation errors",
        action="store_true",
    )
    parser.add_argument(
        "-gtc",
        "--generate-test-cases",
        help="Generate test cases each branch of symbolic execution tree",
        action="store_true",
    )
    parser.add_argument(
        "-as",
        "--automated-solc-version-switch",
        help="Automatically switch to the required Solidity version of the contract",
        action="store_true",
    )
    parser.add_argument(
        "-match",
        help="To match exsited vulnerable contracts",
        action="store_true",
    )
    parser.add_argument(
        "-event",
        help="event",
        action="store",
        type=str,
    )
    parser.add_argument(
        "-pd",
        help = "project directory",
        action="store",
        type=str
    )

    args = parser.parse_args()
    args.allow_paths = args.allow_paths if args.allow_paths else ""

    if args.timeout:
        global_params.TIMEOUT = args.timeout

    logging.basicConfig()
    rootLogger = logging.getLogger(None)

    if args.verbose:
        rootLogger.setLevel(level=logging.DEBUG)
    else:
        rootLogger.setLevel(level=logging.INFO)

    global_params.PRINT_PATHS = 1 if args.paths else 0
    global_params.REPORT_MODE = 1 if args.report else 0

    global_params.STORE_RESULT = 1 if args.json else 0
    global_params.DEBUG_MODE = 1 if args.debug else 0
    global_params.GENERATE_TEST_CASES = 1 if args.generate_test_cases else 0
    global_params.PARALLEL = 1 if args.parallel else 0
    global_params.SOLC_SWITCH = 1 if args.automated_solc_version_switch else 0
    global_params.MATCH = True if args.match else False

    if args.pd:
        global_params.PROJECT_DIR = args.pd
    if args.event:
        global_params.EVENT = args.event
    if args.solc_version:
        global_params.SOLC_VERSION = args.solc_version
    # for writing current tested contract address in json result file
    if args.address:
        global_params.CONTRACT_ADDRESS = args.address

    global_params.TOOL_DIR = os.getcwd()
    global_params.TARGET_CONTRACTS = args.target_contracts
    global_params.TARGET_FUNCTION = args.target_fselector

    if args.source:
        global_params.SOURCE = args.source
    elif args.contract_address:
        target_path = os.path.join(
            global_params.CRAWL_DIR, args.contract_address, args.contract_address
        )
        if not os.path.exists(target_path + ".sol"):
            crawl_contract(global_params.CRAWL_DIR, args.contract_address)

        global_params.SOURCE = target_path + ".sol"
        args.source = global_params.SOURCE

    # set limit to set execution bounds
    if args.depth_limit:
        global_params.DEPTH_LIMIT = args.depth_limit
    if args.gas_limit:
        global_params.GAS_LIMIT = args.gas_limit
    if args.loop_limit:
        global_params.LOOP_LIMIT = args.loop_limit
    if args.global_timeout:
        global_params.GLOBAL_TIMEOUT = args.global_timeout

    if not has_dependencies_installed():
        return

    # analyze Solidity source code
    exit_code = analyze_solidity()

    if global_params.MATCH:
        #这次编译得到的合约函数签名
        event_func_dir = global_params.EVENT_FUNC_DIR
        
        #存在于“数据库”中的函数签名
        existed_list = None
        with open("event_func_dir.json", "r", encoding="utf-8") as f:
            existed_list = json.loads(f.read())
            cur_funcs = None
            for key in event_func_dir:
                cur_funcs = event_func_dir[key]["func sigs"]

            print("\n========================================匹配结果=========================================")
            for event in existed_list:
                #如果在数据集中找到了自己就跳过
                if event == global_params.EVENT:
                    continue

                intersaction = []
                for cur_func in cur_funcs:
                    if cur_func in existed_list[event]["func sigs"]:
                        intersaction.append(cur_func)
                if len(intersaction) > 0:
                    print(event, intersaction)
    

    exit(exit_code)


if __name__ == "__main__":
    main()

