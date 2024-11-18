import base64
import errno
import pickle
import signal
import time
import tokenize
import traceback
import zlib
from collections import namedtuple
from tokenize import NAME, NEWLINE, NUMBER

from numpy import mod
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich import box
from rich.console import Console

from cfg_builder.basicblock import BasicBlock
from cfg_builder.execution_states import EXCEPTION, PICKLE_PATH, UNKNOWN_INSTRUCTION
from cfg_builder.utils import *
from cfg_builder.vargenerator import *
import global_params
import logging

# Initiate table for live print.
console = Console()
table = Table()
live = Live(table, console=console, vertical_overflow="crop", auto_refresh=True)

log = logging.getLogger(__name__)

# Store visited blocks
visited_blocks = set()

UNSIGNED_BOUND_NUMBER = 2**256 - 1
CONSTANT_ONES_159 = BitVecVal((1 << 160) - 1, 256)




def generate_table(
    opcode, block_cov, pc, perc, g_src_map, global_problematic_pcs, current_func_name
) -> Table:

    """Make a new table for live presentation

    Returns:
        table: table for live show
    """
    defect_table = Table(box=box.SIMPLE)

    defect_table.add_column("Defect", justify="center", style="bold", no_wrap=True)

    defect_table.add_row("Privileged Address")
    defect_table.add_row("Unrestricted 'from'")
    defect_table.add_row("Owner Inconsistency")
    defect_table.add_row("Empty Transfer Event")

    end = time.time()

    time_coverage_table = Table(box=box.SIMPLE)
    time_coverage_table.add_column(
        "Time", justify="left", style="cyan", no_wrap=True, width=8
    )
    time_coverage_table.add_column(
        "Code Coverage", justify="left", style="yellow", no_wrap=True
    )
    time_coverage_table.add_column(
        "Block Coverage", justify="left", style="yellow", no_wrap=True
    )
    time_coverage_table.add_row(
        str(round(end - begin, 1)), str(round(perc, 1)), str(round(block_cov, 1))
    )

    block_table = Table(box=box.SIMPLE)
    block_table.add_column("PC", justify="left", style="cyan", no_wrap=True, width=8)
    block_table.add_column(
        "Opcode", justify="left", style="yellow", no_wrap=True, width=8
    )
    block_table.add_column(
        "Current Function", justify="left", style="yellow", no_wrap=True, min_width=19
    )

    block_table.add_row(str(pc), opcode, current_func_name)

    state_table = Table.grid(expand=True)
    state_table.add_column(justify="center")
    state_table.add_row(time_coverage_table)
    state_table.add_row(block_table)

    reporter = Table(box=box.ROUNDED, title="WakeMint GENESIS v0.0.1")
    reporter.add_column("Defect Detection", justify="center")
    reporter.add_column("Execution States", justify="center")
    reporter.add_row(defect_table, state_table)
    return reporter

# def generate_table(
#     opcode, block_cov, pc, perc, g_src_map, global_problematic_pcs, current_func_name
# ) -> Table:
#     (
#         proxy,
#         reentrancy,
#         unlimited_minting,
#         violation,
#         public_burn,
#     ) = dynamic_defect_identification(g_src_map, global_problematic_pcs)
#     """Make a new table for live presentation

#     Returns:
#         table: table for live show
#     """
#     defect_table = Table(box=box.SIMPLE)

#     defect_table.add_column("Defect", justify="right", style="bold", no_wrap=True)
#     defect_table.add_column("Status", style="green")
#     defect_table.add_column("Location", justify="left", style="cyan")

#     defect_table.add_row("Risky Mutable Proxy", str(proxy.is_defective()), str(proxy))
#     defect_table.add_row(
#         "ERC-721 Reentrancy", str(reentrancy.is_defective()), str(reentrancy)
#     )
#     defect_table.add_row(
#         "Unlimited Minting",
#         str(unlimited_minting.is_defective()),
#         str(unlimited_minting),
#     )
#     defect_table.add_row(
#         "Missing Requirements", str(violation.is_defective()), str(violation)
#     )
#     defect_table.add_row(
#         "Public Burn", str(public_burn.is_defective()), str(public_burn)
#     )
#     end = time.time()

#     time_coverage_table = Table(box=box.SIMPLE)
#     time_coverage_table.add_column(
#         "Time", justify="left", style="cyan", no_wrap=True, width=8
#     )
#     time_coverage_table.add_column(
#         "Code Coverage", justify="left", style="yellow", no_wrap=True
#     )
#     time_coverage_table.add_column(
#         "Block Coverage", justify="left", style="yellow", no_wrap=True
#     )
#     time_coverage_table.add_row(
#         str(round(end - begin, 1)), str(round(perc, 1)), str(round(block_cov, 1))
#     )

#     block_table = Table(box=box.SIMPLE)
#     block_table.add_column("PC", justify="left", style="cyan", no_wrap=True, width=8)
#     block_table.add_column(
#         "Opcode", justify="left", style="yellow", no_wrap=True, width=8
#     )
#     block_table.add_column(
#         "Current Function", justify="left", style="yellow", no_wrap=True, min_width=19
#     )

#     block_table.add_row(str(pc), opcode, current_func_name)

#     state_table = Table.grid(expand=True)
#     state_table.add_column(justify="center")
#     state_table.add_row(time_coverage_table)
#     state_table.add_row(block_table)

#     reporter = Table(box=box.ROUNDED, title="WakeMint GENESIS v0.0.1")
#     reporter.add_column("Defect Detection", justify="center")
#     reporter.add_column("Execution States", justify="center")
#     reporter.add_row(defect_table, state_table)
#     return reporter


class Parameter:
    def __init__(self, **kwargs):
        attr_defaults = {
            "stack": [],
            "calls": [],
            "memory": [],
            "visited": [],
            "overflow_pcs": [],
            "mem": {},
            "analysis": {},
            "sha3_list": {},
            "global_state": {},
            "path_conditions_and_vars": {},
        }
        for attr, default in six.iteritems(attr_defaults):
            setattr(self, attr, kwargs.get(attr, default))

    def copy(self):
        _kwargs = custom_deepcopy(self.__dict__)
        return Parameter(**_kwargs)


def initGlobalVars():
    # Initialize global variables
    global g_src_map
    global solver
    # Z3 solver
    solver = Solver()
    solver.set("timeout", global_params.TIMEOUT)

    global MSIZE
    MSIZE = False

    global revertible_overflow_pcs
    revertible_overflow_pcs = set()

    global g_disasm_file
    with open(g_disasm_file, "r") as f:
        disasm = f.read()
    if "MSIZE" in disasm:
        MSIZE = True

    global g_timeout
    g_timeout = False

    global visited_pcs
    visited_pcs = set()

    global results
    if g_src_map:
        global start_block_to_func_sig
        start_block_to_func_sig = {}

        results = {
            "evm_code_coverage": "",
            "instructions": "",
            "time": "",
            "analysis": {
                "privileged_address": [],
                "unrestricted_from_and_owner_inconsistency": [],
                "empty_transfer_event": [],
            },
            "bool_defect": {
                "privileged_address": False,
                "unrestricted_from_and_owner_inconsistency": False,
                "empty_transfer_event": False
            },
        }
    else:
        results = {
            "evm_code_coverage": "",
            "instructions": "",
            "time": "",
            "bool_defect": {
                "privileged_address": False,
                "unrestricted_from_and_owner_inconsistency": False,
                "empty_transfer_event": False
            },
        }

    global calls_affect_state
    calls_affect_state = {}

    # capturing the last statement of each basic block
    global end_ins_dict
    end_ins_dict = {}

    # capturing all the instructions, keys are corresponding addresses
    global instructions
    instructions = {}

    # capturing the "jump type" of each basic block
    global jump_type
    jump_type = {}

    global vertices
    vertices = {}

    global edges
    edges = {}

    # start: end
    global blocks
    blocks = {}

    global visited_edges
    visited_edges = {}

    global money_flow_all_paths
    money_flow_all_paths = []

    global reentrancy_all_paths
    reentrancy_all_paths = []

    # store the path condition corresponding to each path in money_flow_all_paths
    global path_conditions
    path_conditions = []

    global global_problematic_pcs  # for different defects
    global_problematic_pcs = {
        "privileged_address": [],
        "unrestricted_from_and_owner_inconsistency": [],
        "empty_transfer_event": [],
    }
    # global_problematic_pcs = {
    #     "proxy_defect": [],
    #     "burn_defect": [],
    #     "reentrancy_defect": [],
    #     "unlimited_minting_defect": [],
    #     "violation_defect": [],
    # }

    # store global variables, e.g. storage, balance of all paths
    global all_gs
    all_gs = []

    global total_no_of_paths
    total_no_of_paths = 0

    global no_of_test_cases
    no_of_test_cases = 0

    # to generate names for symbolic variables
    global gen
    gen = Generator()

    global rfile
    if global_params.REPORT_MODE:
        rfile = open(g_disasm_file + ".report", "w")


def is_testing_evm():
    return global_params.UNIT_TEST != 0


def compare_storage_and_gas_unit_test(global_state, analysis):
    unit_test = pickle.load(open(PICKLE_PATH, "rb"))
    test_status = unit_test.compare_with_symExec_result(global_state, analysis)
    exit(test_status)


def change_format():
    """Change format for tokenization and buildng CFG"""
    with open(g_disasm_file) as disasm_file:
        file_contents = disasm_file.readlines()
        i = 0
        firstLine = file_contents[0].strip("\n")
        for line in file_contents:
            line = line.replace(":", "")
            lineParts = line.split(" ")
            try:  # removing initial zeroes
                lineParts[0] = str(int(lineParts[0], 16))

            except:
                lineParts[0] = lineParts[0]
            lineParts[-1] = lineParts[-1].strip("\n")
            try:  # adding arrow if last is a number
                lastInt = lineParts[-1]
                if (int(lastInt, 16) or int(lastInt, 16) == 0) and len(lineParts) > 2:
                    lineParts[-1] = "=>"
                    lineParts.append(lastInt)
            except Exception:
                pass
            file_contents[i] = " ".join(lineParts)
            i = i + 1
        file_contents[0] = firstLine
        file_contents[-1] += "\n"

    with open(g_disasm_file, "w") as disasm_file:
        disasm_file.write("\n".join(file_contents))


def build_cfg_and_analyze():
    """Build cfg and perform symbolic execution"""
    change_format()
    log.info("Building CFG...")
    with open(g_disasm_file, "r") as disasm_file:
        disasm_file.readline()  # Remove first line
        tokens = tokenize.generate_tokens(disasm_file.readline)  # tokenization
        collect_vertices(tokens)  # find vertices
        construct_bb()
        construct_static_edges()  # find static edges from stack top
        full_sym_exec()  # jump targets are constructed on the fly


def print_cfg():
    for block in vertices.values():
        block.display()
    log.debug(str(edges))


def mapping_push_instruction(
    current_line_content, current_ins_address, idx, positions, length
):
    global g_src_map
    while idx < length:
        if not positions[idx]:
            return idx + 1
        name = positions[idx]["name"]
        if name.startswith("tag"):
            idx += 1
        else:
            if name.startswith("PUSH"):
                if name == "PUSH":
                    value = positions[idx]["value"]
                    instr_value = current_line_content.split(" ")[1]
                    if int(value, 16) == int(instr_value, 16):
                        g_src_map.instr_positions[current_ins_address] = (
                            g_src_map.positions[idx]
                        )
                        idx += 1
                        break
                    else:
                        # print(idx, positions[idx])
                        # print(value, instr_value, current_line_content)
                        raise Exception("Source map error")
                else:
                    g_src_map.instr_positions[current_ins_address] = (
                        g_src_map.positions[idx]
                    )
                    idx += 1
                    break
            else:
                raise Exception("Source map error")
    return idx


def mapping_non_push_instruction(
    current_line_content, current_ins_address, idx, positions, length
):
    global g_src_map
    while idx < length:
        if not positions[idx]:
            return idx + 1
        name = positions[idx]["name"]
        if name.startswith("tag"):
            idx += 1
        else:
            instr_name = current_line_content.split(" ")[0]
            if (
                name == instr_name
                or name == "INVALID"
                and instr_name == "ASSERTFAIL"
                or name == "KECCAK256"
                and instr_name == "SHA3"
                or name == "SELFDESTRUCT"
                and instr_name == "SUICIDE"
            ):
                g_src_map.instr_positions[current_ins_address] = g_src_map.positions[
                    idx
                ]
                idx += 1
                break
            else:
                raise RuntimeError(
                    f"Source map error, unknown name({name}) or instr_name({instr_name})"
                )
    return idx


# 1. Parse the disassembled file
# 2. Then identify each basic block (i.e. one-in, one-out)
# 3. Store them in vertices


def collect_vertices(tokens):
    global g_src_map
    if g_src_map:
        idx = 0
        positions = g_src_map.positions
        length = len(positions)
    global end_ins_dict
    global instructions
    global jump_type

    current_ins_address = 0
    last_ins_address = 0
    is_new_line = True
    current_block = 0
    current_line_content = ""
    wait_for_push = False
    is_new_block = False

    for tok_type, tok_string, (srow, scol), _, line_number in tokens:
        if wait_for_push is True:
            push_val = ""
            if current_line_content == "PUSH0 " and tok_type == NEWLINE:
                is_new_line = True
                current_line_content += "0 "
                instructions[current_ins_address] = current_line_content
                idx = (
                        mapping_push_instruction(
                        current_line_content,
                        current_ins_address,
                        idx,
                        positions,
                        length,
                    )
                    if g_src_map
                    else None
                )
                current_line_content = ""
                wait_for_push = False
                continue

            for ptok_type, ptok_string, _, _, _ in tokens:
                if ptok_type == NEWLINE:
                    is_new_line = True
                    current_line_content += push_val + " "
                    instructions[current_ins_address] = current_line_content
                    idx = (
                        mapping_push_instruction(
                            current_line_content,
                            current_ins_address,
                            idx,
                            positions,
                            length,
                        )
                        if g_src_map
                        else None
                    )
                    current_line_content = ""
                    wait_for_push = False
                    break
                try:
                    int(ptok_string, 16)
                    push_val += ptok_string
                except ValueError:
                    pass

            continue
        elif is_new_line is True and tok_type == NUMBER:  # looking for a line number
            last_ins_address = current_ins_address
            try:
                current_ins_address = int(tok_string)
            except ValueError:
                log.critical("ERROR when parsing row %d col %d", srow, scol)
                quit()
            is_new_line = False
            if is_new_block:
                current_block = current_ins_address
                is_new_block = False
            continue
        elif tok_type == NEWLINE:
            is_new_line = True
            log.debug(current_line_content)
            instructions[current_ins_address] = current_line_content
            idx = (
                mapping_non_push_instruction(
                    current_line_content, current_ins_address, idx, positions, length
                )
                if g_src_map
                else None
            )
            current_line_content = ""
            continue
        elif tok_type == NAME:
            if tok_string == "JUMPDEST":
                if last_ins_address not in end_ins_dict:
                    end_ins_dict[current_block] = last_ins_address
                current_block = current_ins_address
                is_new_block = False
            elif (
                tok_string == "STOP"
                or tok_string == "RETURN"
                or tok_string == "SUICIDE"
                or tok_string == "REVERT"
                or tok_string == "ASSERTFAIL"
            ):
                jump_type[current_block] = "terminal"
                end_ins_dict[current_block] = current_ins_address
            elif tok_string == "JUMP":
                jump_type[current_block] = "unconditional"
                end_ins_dict[current_block] = current_ins_address
                is_new_block = True
            elif tok_string == "JUMPI":
                jump_type[current_block] = "conditional"
                end_ins_dict[current_block] = current_ins_address
                is_new_block = True
            elif tok_string.startswith("PUSH", 0):
                wait_for_push = True
            is_new_line = False
        if tok_string != "=" and tok_string != ">":
            current_line_content += tok_string + " "

    if current_block not in end_ins_dict:
        log.debug("current block: %d", current_block)
        log.debug("last line: %d", current_ins_address)
        end_ins_dict[current_block] = current_ins_address

    if current_block not in jump_type:
        jump_type[current_block] = "terminal"

    for key in end_ins_dict:
        if key not in jump_type:
            jump_type[key] = "falls_to"


def construct_bb():
    global vertices
    global edges
    global blocks
    sorted_addresses = sorted(instructions.keys())
    size = len(sorted_addresses)
    # logging.info("instruction size: %d" % size)
    for key in end_ins_dict:
        end_address = end_ins_dict[key]
        block = BasicBlock(key, end_address)
        if key not in instructions:
            continue
        block.add_instruction(instructions[key])
        i = sorted_addresses.index(key) + 1
        while i < size and sorted_addresses[i] <= end_address:
            block.add_instruction(instructions[sorted_addresses[i]])
            i += 1
        block.set_block_type(jump_type[key])
        vertices[key] = block
        blocks[key] = end_address
        edges[key] = []


def construct_static_edges():
    add_falls_to()  # these edges are static


def add_falls_to():
    global vertices
    global edges
    key_list = sorted(jump_type.keys())
    length = len(key_list)
    for i, key in enumerate(key_list):
        if (
            jump_type[key] != "terminal"
            and jump_type[key] != "unconditional"
            and i + 1 < length
        ):
            target = key_list[i + 1]
            edges[key].append(target)
            vertices[key].set_falls_to(target)


def get_init_global_state(path_conditions_and_vars):
    global_state = {"balance": {}, "pc": 0}
    init_is = init_ia = deposited_value = sender_address = receiver_address = (
        gas_price
    ) = origin = currentCoinbase = currentNumber = currentDifficulty = (
        currentGasLimit
    ) = currentChainId = currentSelfBalance = currentBaseFee = callData = None

    sender_address = BitVec("Is", 256)
    receiver_address = BitVec("Ia", 256)
    deposited_value = BitVec("Iv", 256)
    init_is = BitVec("init_Is", 256)
    init_ia = BitVec("init_Ia", 256)

    path_conditions_and_vars["Is"] = sender_address
    path_conditions_and_vars["Ia"] = receiver_address
    path_conditions_and_vars["Iv"] = deposited_value

    # from s to a, s is sender, a is receiver
    # v is the amount of ether deposited and transferred
    constraint = deposited_value >= BitVecVal(0, 256)
    path_conditions_and_vars["path_condition"].append(constraint)
    constraint = init_is >= deposited_value
    path_conditions_and_vars["path_condition"].append(constraint)
    constraint = init_ia >= BitVecVal(0, 256)
    path_conditions_and_vars["path_condition"].append(constraint)

    # update the balances of the "caller" and "callee"
    global_state["balance"]["Is"] = init_is - deposited_value
    global_state["balance"]["Ia"] = init_ia + deposited_value

    if not gas_price:
        new_var_name = gen.gen_gas_price_var()
        gas_price = BitVec(new_var_name, 256)
        path_conditions_and_vars[new_var_name] = gas_price

    if not origin:
        new_var_name = gen.gen_origin_var()
        origin = BitVec(new_var_name, 256)
        path_conditions_and_vars[new_var_name] = origin

    if not currentCoinbase:
        new_var_name = "IH_c"
        currentCoinbase = BitVec(new_var_name, 256)
        path_conditions_and_vars[new_var_name] = currentCoinbase

    if not currentNumber:
        new_var_name = "IH_i"
        currentNumber = BitVec(new_var_name, 256)
        path_conditions_and_vars[new_var_name] = currentNumber

    if not currentDifficulty:
        new_var_name = "IH_d"
        currentDifficulty = BitVec(new_var_name, 256)
        path_conditions_and_vars[new_var_name] = currentDifficulty

    if not currentGasLimit:
        new_var_name = "IH_l"
        currentGasLimit = BitVec(new_var_name, 256)
        path_conditions_and_vars[new_var_name] = currentGasLimit

    if not currentChainId:
        new_var_name = "IH_cid"
        currentChainId = BitVec(new_var_name, 256)
        path_conditions_and_vars[new_var_name] = currentChainId

    if not currentSelfBalance:
        new_var_name = "IH_b"
        currentSelfBalance = BitVec(new_var_name, 256)
        path_conditions_and_vars[new_var_name] = currentSelfBalance

    if not currentBaseFee:
        new_var_name = "IH_f"
        currentBaseFee = BitVec(new_var_name, 256)
        path_conditions_and_vars[new_var_name] = currentBaseFee

    new_var_name = "IH_s"
    currentTimestamp = BitVec(new_var_name, 256)
    path_conditions_and_vars[new_var_name] = currentTimestamp

    # the state of the current contract
    if "Ia" not in global_state:
        global_state["Ia"] = {}
    global_state["miu_i"] = 0
    global_state["value"] = deposited_value
    global_state["sender_address"] = sender_address
    global_state["receiver_address"] = receiver_address
    global_state["gas_price"] = gas_price
    global_state["origin"] = origin
    global_state["currentCoinbase"] = currentCoinbase
    global_state["currentTimestamp"] = currentTimestamp
    global_state["currentNumber"] = currentNumber
    global_state["currentDifficulty"] = currentDifficulty
    global_state["currentGasLimit"] = currentGasLimit

    global_state["currentChainId"] = currentChainId
    global_state["currentSelfBalance"] = currentSelfBalance
    global_state["currentBaseFee"] = currentBaseFee

    # the state of gates to detect each defect
    global_state["ERC721_reentrancy"] = {
        "pc": [],
        "key": None,
        "check": False,
        "var": [],
    }

    global_state["standard_violation"] = {
        "mint_pc": [],
        "approve_pc": [],
        "setApprovalForAll_pc": [],
    }

    global_state["unlimited_minting"] = {
        "pc": [],
        "check": False,
    }

    global_state["mint"] = {
        "trigger": False,
        "to": None,
        "token_id": None,
        "quantity": None,
        "hash": None,
        "MSTORE_1": False,
        "MSTORE_2": False,
        "valid": False,
    }

    global_state["approve"] = {
        "trigger": False,
        "to": None,
        "token_id": None,
        # *Load owner before approval
        "owner_hash": None,
        "hash": None,
        "MSTORE_1": False,
        "MSTORE_2": False,
        # *Note the hash of owner(_owners[tokenId])
        "MSTORE_owner": False,
        "valid": False,
    }

    global_state["transfer"] = {
        "trigger": False,
        "to": None,
        "token_id": None,
        "from": None,
        "MSTORE_owner": False,
        "owner_hash": None,
        "MSTORE_2": False,
    }

    global_state["setApprovalForAll"] = {
        "trigger": False,
        "operator": None,
        "approved": None,
        "MSTORE_1": False,
        "MSTORE_2": False,
        "MSTORE_3": False,
        "hash": None,
        "valid": False,
    }

    global_state["burn"] = {
        "trigger": False,
        "token_id": None,
        "hash": None,
        "MSTORE_1": False,
        "MSTORE_2": False,
        "sload": None,
        "valid": False,
        "pc": None,
    }

    return global_state


def get_start_block_to_func_sig():
    """Map block to function signature

    Returns:
        dict: pc tp function signature
    """
    state = 0
    func_sig = None
    for pc, instr in six.iteritems(instructions):
        if state == 0 and instr.startswith("PUSH4"):
            state += 1
            func_sig = instr.split(" ")[1][2:]
        elif state == 1 and instr.startswith("EQ"):
            state += 1
        elif state == 2 and instr.startswith("PUSH"):
            state = 0
            pc = instr.split(" ")[1]
            pc = int(pc, 16)
            start_block_to_func_sig[pc] = func_sig
        else:
            state = 0
    return start_block_to_func_sig


def full_sym_exec():
    if g_src_map:
        start_block_to_func_sig = get_start_block_to_func_sig()
        logging.info(start_block_to_func_sig)

        func_sigs = []
        for key in start_block_to_func_sig:
            func_sigs.append(start_block_to_func_sig[key])
        print(func_sigs)

        #回到tool.py的目录
        os.chdir("/mnt/sdb/home/xiaolei/VCmatcher")
        event_func_dir = {}
        temp = {}
        temp["source file"] = g_source_file
        temp["func sigs"] = func_sigs
        temp["project directory"] = global_params.PROJECT_DIR
        event_func_dir[global_params.EVENT] = temp
        global_params.EVENT_FUNC_DIR = event_func_dir

        if not global_params.MATCH:
            with open("event_func_dir.json", "r", encoding="utf-8") as f:
                directory = json.loads(f.read())
                if directory:
                    directory[global_params.EVENT] = temp
                else:
                    directory = event_func_dir
                
            with open("event_func_dir.json", "w", encoding="utf-8") as f:
                f.write(json.dumps(directory))



class TimeoutError(Exception):
    pass


class Timeout:
    """Timeout class using ALARM signal."""

    def __init__(self, sec=10, error_message=os.strerror(errno.ETIME)):
        self.sec = sec
        self.error_message = error_message

    def __enter__(self):
        signal.signal(signal.SIGALRM, self._handle_timeout)
        signal.alarm(self.sec)

    def __exit__(self, *args):
        signal.alarm(0)  # disable alarm

    def _handle_timeout(self, signum, frame):
        raise TimeoutError(self.error_message)


def do_nothing():
    pass


def run_build_cfg_and_analyze(timeout_cb=do_nothing):
    initGlobalVars()
    global g_timeout
    try:
        with Timeout(sec=global_params.GLOBAL_TIMEOUT):
            build_cfg_and_analyze()
            log.debug("Done Symbolic execution")
    except TimeoutError:
        g_timeout = True
        timeout_cb()


def test():
    global_params.GLOBAL_TIMEOUT = global_params.GLOBAL_TIMEOUT_TEST

    def timeout_cb():
        traceback.print_exc()
        exit(EXCEPTION)

    run_build_cfg_and_analyze(timeout_cb=timeout_cb)


def analyze():
    def timeout_cb():
        if global_params.DEBUG_MODE:
            traceback.print_exc()

    run_build_cfg_and_analyze(timeout_cb=timeout_cb)


def run(disasm_file=None, source_file=None, source_map=None, slot_map=None):
    """Run specific contracts with the given sources and extracted slot map"""
    global g_disasm_file
    global g_source_file
    global g_src_map
    global results
    global begin
    global g_slot_map

    g_disasm_file = disasm_file
    g_source_file = source_file
    g_src_map = source_map
    g_slot_map = slot_map

    if is_testing_evm():
        test()
    else:
        begin = time.time()
        log.info("\t============ Results of %s===========" % source_map.cname)
        analyze()
    