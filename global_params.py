"""Global configuration variables for running program"""

TOOL_DIR = None

PROJECT_DIR = None

EVENT = None

MATCH = None

EVENT_FUNC_DIR = None

# enable reporting of the result
REPORT_MODE = 0

# print everything in the console
PRINT_MODE = 0

# enable log file to print all exception
DEBUG_MODE = 0

# Timeout for z3 in ms
TIMEOUT = 1000

# Set this flag to 2 if we want to do evm real value unit test
# Set this flag to 3 if we want to do evm symbolic unit test
UNIT_TEST = 0

# timeout to run symbolic execution (in secs)
GLOBAL_TIMEOUT = 600

# timeout to run symbolic execution (in secs) for testing
GLOBAL_TIMEOUT_TEST = 2

# print path conditions
PRINT_PATHS = 0

# Redirect results to a json file.
STORE_RESULT = 1

# depth limit for DFS
DEPTH_LIMIT = 500

GAS_LIMIT = 400000000

LOOP_LIMIT = 200

GENERATE_TEST_CASES = 0

# Run WakeMint in parallel
PARALLEL = 0

SOLC_SWITCH = 0

SOLC_VERSION = None

IS_LOW_VERSION = False

# Iterable of targeted smart contract names
TARGET_CONTRACTS = None

TARGET_FUNCTION = None

CRAWL_DIR = "./test/"

SOURCE = None

# output json elements
CONTRACT_ADDRESS = ""
CONTRACT_COUNT = 0
STORAGE_VAR_COUNT = 0
PUB_FUN_COUNT = 0

# magic value for analysis
ONERC721RECEIVED_SELECTOR = 353073666
ONERC721RECEIVED_SELECTOR_SHL = None
# ONERC721RECEIVED_SELECTOR_SHL = 9518847231895308808422688260840288680026284048802002002228286400486822662662
