import os
import subprocess
import json
import re

_dir = ""
caddress = ""
platform = ""

cmd = "python crawl.py --dir " + _dir + " --caddress " + caddress + " --platform " + platform
result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
if result.returncode != 0:
    print(cmd)