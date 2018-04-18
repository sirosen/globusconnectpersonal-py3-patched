#!/usr/bin/env python


#
# Copyright 2010-2011 University of Chicago
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""
Globus Connect Setup for linux
Initialize ~/.globusonline/lta directory if it doesn't exist.
Call relaytool to handle setup

Requires: GLOBUS_LOCATION
Dependencies: relaytool
"""


import re
import sys
import os
import time
import signal
import pwd

# py2 vs py3 compat
PY2 = sys.version_info[0] == 2
PY3 = sys.version_info[0] == 3

try:
    GLOBUS_LOCATION = os.environ['GLOBUS_LOCATION']
except KeyError:
    raise Exception("Need GLOBUS_LOCATION defined")

EXE_DIR = os.path.dirname(sys.argv[0])
TOP_DIR = sys.argv[len(sys.argv)-1]
CONFIG_DIR = os.path.join(TOP_DIR, "lta")

os.environ['LD_LIBRARY_PATH'] = "%s/lib:%s" % (
GLOBUS_LOCATION, os.getenv('LD_LIBRARY_PATH', ""))
RELAYTOOL = os.environ['GCP_RELAYTOOL_PATH']

class Config: pass


def make_dir(dir):
    if not os.path.exists(dir):
        os.mkdir(dir)


def run_cmd(cmd, args):
    """
    We don't have access to subprocess.  Do it the old-fashioned way.
    """
    stdin_pipe = os.pipe()
    stdout_pipe = os.pipe()
    stderr_pipe = os.pipe()
    pid = os.fork()
    if pid == 0:
        # Child.  Exec.
        os.close(0)
        os.close(1)
        os.close(2)
        # fd = open("/dev/null", "r")
        os.dup2(stdin_pipe[0], 0)
        os.dup2(stdout_pipe[1], 1)
        os.dup2(stderr_pipe[1], 2)
        # os.closerange(3, 500)
        os.close(stdin_pipe[1])
        os.close(stdout_pipe[0]) # Close read end
        os.close(stderr_pipe[0])
        os.execl(cmd, *args)
    else:
        os.close(stdin_pipe[0])
        os.close(stdout_pipe[1]) # Close write end
        os.close(stderr_pipe[1])
        out_buf = os.read(stdout_pipe[0], 100000)
        err_buf = os.read(stderr_pipe[0], 100000)
        status = os.waitpid(pid, 0)
        return (os.WEXITSTATUS(status[1]), os.WTERMSIG(status[1]), out_buf, err_buf)


def contact_relay(code, server):
    """
    Contact service and get config blob using one time key
    """
    print("Contacting %s" % (server))

    os.environ['GCP_RELAY_SERVER'] = server
    os.environ['GCP_SETUP_CODE'] = code

    def _print_out_err(out, err):
        if PY3:
            out = out.decode('utf-8')
            err = err.decode('utf-8')
        if out:
            print("\n".join(out, err))
        else:
            print(err)

    rc, sig, out, err = run_cmd(RELAYTOOL, [os.path.basename(RELAYTOOL)])
    # PY2/PY3 compat
    # out, err may be bytestrings on py3, so convert to str() explicitly before
    # printing
    if rc == 255:
        print("Error: Could not connect to server")
        print("---")
        _print_out_err(b"", err)
        return rc
    if rc != 0:
        print("Error: The server returned an error")
        print("---")
        _print_out_err(out, err)
        return rc
    if rc == 0 and sig != 0:
        print("Error: Could not connect to server")
        print("---")
        print("Exited abnormaly: received signal " + str(sig))
        _print_out_err(out, err)
        return sig
    return rc


def main(code, server):
    # Validate safe chars
    mo = re.match("^[0-9a-zA-Z-]+$", code)
    if not mo:
        raise Exception("Invalid Code '%s'" % code)
    mo = re.match("^[0-9a-zA-Z.-:]+$", server)
    if not mo:
        raise Exception("Invalid Server '%s'" % server)

    print("Configuration directory: %s" % CONFIG_DIR)
    make_dir(TOP_DIR)
    make_dir(CONFIG_DIR)

    # Now talk to service.  Retrieve security info
    rc = contact_relay(code, server)
    return rc 


if __name__ == "__main__":
    args = sys.argv[1:]
    if not args or args[0] == "-h":
        print("Usage: setup.py code [server]")
        sys.exit(2)
    code = args[0].strip()
    if len(args) == 3:
        server = args[1].strip()
    else:
        server = os.getenv('GCP_RELAY_SERVER', "relay.globusonline.org:2223")
    rc = main(code, server)
    if rc == 0:
        print("Done!")
    sys.exit(rc)
