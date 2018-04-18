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

import os
import sys
from socket import socket, AF_UNIX, SOCK_STREAM
from select import select
from signal import signal, SIGINT
import re
import platform
import getpass


GCP_VERSION = "2.3.5"
if len(sys.argv) > 1 and sys.argv[1] == "-version":
    print(GCP_VERSION)
    sys.exit(0)

dist_string = ""
try:
    dist = platform.dist()
    arch = platform.architecture()
    dist_string_parts = []
    if dist[0] != "":
        dist_string_parts.append(dist[0])
    if dist[1] != "":
        dist_string_parts.append(dist[1])
    if arch[0] != "":
        dist_string_parts.append(arch[0])
    dist_string = "-".join(dist_string_parts)
except:
    dist_string = "unknown Linux"

LINUX_VER = dist_string

try:
    GLOBUS_LOCATION = os.environ['GLOBUS_LOCATION']
except KeyError:
    raise Exception("Need GLOBUS_LOCATION defined")
EXE_DIR = os.path.dirname(sys.argv[0])

os.environ['LD_LIBRARY_PATH'] = "%s/lib:%s" % (
        GLOBUS_LOCATION, os.getenv('LD_LIBRARY_PATH', ""))

os.environ['GCP_OS'] = "linux"
os.environ['GCP_OS_VERSION'] = LINUX_VER
os.environ['GCP_APP_VERSION'] = GCP_VERSION
# getuser() checks environment variables in this order:
# LOGNAME, USER, LNAME, USERNAME
# it then failsover to using pwd
os.environ['GCP_USER'] = getpass.getuser()
os.environ['GCP_GLOBAL_ETC_DIR'] = os.path.join(EXE_DIR, "etc")
os.environ['GCP_SSH_PATH'] = os.path.join(GLOBUS_LOCATION, "bin", "ssh")
os.environ['GCP_PDEATH_PATH'] = os.path.join(GLOBUS_LOCATION, "bin", "pdeath")
os.environ['GCP_RELAYTOOL_PATH'] = os.path.join(GLOBUS_LOCATION, "bin", "relaytool")
os.environ['GCP_GRIDFTP_PATH'] = os.path.join(GLOBUS_LOCATION, "sbin", "globus-gridftp-server")


GC_CONTROL_ADDRESS = ""


def status_to_rc(status):
    if os.WIFSIGNALED(status):
        return -os.WTERMSIG(status)
    elif os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    else:
        assert 0


def ctrlc(sig, frame):
    sys.exit(1)


def send2clients(fds, data):
    for i in range(len(fds)):
        try:
            fds[i].send(data)
        except Exception:
            fds.pop(i)

def start(debug):
    s = socket(AF_UNIX, SOCK_STREAM, 0)
    try:
        s.bind(GC_CONTROL_ADDRESS)
    except Exception:
        if 'Address already in use' in e:
            sys.stderr.write("Another Globus Connect Personal is currently running\n")
            sys.exit(1)
        else:
            raise
    s.listen(5)

    piread, piwrite = os.pipe()
    pread, pwrite = os.pipe()
    peread, pewrite = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(piwrite)
        os.close(pread)
        os.close(peread)
        os.dup2(piread, 0)
        os.dup2(pwrite, 1)
        os.dup2(pewrite, 2)
        os.execl("./gc.py", "gc.py", args[3], args[1], args[2], args[4])
    else:
        os.close(piread)
        os.close(pwrite)
        os.close(pewrite)
        fds = [pread, s]
        while True:
            rfds, _, _ = select(fds, [], [])
            # next line from gc.py through pipe
            if rfds[0] == pread:
                data = os.read(pread, 1024)
                if not data:
                    error = os.read(peread, 1024)
                    pid, status = os.waitpid(pid, 0)
                    rc = status_to_rc(status)
                    mesg = "%s\nSubprocess pid %d exited, rc=%d\n" \
                            % (error, pid, rc)
                    sys.stderr.write(mesg)
                    send2clients(fds[2:], mesg)
                    sys.exit(rc)
                if debug:
                    sys.stdout.write(data)
                    sys.stdout.flush()
                send2clients(fds[2:], data)
            # control socket accepting a new client
            elif rfds[0] == s:
                conn, addr = s.accept()
                fds.append(conn)
            # command from a client on a control socket
            else:
                try:
                    cmd = rfds[0].recv(16)
                except Exception:
                    fds.remove(rfds[0])
                    continue
                if not cmd:
                    fds.remove(rfds[0])
                    continue
                if cmd == "stop":
                    sys.exit(0)
                elif cmd == "status" or cmd == "trace":
                    pass
                else:
                    try:
                        rfds[0].send("Error: unrecognized command")
                    except Exception:
                        fds.remove(rfds[0])


def setup():
    os.execl("setup.py", args[0], args[1], args[2])


def stop():
    s = socket(AF_UNIX, SOCK_STREAM, 0)
    try:
        s.bind(GC_CONTROL_ADDRESS)
    except Exception as e:
        if 'Address already in use' in e:
            sys.stdout.write("Globus Connect Personal is currently running and" \
                    " connected to Globus Online\n" \
                    "Sending stop signal... ")
            s.connect(GC_CONTROL_ADDRESS)
            s.send("stop")
            s.close()
            sys.stdout.write("Done\n")
            sys.exit(0)
        else:
            raise
    sys.stdout.write("No Globus Connect Personal connected to Globus Online Service\n")
    sys.exit(1)


def status():
    s = socket(AF_UNIX, SOCK_STREAM, 0)
    try:
        s.bind(GC_CONTROL_ADDRESS)
    except Exception as e:
        if 'Address already in use' in e:
            s.connect(GC_CONTROL_ADDRESS)
            s.send("status")
            data = ""
            while True:
                data = data + s.recv(1024)
                ftp = re.search('^#gridftp (\w+)$', data, re.MULTILINE)
                relay = re.search('^#relaytool ([\w/]+)$', data, re.MULTILINE)
                if ftp and relay:
                    if relay.group(1) == "n/a":
                        print("Globus Online:   disconnected")
                    else:
                        print("Globus Online:   " + relay.group(1))
                    if ftp.group(1) == "0":
                        print("Transfer Status: idle")
                    else:
                        print("Transfer Status: active")
                    break
            s.close()
            sys.exit(0)
        else:
            raise
    sys.stdout.write("No Globus Connect Personal connected to Globus Online Service\n")
    sys.exit(1)


def trace():
    s = socket(AF_UNIX, SOCK_STREAM, 0)
    try:
        s.bind(GC_CONTROL_ADDRESS)
    except Exception as e:
        if 'Address already in use' in e:
            s.connect(GC_CONTROL_ADDRESS)
            s.send("trace")
            while True:
                try:
                    data = s.recv(1024)
                except Exception:
                    print("Connection reset by peer")
                    sys.exit(0)
                sys.stdout.write(data)
            s.close()
            sys.exit(0)
        else:
            raise
    sys.stdout.write("No Globus Connect Personal connected to Globus Online Service\n")
    sys.exit(1)


if __name__ == "__main__":
    signal(SIGINT, ctrlc)
    args = sys.argv[1:]
    GC_CONTROL_ADDRESS = "\0/org/globusonline/globusconnect%s/uid=%d" % (args[len(args)-1], os.getuid())
    if args[0] == "-start":
        start(debug=False)
    elif args[0] == "-debug":
        start(debug=True)
    elif args[0] == "-setup":
        setup()
    elif args[0] == "-stop":
        stop()
    elif args[0] == "-status":
        status()
    elif args[0] == "-trace":
        trace()
