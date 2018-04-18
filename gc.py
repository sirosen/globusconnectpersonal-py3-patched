#!/usr/bin/env python

#  Copyright 2010-2011 University of Chicago
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import time
import sys
import os
import csv
import errno
import traceback
from socket import socket, AF_INET, SOCK_STREAM
from select import select

"""
Spawn gridftp worker (inetd) instances and keep track of current count.
Also spawn relaytool connection to relay service.
Config items used: SERVER, SERVER_PORT
Env vars used: GLOBUS_LOCATION
"""

# TODO: use optparse, the positional args make things complicated when
# we don't want to pass RP.
if len(sys.argv) != 5:
    print("Usage: %s config_dir restricted_paths shared_paths foward" %
          sys.argv[0])
    sys.exit(1)

ARG_GO_CONF_DIR = sys.argv[1]
ARG_RESTRICTED_PATHS = sys.argv[2].strip()
ARG_SHARING_RP = sys.argv[3].strip()
ARG_FORWARD = sys.argv[4]

GCP_VERSION = os.environ['GCP_APP_VERSION']

try:
    GLOBUS_LOCATION = os.environ['GLOBUS_LOCATION']
except KeyError:
    raise Exception("Need GLOBUS_LOCATION defined")
EXE_DIR = os.path.dirname(sys.argv[0])
GC_DIR = ARG_GO_CONF_DIR + "/lta"
CONFIG = os.path.join(GC_DIR, "config")
PATH_CONFIG = os.path.join(GC_DIR, "config-paths")
X509_USER_CERT = os.path.join(GC_DIR, "ftp-cert2.pem")
X509_USER_KEY = os.path.join(GC_DIR, "ftp-key2.pem")
X509_CERT_DIR = os.path.join(EXE_DIR, "etc", "ca")
GRIDMAP = os.path.join(GC_DIR, "gridmap")

os.environ['X509_USER_CERT'] = X509_USER_CERT
os.environ['X509_USER_KEY'] = X509_USER_KEY
os.environ['X509_USER_PROXY'] = ""
os.environ['X509_CERT_DIR'] = X509_CERT_DIR
os.environ['GRIDMAP'] = GRIDMAP
os.environ['GSI_AUTHZ_CONF'] = "/foobaronetwothree"
os.environ['LD_LIBRARY_PATH'] = "%s/lib:%s" % (
        GLOBUS_LOCATION, os.getenv('LD_LIBRARY_PATH', ""))

# Check for required files from setup
for f in (GC_DIR, GRIDMAP, CONFIG):
    if not os.path.exists(f):
        print("Error: '%s' does not exist" % f)
        print("Please run setup")
        sys.exit(1)

PDEATH = os.environ['GCP_PDEATH_PATH']
GRIDFTP_SERVER = os.environ['GCP_GRIDFTP_PATH']
RELAYTOOL = os.environ['GCP_RELAYTOOL_PATH']
RELAY_RETRY_SECS = 5.0
STATUS_INTERVAL_SECS = 5.0

RELAY_STATUS_NONE = "n/a"
RELAY_STATUS_CONNECTING = "connecting"
RELAY_STATUS_CONNECTED = "connected"
RELAY_STATUS_PAUSED = "paused"

GC_CONTROL_ADDRESS = "\0/org/globusonline/globusconnect/uid=%d" % os.getuid()

class ChildProcess(object):
    pass

"""
Helper Functions
"""
def read_end(p):
    return p[0]

def write_end(p):
    return p[1]

def log(msg):
    sys.stdout.write(msg.strip() + "\n")

def log_exception(msg):
    sys.stderr.write(msg.strip() + "\n")
    traceback.print_exc()

def status_to_rc(status):
    if os.WIFSIGNALED(status):
        return -os.WTERMSIG(status)
    elif os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    else:
        assert 0

def close_all_fds(keep=None):
    fds = os.listdir("/proc/self/fd")
    for _fd in fds:
        fd = int(_fd)
        if keep and fd in keep:
            continue
        try:
            os.close(fd)
        except Exception:
            pass

def load_config(name):
    """
    Simple K=V config file parser
    Return dict
    """
    f = open(name)
    ret = {}
    for l in f:
        if not l.startswith("#"):
            if "=" in l:
                key, val = l.split("=", 1)
                ret[key] = val.strip()
    f.close()
    return ret

def get_path_args():
    """Use args from command line if present, otherwise read options from
    config config file (i.e. set using the GUI). Returns args suitable
    for passing directly to gridftp."""
    # Note: NONE is a hack to workaround tcl limitations re passing
    # empty positional args.
    read_config = True
    restrict_paths, shared_paths = [], []
    if ARG_RESTRICTED_PATHS and ARG_RESTRICTED_PATHS != "NONE":
        restrict_paths = ARG_RESTRICTED_PATHS.split(",")
        read_config = False
    if ARG_SHARING_RP and ARG_SHARING_RP != "NONE":
        shared_paths = ARG_SHARING_RP.split(",")
        read_config = False

    if read_config:
        restrict_paths, shared_paths = load_path_config_file(PATH_CONFIG)

    if not shared_paths:
        shared_paths = ["n/"]
    if not restrict_paths:
        restrict_paths = ["n/"]
    else:
        # hard code no dot files, we can add an option later
        restrict_paths.append("n~/.*")

    rp_arg = ",".join(restrict_paths)
    srp_arg = ",".join(shared_paths)

    return (rp_arg, srp_arg)


def load_path_config_file(name, create_if_empty=True):
    """Read config
    config config file (i.e. set using the GUI)."""
    # Note: NONE is a hack to workaround tcl limitations re passing
    # empty positional args.
    restrict_paths = []
    shared_paths = []
    try:
        f = open(name)
        for row in csv.reader(f):
            #wrap this with a try just in case people go in a mess things up
            try:
                path, shareable, writable = row
                # Escape comma and percent, but allow shell wildcards.
                # Users are responsible for backslash escaping wildcards if
                # they want literal behavior. No other characters could be
                # misinterpreted, so further encoding is not needed.
                path = path.replace("%", "%25")
                path = path.replace(",", "%2C")
                if (writable == '1'):
                    path = "rw" + path
                else:
                    path = "r" + path
                restrict_paths.append(path)
                if shareable == '1':
                    shared_paths.append(path)
            except:
                print("failed to parse from config file: %s" % row)
        f.close()
    except IOError as e:
        if e.errno == errno.ENOENT:
            # This should happen only if run in command line mode
            # without ever using the GUI. If args are not present, use the
            # default of user's home dir read-write and save to config
            # file.
            restrict_paths = ["rw~/"]
            f = open(name, "w")
            f.write("~/,0,1\n")
            f.close()
        else:
            raise

    return (restrict_paths, shared_paths)


class EventManager(object):
    """
    Handle fd and process exit events
    Call registered callback function
    """
    def __init__(self):
        self._fd_map = {} # fd num -> callable
        self._pid_map = {} # pid -> callable
        self._pgrp_id = os.getpgrp()

    def add_pid(self, pid, fn):
        self._pid_map[pid] = fn

    def add_fd(self, fd, fn):
        self._fd_map[fd] = fn

    def remove_fd(self, fd):
        del self._fd_map[fd]

    def poll(self, timeout=1.0):
        rfds, wfds, errfds = select(self._fd_map.keys(), [], [], timeout)
        if rfds:
            for fd in rfds:
                #log("event for fd %d" % fd)
                fn = self._fd_map[fd]
                fn(fd)
            return True

        if self._pid_map:
            pid, status = os.waitpid(-self._pgrp_id, os.WNOHANG)
            if pid not in self._pid_map and pid != 0:
                log("Process %d not in PID map crashed with status %d" % (pid, status))
            elif pid != 0:
                log("event for pid %d" % pid)
                fn = self._pid_map[pid]
                del self._pid_map[pid]
                rc = status_to_rc(status)
                log("rc=%d" % rc)
                fn(pid, rc)
                return True

        # Timeout
        return False



class GlobusConnect(object):
    def __init__(self):
        config = load_config(CONFIG)
        self._relay_port = int(config["SERVER_PORT"])
        self._relay_server = config["SERVER"]
        self._socket = None
        self._gridftp_port = None
        self._gridftp_procs = {} # pid -> ChildProcess
        self._relaytool_proc = None
        self._relaytool_status = RELAY_STATUS_NONE
        self._relaytool_restart_time = None
        # explicitly handle as bytestring for py2/py3 compat
        self._relaytool_buf_overflow = b""
        self._manager = EventManager()
        self._next_status_time = time.time()
        self._pid = "%s" % (os.getpid())

    def init(self):

        """
        Create listening socket
        """
        self._socket = socket(AF_INET, SOCK_STREAM, 0)
        for i in range(900, 10000):
            try:
                self._socket.bind(("localhost", i))
                self._gridftp_port = i
                break
            except Exception:
                pass
        self._socket.listen(10)
        self._manager.add_fd(self._socket.fileno(), self._gridftp_accept)
        log("Listening on localhost:%d" % self._gridftp_port)
        self._start_relaytool()
        # Catch when parent dies
        self._manager.add_fd(0, self._parent_died)


    def run(self):
        """
        Main loop.  Handle gridftp connetions, processes exiting, and timers
        """
        while True:
            self._manager.poll()
            cur_time = time.time()
            if cur_time > self._next_status_time:
                # show current status
                log("#gridftp %d" % len(self._gridftp_procs))
                log("#relaytool %s" % self._relaytool_status)
                self._next_status_time = time.time() + STATUS_INTERVAL_SECS
            if not self._relaytool_proc and cur_time > self._relaytool_restart_time:
                self._start_relaytool()


    def _parent_died(self, fd):
        log("parent died, exiting")
        sys.exit(0)


    #
    # Gridftp methods
    #
    def _gridftp_accept(self, fd):
        try:
            sock, addr = self._socket.accept()
            log("Got connection from %s" % (addr,))
        except Exception:
            log_exception("Accept failed")
        self._add_gridftp(sock.fileno())
        sock.close()

    def _add_gridftp(self, sock_fd):
        """
        Start a gridftp server child process in inetd mode
        """
        restrict_paths, shared_paths = get_path_args()
        version_tags = ["GCP",GCP_VERSION+"L"]
        version_tag = "-".join(version_tags)
        print(version_tag)
        
        p = ChildProcess()
        log("Sock fd: %d" % sock_fd)
        pid = os.fork()
        if pid > 0:
            p.pid = pid
            self._gridftp_procs[pid] = p
            self._manager.add_pid(pid, self._gridftp_exited)
            return
        # Child

        close_all_fds(keep=(1, sock_fd))
        os.dup2(1, 2)
        # GT 5.0.3 should set NODELAY on inetd socket
        os.dup2(sock_fd, 0)
        os.dup2(sock_fd, 1)

        args = [os.path.basename(PDEATH),
                self._pid,
                GRIDFTP_SERVER,
                os.path.basename(GRIDFTP_SERVER),
                "-i", "-always-send-markers",
                "-hostname", "127.0.0.1",
                "-c", "/foobaronetwothree",
                "-log-module", "stdio:buffer=0",
                "-d", "TRANSFER,DEBUG,ALL",
                "-l", "/dev/stderr",
                "-sharing-dn", "/C=US/O=Globus Consortium/OU=Globus Online/OU=Transfer User/CN=__transfer__",
                "-allow-udt", "-threads", "1",
                "-version-tag", version_tag]
        args.append("-restrict-paths")
        args.append(restrict_paths)

        args.append("-sharing-rp")
        args.append(shared_paths)

        #with open("/tmp/gc.py.log", "w") as logfile:
        #    logfile.write("gc.py args = %s\n" % args)

        os.execv(PDEATH, args)

    def _gridftp_exited(self, pid, rc):
        log("gridftp pid %d exited, rc=%d" % (pid, rc))
        del self._gridftp_procs[pid]


    #
    # relaytool methods
    #
    def _start_relaytool(self):
        log("Starting relaytool")
        self._relaytool_status = RELAY_STATUS_CONNECTING
        c = ChildProcess()
        c.pipe = os.pipe()
        c
        pid = os.fork()
        if pid > 0:
            os.close(write_end(c.pipe))
            c.pid = pid
            self._relaytool_proc = c
            # Don't monitor pid - we can watch when fd is closed and we
            # don't want any races (read all data first)
            self._manager.add_fd(read_end(c.pipe), self._relaytool_input)
            return

        # Child

        # Set the child to be the leader of its process group
        # This will allow us to separate the relaytool child from the rest of the
        # children (i.e. gridftp) so that we can reap the two group of children
        # separately
        os.setpgrp()

        out_fd = write_end(c.pipe)
        close_all_fds(keep=(out_fd,))
        #null_fd = open("/dev/null", "r")
        os.dup2(out_fd, 0)
        os.dup2(out_fd, 1)
        os.dup2(out_fd, 2)
        os.environ['GCP_RELAY_SERVER'] = "%s:%s" % (self._relay_server, self._relay_port)

        if ARG_FORWARD == "forward":
          os.environ['GCP_FTP_PORT'] = "%s" % (self._gridftp_port)
          os.execl(RELAYTOOL, os.path.basename(RELAYTOOL))
        else:
          os.environ['GCP_FTP_PORT'] = "-1"
          os.execl(RELAYTOOL, os.path.basename(RELAYTOOL))

    def _relaytool_input(self, fd):
        #log("relaytool input %d" % fd)
        #log("read end is %d" % read_end(self._relaytool_proc.pipe))
        #using 1024 because subprocess also uses that as a default.
        buf = os.read(fd, 1024)
        if buf:
            # PY2/PY3 compat
            # all of this needs to carefully make everything an explicit
            # bytestring to work on py3
            # but the interface for b"..." and "..." (unicode str on py3) is
            # compatible for everything we do here
            lines = (self._relaytool_buf_overflow + buf).split(b"\n")
            self._relaytool_buf_overflow = ""
            if not lines[-1].endswith(b"\n"):
                self._relaytool_buf_overflow = lines.pop().strip()
            for l in lines:
                line = l.strip()
                if b"RELAYTOOL=1" in line:
                    if b"status=CONNECTED" in line:
                        self._relaytool_status = RELAY_STATUS_CONNECTED
                    elif b"status=PAUSED" in line:
                        self._relaytool_status = RELAY_STATUS_PAUSED
                print(str(line))

        else:
            # Closed, process most likely is dead
            pid, status = os.waitpid(self._relaytool_proc.pid, 0)
            rc = status_to_rc(status)
            self._relaytool_exited(pid, rc)


    def _relaytool_exited(self, pid, rc):
        log("relaytool pid %d exited, rc=%d" % (pid, rc))
        fd = read_end(self._relaytool_proc.pipe)
        self._manager.remove_fd(fd)
        os.close(fd)
        self._relaytool_proc = None
        self._relaytool_status = RELAY_STATUS_NONE
        # Retry again later
        self._relaytool_restart_time = time.time() + RELAY_RETRY_SECS



if __name__ == "__main__":
    gc = GlobusConnect()
    gc.init()
    gc.run()
