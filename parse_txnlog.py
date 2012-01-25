#!/usr/bin/env python

# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from optparse import OptionParser

import struct
import binascii
import time

class LogFileHeader(object):
    def __init__(self, log):
        s = struct.Struct('4s')
        self.MAGIC = int(binascii.hexlify(s.pack('ZKLG')), 16)
        s = struct.Struct('>i i q')
        (self.magic, self.version, self.dbid) = s.unpack(log.read(s.size))
    def isvalid(self):
        return self.magic == self.MAGIC

SESSIONCLOSE = -11
SESSIONCREATE = -10
ERROR = -1
NOTIFICATION = 0
CREATE = 1
DELETE = 2
EXISTS = 3
GETDATA = 4
SETDATA = 5
GETACL = 6
SETACL = 7
GETCHILDREN = 8
SYNC = 9
PING = 11
GETCHILDREN2 = 12
CHECK = 13
MULTI = 14
AUTH = 100
SETWATCHES = 101
SASL = 102

opcodes = { 
    SESSIONCLOSE:'sessionclose',
    SESSIONCREATE:'sessioncreate',
    ERROR:'error',
    NOTIFICATION:'notification',
    CREATE:'create',
    DELETE:'delete',
    EXISTS:'exists',
    GETDATA:'getdata',
    SETDATA:'setdata',
    GETACL:'getacl',
    SETACL:'setacl',
    GETCHILDREN:'getchildren',
    SYNC:'sync',
    PING:'ping',
    GETCHILDREN2:'getchildren2',
    CHECK:'check',
    MULTI:'multi',
    AUTH:'auth',
    SETWATCHES:'setwatches',
    SASL:'sasl',
}

# endofstream
class EOS(Exception):
    pass

class UnknownType(Exception):
    def __init__(self, type):
        self.type = type
    def __str__(self):
        return "Unknown type %d" % self.type

class Txn(object):
    def __init__(self, log):
        s = struct.Struct('>q i')
        (self.crc, self.txn_len) = s.unpack(log.read(s.size))

        if self.txn_len == 0: raise EOS()

        self.header = h = TxnHeader(log)
        if h.type == CREATE:
            self.entry = TxnCreate(log)
        elif h.type == DELETE:
            self.entry = TxnDelete(log)
        elif h.type == SETDATA:
            self.entry = TxnSetData(log)
        elif h.type == SETACL:
            self.entry = TxnSetAcl(log)
        elif h.type == SESSIONCREATE:
            self.entry = TxnSessionCreate(log)
        elif h.type == SESSIONCLOSE:
            self.entry = TxnSessionClose(log)
        elif h.type == ERROR:
            self.entry = TxnError(log)
        else:
            raise(UnknownType(h.type))

        eor = log.read(1)
    def __str__(self):
        return "%s -- %s" % (self.header, self.entry)

class TxnHeader(object):
    def __init__(self, log):
        s = struct.Struct('>Q I Q Q i')
        (self.client_id, self.cxid, self.zxid, self.time,
         self.type) = s.unpack(log.read(s.size))
    def op2type(self, type):
        return opcodes[type]
    def __str__(self):
        return "%s (%3dms) sessionid 0x%x zxid 0x%x cxid 0x%x %s" % (
                  time.ctime(self.time/1000), self.time % 1000,
                  self.client_id, self.zxid, self.cxid,
                  self.op2type(self.type))

class TxnEntry(object):
    def readString(self, log):
        _len = self.readInt(log)
        s = struct.Struct(str(_len) + 's')
        _str = s.unpack(log.read(s.size))
        return _str

    def readData(self, log):
        _len = self.readInt(log)
        return log.read(_len)

    def readAcls(self, log):
        count = self.readInt(log)
        return [self.readAcl(log) for i in xrange(count)]

    def readAcl(self, log):
        return Acl(log)

    def readInt(self, log):
        s = struct.Struct('>i')
        (_int,) = s.unpack(log.read(s.size))
        return _int

    def readBool(self, log):
        s = struct.Struct('B')
        _bool = s.unpack(log.read(s.size))
        return _bool == 0

class Acl(TxnEntry):
    def __init__(self, log):
        self.perms = self.readInt(log)
        self.scheme = self.readString(log)
        self.id = self.readString(log)
    def __str__(self):
        return "Acl %s %s %x" % (self.scheme, self.id, self.perms)

class TxnError(TxnEntry):
    Ok = 0
    SystemError = -1
    RuntimeInconsistency = -2
    DataInconsistency = -3
    ConnectionLoss = -4
    MarshallingError = -5
    Unimplemented = -6
    OperationTimeout = -7
    BadArguments = -8
    APIError = -100
    NoNode = -101
    NoAuth = -102
    BadVersion = -103
    NoChildrenForEphemerals = -108
    NodeExists = -110
    NotEmpty = -111
    SessionExpired = -112
    InvalidCallback = -113
    InvalidACL = -114
    AuthFailed = -115
    SessionMoved = -118

    errorcodes = {
        Ok:'ok',
        SystemError:'systemerror',
        RuntimeInconsistency:'runtimeinconsistency',
        DataInconsistency:'datainconsistency',
        ConnectionLoss:'connectionloss',
        MarshallingError:'marshallingerror',
        Unimplemented:'unimplemented',
        OperationTimeout:'operationtimeout',
        BadArguments:'badarguments',
        APIError:'apierror',
        NoNode:'nonode',
        NoAuth:'noauth',
        BadVersion:'badversion',
        NoChildrenForEphemerals:'nochildrenforephemerals',
        NodeExists:'nodeexists',
        NotEmpty:'notempty',
        SessionExpired:'sessionexpired',
        InvalidCallback:'invalidcallback',
        InvalidACL:'invalidacl',
        AuthFailed:'authfailed',
        SessionMoved:'sessionmoved',
    }

    def __init__(self, log):
        self.err = self.readInt(log)
    def __str__(self):
        return "Error %s" % self.errorcodes[self.err]

class TxnCreate(TxnEntry):
    def __init__(self, log):
        self.path = self.readString(log)
        self.data = self.readData(log)
        self.acls = self.readAcls(log)
        self.ephemeral = self.readBool(log)
    def __str__(self):
        return "Create path %s data '%s' acls %s ephemeral %i" % (
                 self.path, self.data, self.acls, self.ephemeral)

class TxnDelete(TxnEntry):
    def __init__(self, log):
        self.path = self.readString(log)
    def __str__(self):
        return "Delete path %s" % self.path

class TxnSetData(TxnEntry):
    def __init__(self, log):
        self.path = self.readString(log)
        self.data = self.readData(log)
        self.version = self.readInt(log)
    def __str__(self):
        return "SetData path %s data '%s' version %i" % (self.path, self.data, self.version)

class TxnSetAcl(TxnEntry):
    def __init__(self, log):
        self.path = self.readString(log)
        self.acls = self.readAcls(log)
        self.version = self.readInt(log)
    def __str__(self):
        return "SetAcl path %s acls %s version %i" % (self.path, self.acls, self.version)

class TxnSessionCreate(TxnEntry):
    def __init__(self, log):
        self.timeout = self.readInt(log)
    def __str__(self):
        return "SessionCreate timeout %ims" % (self.timeout)

class TxnSessionClose(TxnEntry):
    def __init__(self, log):
        pass
    def __str__(self):
        return "SessionClose"

if __name__ == '__main__':
    usage = "usage: %prog [options] zookeeper_txnlog"
    parser = OptionParser(usage=usage)

    #parser.add_option("-c", "--count", dest="count", type="int",
    #                  default=3, help="ensemble size (default 3)")

    (options, args) = parser.parse_args()

    if len(args) != 1:
        parser.error("need log file")

    log = open(args[0], 'rb')
    log_header = LogFileHeader(log)
    if not log_header.isvalid():
        parser.error("Not a valid ZooKeeper transaction log")

    start = None
    try:
        while(True):
            txn = Txn(log)
            if not start:
                start = txn.header.time
                print("Log starts at %s and %ims" % (time.ctime(start/1000), start % 1000))
            diff = txn.header.time - start
            print("%09i,%03i %s" % (diff/1000, diff%1000, str(txn)[33:]))
    except Exception as e:
        print(e)

    log.close()
