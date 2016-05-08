from __future__ import print_function, division

import base64
import random
import httplib
import ssl
import json
import collections

__all__ = ["get_ncauth_from_user", "RecordType", "connect", 
           "get_all_records", "add_record", "remove_record", "sync"]

def get_ncauth_from_user():
    text = raw_input("Please provide the .ncauth cookie: ")
    _, _, text = text.rpartition(".ncauth=")
    text, _, _ = text.partition(";")
    text = text.strip()

    try:
        base64.b16decode(text)
    except:
        raise Exception("Invalid .ncauth cookie: expected uppercase hex digits only")

    return text

def _make_headers(ncauth):
    compliance = "".join("{:02x}".format(random.randint(0, 255)) for _i in range(20))
    return \
        { "Cookie": "_NcCompliance={0}; .ncauth={1}".format(compliance, ncauth)
        , "_NcCompliance": compliance
        , "Content-Type": "application/json;charset=UTF-8"
        }

NAMECHEAP_HOST = "ap.www.namecheap.com"
BASE_PATH = "/Domains/dns/"

class RecordType(object):
    DATA_FORWARDS = \
        { "A":      1
        , "CNAME":  2
        , "MX":     3
        , "MXE":    4
        , "TXT":    5
        , "URL":    6
        , "FRAME":  7
        , "AAAA":   8
        , "NS":     9
        , "URL301": 10
        , "SRV":    11
        }
    DATA_BACKWARDS = {v: k for k, v in DATA_FORWARDS.items()}

    def __init__(self, name_or_int):
        if isinstance(name_or_int, RecordType):
            self.name = name_or_int.name
            self.int = name_or_int.int
        elif name_or_int in self.DATA_FORWARDS:
            self.name = name_or_int
            self.int = self.DATA_FORWARDS[name_or_int]
        elif name_or_int in self.DATA_BACKWARDS:
            self.int = name_or_int
            self.name = self.DATA_BACKWARDS[name_or_int]
        else:
            raise ValueError("Unrecognised RecordType", name_or_int)

    def __hash__(self):
        return self.int

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.int == self.other.int

    def __repr__(self):
        return self.name

class Record(object):
    def __init__(self, host, data, record_type, mx_priority=None, host_id=None):
        record_type = RecordType(record_type)

        if (record_type == RecordType("MX")) != (mx_priority is not None):
            raise Exception("mx_priority should be not none iff record type is mx")

        self.host = host
        self.data = data
        self.record_type = record_type
        self.mx_priority = mx_priority
        self.host_id = host_id

    def __str__(self):
        return "{:10} {:20} {}".format(self.record_type, self.host, self.data)

    def __repr__(self):
        s = "Record(host={host!r}, data={data!r}, record_type={record_type!r}".format(self.__dict__)
        if self.mx_priority is not None:
            s += ", mx_priority={!r}".format(self.mx_priority)
        if self.host_id is not None:
            s += ", host_id={!r}".format(self.host_id)
        s += ")"
        return s

    @classmethod
    def of_json(cls, row):
        return cls(host=row["Host"], data=row["Data"], host_id=row["HostId"],
                   record_type=RecordType(row["RecordType"]),
                   mx_priority=row["Priority"])

    def to_add_request_json(self, ttl=1800):
        if self.host_id is not None:
            raise Exception("record already exists", self)
        data = \
            { "HostId": -1
            , "Host": self.host
            , "Data": self.data
            , "RecordType": self.record_type.int
            , "Ttl": ttl
            }
        if self.record_type == RecordType("MX"):
            data["Priority"] = self.mx_priority
        return data

def connect():
    return httplib.HTTPSConnection(NAMECHEAP_HOST, context=ssl.create_default_context())

def get_response_and_assert_ok(conn):
    resp = conn.getresponse()
    if 200 <= resp.status < 300:
        return resp.read()
    else:
        raise Exception("Request failed", resp.status, resp.reason, resp.read())

def get_all_records(conn, domain, ncauth):
    path = BASE_PATH + "GetAdvancedDnsInfo?domainName=" + domain
    conn.request("GET", path, None, _make_headers(ncauth=ncauth))
    resp = get_response_and_assert_ok(conn=conn)
    resp = json.loads(resp)

    return [Record.of_json(row) for row in resp["Result"]["CustomHostRecords"]["Records"]]

def add_record(conn, domain, ncauth, record):
    data = \
        { "model": record.to_add_request_json()
        , "domainName": domain
        , "isAddNewProcess": True
        }

    path = BASE_PATH + "AddOrUpdateHostRecord"
    conn.request("POST", path, json.dumps(data), _make_headers(ncauth=ncauth))
    get_response_and_assert_ok(conn=conn)

def remove_record(conn, domain, ncauth, record):
    data = \
        { "hostId": record.host_id
        , "recordType": record.record_type.int
        , "domainName": domain
        }
    path = BASE_PATH + "RemoveDomainDnsRecord"
    conn.request("POST", path, json.dumps(data), _make_headers(ncauth=ncauth))
    get_response_and_assert_ok(conn=conn)

class HashableRecordIgnoringHostId(Record):
    @classmethod
    def of_record(cls, rec):
        cls(host=rec.host, data=rec.data, record_type=rec.record_type,
            mx_priority=rec.mx_priority, host_id=rec.host_id)

    def __tuple(self):
        return (self.host, self.data, self.record_type, self.mx_priority)

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.__tuple() == other.__tuple()

    def __hash__(self, other):
        return hash(self.__tuple())

def sync(conn, domain, ncauth, records, verbose=True):
    records = set(HashableRecordIgnoringHostId.of_record(x) for x in records)
    existing_records = set(HashableRecordIgnoringHostId.of_record(x) 
                           for x in get_all_records(conn, domain, ncauth))

    for record in records & existing_records:
        if verbose: print("Keeping ", repr(record))
    for record in existing_records - records:
        if verbose: print("Removing", repr(record))
        remove_record(conn, domain, ncauth, record)
    for record in records - existing_records:
        if verbose: print("Adding  ", repr(record))
        add_record(conn, domain, ncauth, record)
