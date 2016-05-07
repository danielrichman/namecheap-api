from __future__ import print_function, division

import base64
import random
import httplib
import ssl
import json

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
RECORD_TYPE_INTEGERS = \
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
RECORD_TYPE_INTEGERS_REV = {v: k for k, v in RECORD_TYPE_INTEGERS.items()}


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

    def f(row):
        return \
            { "host": row["Host"]
            , "data": row["Data"]
            , "host_id": row["HostId"]
            , "record_type": RECORD_TYPE_INTEGERS_REV[row["RecordType"]]
            }

    return [f(row) for row in resp["Result"]["CustomHostRecords"]["Records"]]

def add_record(conn, domain, ncauth, host, data, record_type, ttl=1799):
    data = \
        { "model":
            { "HostId": -1
            , "Host": host
            , "Data": data
            , "RecordType": RECORD_TYPE_INTEGERS[record_type]
            , "Ttl": ttl
            }
        , "domainName": domain
        , "isAddNewProcess": True
        }

    path = BASE_PATH + "AddOrUpdateHostRecord"
    conn.request("POST", path, json.dumps(data), _make_headers(ncauth=ncauth))
    get_response_and_assert_ok(conn=conn)

def remove_record(conn, domain, ncauth, host_id, record_type):
    data = \
        { "hostId": host_id
        , "recordType": RECORD_TYPE_INTEGERS[record_type]
        , "domainName": domain
        }
    path = BASE_PATH + "RemoveDomainDnsRecord"
    conn.request("POST", path, json.dumps(data), _make_headers(ncauth=ncauth))
    get_response_and_assert_ok(conn=conn)
