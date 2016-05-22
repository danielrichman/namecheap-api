import namecheap_api

def records():
    def f(record_type, host, data):
        return namecheap_api.Record(host=host, data=data, record_type=record_type)

    for host in ["@", "www", "yocto"]:
        yield f("A", host, "94.23.154.77")
        yield f("AAAA", host, "2001:41d0:2:9795:94:23:154:77")

    yield f("TXT", "@", "v=spf1 include:_spf.google.com -all")

    def g(data, priority):
        return namecheap_api.Record(host="@", data=data, mx_priority=priority, record_type="MX")

    yield g("aspmx.l.google.com.", 1)
    yield g("alt1.aspmx.l.google.com.", 5)
    yield g("alt2.aspmx.l.google.com.", 5)
    yield g("aspmx2.googlemail.com.", 10)
    yield g("aspmx3.googlemail.com.", 10)

def main():
    records_list = list(records())

    print("1) Log into the namecheap website")
    print("2) Open the chrome inspector (or equivalent)")
    print("3) Copy the '.ncauth' cookie from any request headers,")
    print("   or the Resources tab, Cookies section.")
            
    ncauth = namecheap_api.get_ncauth_from_user()
    conn = namecheap_api.connect()
    namecheap_api.sync(conn=conn, domain="drichman.net", ncauth=ncauth, records=records_list)

if __name__ == "__main__":
    main()
