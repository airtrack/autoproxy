AutoProxy
=========

Auto choose proxy or not by rules.

* TCP connections are automatically proxied or directly connected according to the rules.
* UDP packets are sent directly to the destination address or via a proxy, based on matching rules for the destination address.
* DNS server, according to the rules, directly resolves to the upstream DNS or goes through a proxy to resolve to the upstream DNS.
* Optional hosts files can override DNS answers and force TCP domain connections to use a fixed IP directly.

Usage
-----

```
./autoproxy autoproxy.toml
```

Hosts override
--------------

You can configure optional hosts files in `autoproxy.toml`:

```toml
hosts_ipv4 = "config/hosts4.txt"
hosts_ipv6 = "config/hosts6.txt"
```

The format is the same as `/etc/hosts`, one IP and one domain per line:

```txt
1.2.3.4 example.com
2408::1 example.com
```

When a domain matches a hosts entry:

* DNS `A`/`AAAA` queries return the configured address directly.
* TCP proxy connections use the configured IP directly and keep the original port.

Domain rule files
-----------------

`DomainSuffixSet` uses a plain text file with one suffix per line. Empty lines are ignored, and lines starting with `#` are comments.

```txt
cn
example.com
# internal domains
corp.local
```

Some well-known domains list:

* Anti-AD domains: [anti-ad-domains.txt](https://github.com/privacy-protection-tools/anti-AD/blob/master/anti-ad-domains.txt)
* CN domains: [cn-domains.txt](https://gist.github.com/aofei/aa9880b4fb6100448ee9576e3f215054)
* Other domains(apple/google): get from [here](https://github.com/felixonmars/dnsmasq-china-list), some conversions are required

GeoIP2 MMDB
-----------

You can get `Country.mmdb` from [here](https://github.com/P3TERX/GeoLite.mmdb).

Work with stunnel and gatewaysocks
----------------------------------

* [stunnel](https://github.com/airtrack/stunnel)
* [gatewaysocks](https://github.com/airtrack/gatewaysocks)

```
    ----------------                 -------------                        -------------
    |              |                 |           |                        |           |
    | gatewaysocks | --- TCP/UDP --> | autoproxy | ------- TCP/UDP -----> |  stunnel  |
    |              |                 |           |    |                   |           |
    ----------------                 -------------    |                   -------------
           ^                               ^          |
           |                               |          |                   -------------
           |                               |          |                   |           |
           |                               |          |--- TCP/UDP -----> |  direct   |
           |                               |                              |           |
           |                               |                              -------------
    -----------------             ------------------
    |    devices    |             |   set system   |
    |  in the same  |             | proxy settings |
    |    router     |             |  to autoproxy  |
    -----------------             ------------------
```
