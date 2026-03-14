AutoProxy
=========

Auto choose proxy or not by rules.

* TCP connections are automatically proxied or directly connected according to the rules.
* UDP packets are sent directly to the destination address or via a proxy, based on matching rules for the destination address.
* DNS server, according to the rules, directly resolves to the upstream DNS or goes through a proxy to resolve to the upstream DNS.

Usage
-----

```
./autoproxy autoproxy.toml
```

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
