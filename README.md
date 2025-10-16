AutoProxy
=========

Auto choose proxy or not by rules.

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
    ----------------                 -------------                        -----------
    | gatewaysocks | --- TCP/UDP --> | autoproxy | ------- TCP/UDP -----> | stunnel |
    ----------------                 -------------    |                   -----------
           ^                               ^          |                   -----------
           |                               |          |--- TCP/UDP -----> |  direct |
           |                               |                              -----------
    -----------------             ------------------
    |    devices    |             |   set system   |
    |  in the same  |             | proxy settings |
    |    router     |             |  to autoproxy  |
    -----------------             ------------------
```
