# ZealFirewall

Linux firewall powered by eBPF and XDP written in Zig.

# Requirements
* zig-linux-x86_64-0.14.0-dev.3456+00a8742bb
* Linux Kernel 6.6+

# Support feature

* IPv4
* IPv6
* TCP
* UDP
* ICMP

# Usage

Clone zbpf.

Put this repo in zbpf.

Add dependencies in `build.zig.zon` and `build.zig`.

```shell
zig build ZealFirewall
# change lo if you need
sudo ./ZealFirewall -i lo
```

# API

## Get all rules

GET /api/v1/rules

## Add rule

POST /api/v1/rule

```json
{
    "src_addr": "127.0.0.1",
    "dst_port": 8000,
    "ip_proto": 6
}
```

> Proto 6 is TCP

```json
{
    "src_addr": "127.0.0.1",
    "dst_port": 8000,
    "ip_proto": 17
}
```

> Proto 17 is UDP

## Get rule

GET /api/v1/rule

```json
{
    "src_addr": "127.0.0.1",
    "dst_port": 8000,
    "ip_proto": 6
}
```

## Delete rule

DELETE /api/v1/rule

```json
{
    "src_addr": "127.0.0.1",
    "dst_port": 8000,
    "ip_proto": 6
}
```

# Reference

[EtherType](https://zh.wikipedia.org/wiki/%E4%BB%A5%E5%A4%AA%E7%B1%BB%E5%9E%8B)

[IPv4](https://zh.wikipedia.org/wiki/IPv4)

[IPv6](https://zh.wikipedia.org/wiki/IPv6)

[IP protocol numbers](https://zh.wikipedia.org/wiki/IP%E5%8D%8F%E8%AE%AE%E5%8F%B7%E5%88%97%E8%A1%A8)

[TCP](https://zh.wikipedia.org/wiki/%E4%BC%A0%E8%BE%93%E6%8E%A7%E5%88%B6%E5%8D%8F%E8%AE%AE)

[UDP](https://zh.wikipedia.org/wiki/%E7%94%A8%E6%88%B7%E6%95%B0%E6%8D%AE%E6%8A%A5%E5%8D%8F%E8%AE%AE)
