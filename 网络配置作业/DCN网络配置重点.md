```shell
switch mode trunk 
switchport trunk allow vlan x;x;x;  #trunk包含哪些vlan
```

# 配置XX服务

```sh
XX-server enable #第一步
```

# 善用”?“

# 配置二层隔离

```
isolate-port group 1 switchport interface ethernet 1/0/4-8 
isolate-port apply l2

loopback-detection interval-time 15 15
loopback-detection control-recovery timeout 1800
interface ethernet 1/0/4-8 
loopback-detection control shutdown
loopback-detection specifiled-vlan 40
```

# 配置DHCP

```

```

