This script allows users to configure IP addresses in LXD containers using
MAAS 2.0 and juju 2.0


How?
----

Steps:

1. Create a device with MAC_ADDRESS and assign it as child of NODE_ID
2. Connect device to SUBNET
3. Create a link for the interface
4. Connect to the LXD host (NODE_ID) and find which NIC is the one with MAC_ADDRESS (e.g. eth1)
5. Generate interface(5) configuration for the nic
6. Backup /etc/network/interfaces (`cp /etc/network/interfaces /etc/network/interfaces.$TIMESTAMP`)
7. If the script is called `--wirte-interfaces`, then append the configuration to /etc/network/interfaces

Note: This script DOES NOT bring up the interface (ifup ethX)

Why?
----

Juju 2.0 doesn't assign IPv6 addresses to containers deployed (See
[LP: #1590598](https://bugs.launchpad.net/juju-core/+bug/1590598), and we were
in the need of attaching those subnets to a bunch of containers of an
OpenStack cloud

Configuration
-------------

The configuration file is a yaml with the following format:

```yaml
machines:
  <NODE_ID>:
    <CONTAINER_NAME>:
      interfaces:
        - mac_address: XX:XX:XX:XX:XX:XX
          subnets:
            - "<SUBNET_NAME>"
```

Usage Example
-------------

Example from a real system:

```yaml
machines:
  4y3h7s:  # maas-node04.maas
    "juju-77d6fb-4-lxd-0.maas":
      interfaces:
        - mac_address: 00:16:3e:dc:98:f0
          subnets:
            - "fd37:eb0d:caae:ece8::/64"
            - "192.168.51.0/24"
        - mac_address: 
          subnets:
            - "fd37:eb0d:caae:ece8::/64"
  4y3h7r:  # maas-node03.maas
    juju-77d6fb-1-lxd-0.maas:
      interfaces:
        - mac_address: 00:16:3e:51:85:01
          subnets:
            - "fd37:eb0d:caae:ece8::/64"
    juju-77d6fb-1-lxd-1.maas:
      interfaces:
        - mac_address: 00:16:3e:5a:9b:ce
          subnets:
          - "fd37:eb0d:caae:ece8::/64"
```


```
$ ./allocate_maas_ip.py --mac-addresses macs.yaml --write-interfaces
```
