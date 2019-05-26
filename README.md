# *snort* Docker image for GNS3

Alpine based image of *snort* designed for use within GNS3. If it
detects `/var/lib/snort/` has not been initialised fetch latest rules
from [snort.org](https://snort.org). The startup script will also set
essential configuration, e.g. setting home network, enabling/disabling
rules based on policy, setup of logging and support for port scan
detection.

All the configuration is performed directly within the startup script
without using *pulledpork*. This was done primarily for me to learn
how *snort* works (thus this *readme* contains lots of information I
have learned while creating the image) and secondarily to have a
light-weight version of *snort* to use within GNS3 for labbing. That
is, the image is not intended for any serious use.

The startup script facilitates running *snort* in 3 different modes:

* **tap/passive/IDS**: Single connection that receives a flow of
  frames to analyse for intrusion attempts. This will raise alerts/log
  offending packets.
* **l2 inline/transparent IPS**: Bridges two network connections, so
  that its possible for *snort* to detect, discard and log
  frames. [More info][ips-afpacket].
* **l3 inline/routed IPS**: Enables Linux to forward packets between
  arbitrary interfaces. *snort* uses `iptables` to intercept all
  forwarded packets, so its possible to detect, discard and log
  packets. [More info][ips-nfq].

## Environment Variables

All the following (except `OINKCODE` and `POLICY`) are used to
customise `snort.conf` file. Please check the `entrypoint.sh` file
which customises the configuration file and snort documentation for
more information.

| Name                    | Purpose                                                                                                                                    |
| ---                     | ---                                                                                                                                        |
| `OINKCODE`              | Used when downloading *registered* rules. Register on [snort.org][snort-rule-download] to get a code.                                      |
| `POLICY`                | Policy name; see [(1)][snort-rules], [(2)][cisco-rules]. Values: `manual` (default), `security`, `balanced`, `connectivity`, `max-detect`. |
| `HOME_NET`              | See snort documentation of `HOME_NET` configuration.                                                                                       |
| `EXTERNAL_NET`          | See snort documentation of `EXTERNAL_NET` configuration.                                                                                   |
| `INTERFACE`             | When not inline, set to single interface. When in `l2` inline, set as `ethX:ethY`. Not used for `l3` inline. Default `eth0`.               |
| `INLINE`                | Run inline as an IPS. Values: `l3` (use `nfq` in `iptables`), `l2` (use `afpacket`), `no` (default - run as IDS).                          |
| `STDOUT`                | Whether alerts are printed to stdout. Values: `none`, `fast` (default), `full`.                                                            |
| `LOG_DIR`               | Location logs and packet captures are stored. Default: `/var/log/snort`                                                                    |
| `LOG_ALERTS`            | Whether alerts are logged to a file. Values: `none` (default), `fast`, `full`.                                                             |
| `ALERT_FILENAME`        | File to log alerts to. Default: `alert.log`.                                                                                               |
| `PACKET_CAPTURE_FORMAT` | Format used for logging packet captures. Values `pcap` (default), `unified2`.                                                              |
| `PCAP_FILENAME`         | Base filename for `pcap` files. Snort will append epoch. Default: `snort.pcap`.                                                            |
| `UNIFIED2_FILENAME`     | Base filename for `unified2` files. Snort will append epoch. Default: `snort.u2`.                                                          |
| `SYSLOG`                | Enable sending alerts over syslog. Values: `yes` or `no` (default).                                                                        |
| `SYSLOG_SERVER`         | Configure `busybox`'s `syslogd`. Default: `10.0.0.1:514`.                                                                                  |
| `SYSLOG_FACILITY`       | See snort documentation of *Output Modules* for values. Default: `log_local4`.                                                             |
| `SYSLOG_PRIORITY`       | See snort documentation of *Output Modules* for values. Default: `alert`.                                                                  |
| `PORTSCAN`              | Enable portscan detection (uses `sfportscan`). Values: `yes` (default), `no`.                                                              |

## Usage

Basic usage to start in IDS mode is as follows:

```
docker run -t -i --rm           \
  -e OINKCODE=<oinkcode>        \
  -e HOME_NET=192.168.0.0/24    \
  -v /host/path:/var/lib/snort/ \
  karimkanso/gns3-snort
```

The first time this is run, it will download the needed rules into
`/var/lib/snort/` and patch the configuration file. Further executions
will detect the configuration file and directly start `snort` without
downloading the rules again.

To edit the configuration file on the host, it will be found at
`/host/path/etc/snort.conf.patched` after running the above command.

Its possible to edit the startup command in the usual docker way. For
example, the above command would be equivalent to:

```
docker run -t -i --rm           \
  -e OINKCODE=<oinkcode>        \
  -e HOME_NET=192.168.0.0/24    \
  -v /host/path:/var/lib/snort/ \
  karimkanso/gns3-snort         \
  snort -c /host/path/etc/snort.conf.patched
```

**Note:** when starting in IDS mode (or layer 2 IPS), it is desirable
that the interface snort is configured to use does not have an ip
address configured. Hence, the normal way (as in the example above) of
starting a docker container with a pre-configured layer 3 routed
interface is not a good configuration. Depending on the situation it
might be recommended to either (I have not tested either as image is
intended for GNS3):

1. allow the docker container to access a `tap` or physical ethernet
   device on the host that can provide a feed of frames to analyse
   (e.g. using `--network host`).
2. start the container with `NET_ADMIN` cap, remove the ip address
   from the interface inside the container (e.g. `ip add del
   172.17.0.x/16 dev eth0`) and mirror traffic between another
   interface to this container (possibly the docker bridge to catch
   all network traffic). Mirroring is described [here][docker-mirror].

Running *snort* as a layer 3 IPS within docker is the cleanest option
as it avoids the need for providing access to layer 2 devices. This is
done by attaching the docker container to all the needed networks and
starting it with environment variable: `INLINE=l3`.

### Usage in GNS3

**TODO:** Download and import the following appliance file.

#### IDS Setup

The typical setup of *snort* to perform network IDS is as follows.

```
                      eth0  ---------  eth2..n
 external network ---------| vSwitch |---------- internal network
     * e.g. internet        ---------
                               | eth1
                               |
                               |
                               | eth0
                             -------
                            | snort |---------- management interface
                             -------  eth1          * access to snort.org
                                                    * syslog server (if configured)
```

Configure `eth1` with an internet connection and `eth0` to only
receive frames. E.g. the following demonstrates a possible
`/etc/network/interfaces` configuration.

```
auto eth0
iface eth0 inet manual
    # prevent NDP processing (i.e. RA/RS)
	pre-up echo 1 > /proc/sys/net/ipv6/conf/eth0/disable_ipv6

auto eth1
iface eth1 inet static
	address 192.168.1.2
	netmask 255.255.255.0
	gateway 192.168.1.1
	up echo nameserver 8.8.8.8 > /etc/resolv.conf
```

Take caution with the topology of the management interface (`eth1`),
when the image starts for the first time it will attempt to download
the rules from `snort.org`. This is approx *100MiB*. Downloading
through virtual appliances running in evaluation mode or
non-production images (e.g. rate limited) is not recommended as it
will end up taking a few minutes extra (or can even crash the
appliance).

**Management Interface:** To provide packets to `eth0` its required to
create a network tap.  Using Local SPAN on Cisco IOSvL2 images is not
stable and not recommended (I have not tested Nexus 9K). Consider
using an [Open vSwitch](http://openvswitch.org) appliance instead. To
enable port mirroring from `eth0` (external network facing) to `eth1`
(snort/ids facing) on *vSwitch*, (assuming `eth0`, `eth1` and
`eth2..n` are in `br0` and traffic flow is between `eth0` and `eth2.n`
that is to be tapped) issue the following command:

```bash
ovs-vsctl --id=@e0 get Port eth0 --      \
          --id=@e1 get Port eth1 --      \
          --id=@m create Mirror name=ids \
              select_dst_port=@e0        \
              select_src_port=@e0        \
              output_port=@e1 --         \
          set Bridge br0 mirrors=@m
```

More information about *vSwitch* configuration can be found in the man
pages:
[ovs-vsctl](http://www.openvswitch.org/support/dist-docs/ovs-vsctl.8.html),
[ovs-vswitchd.conf.db](http://www.openvswitch.org/support/dist-docs/ovs-vswitchd.conf.db.5.html).

Configure the *snort* appliance with the following environment
variables:

* `OINKCODE=abc` set to your [oinkcode][snort-oink].
* `HOME_NET=x.x.x.x/yy` set to internal network.
* `INTERFACE=eth0` interface connected to tap (default).
* `INLINE=no` operate as IDS (default).

#### L2 IPS

The typical setup of *snort* to perform layer 2 IPS is as follows.

```
                      eth0   -------  eth1
 external network ----------| snort |---------- internal network
     * e.g. internet         -------
                                | eth2
                                |
                                |
                            management interface
                                * access to snort.org
                                * syslog server (if configured)
```

Configure `eth2` with an internet connection (see notes about
management interface in [IDS Setup](#ids-setup)) and `eth0`/`eth1` to
only receive frames. E.g. the following demonstrates a possible
`/etc/network/interfaces` configuration.

```
auto eth0
iface eth0 inet manual
    # prevent NDP processing (i.e. RA/RS)
	pre-up echo 1 > /proc/sys/net/ipv6/conf/eth0/disable_ipv6

auto eth1
iface eth1 inet manual
    # prevent NDP processing (i.e. RA/RS)
	pre-up echo 1 > /proc/sys/net/ipv6/conf/eth1/disable_ipv6

auto eth2
iface eth2 inet static
	address 192.168.1.2
	netmask 255.255.255.0
	gateway 192.168.1.1
	up echo nameserver 8.8.8.8 > /etc/resolv.conf
```

Configure the *snort* appliance with the following environment
variables:

* `OINKCODE=abc` set to your [oinkcode][snort-oink].
* `HOME_NET=x.x.x.x/yy` set to internal network.
* `INTERFACE=eth0:eth1` interfaces to bridge.
* `INLINE=l2` operate as IDS.
* `POLICY=balanced` select balanced policy.

#### L3 IPS

The typical setup of *snort* to perform layer 3 IPS is as follows.

```
                      eth0   -------  eth1
 external network ----------| snort |---------- internal network
     * e.g. internet         -------                * syslog server (if configured)
     * access to snort.org
     * access to dns server
```

Configure `eth0` and `eth1` as normal interfaces with ip
addresses. However, it is suggested to configure `eth0` with a default
gateway and `eth1` with only an ip address. See notes about management
interface in [IDS Setup](#ids-setup) as they apply to `eth0` in this
configuration. The following demonstrates a possible
`/etc/network/interfaces` configuration.

```
auto eth0
iface eth0 inet static
	address 192.168.1.2
	netmask 255.255.255.0
	gateway 192.168.1.1
	up echo nameserver 8.8.8.8 > /etc/resolv.conf

auto eth1
iface eth1 inet static
	address 192.168.2.1
	netmask 255.255.255.0
    # optional, add needed internal routes
    up ip route add x.x.x.x/yy via 192.168.2.z
```

Configure the *snort* appliance with the following environment
variables:

* `OINKCODE=abc` set to your [oinkcode][snort-oink].
* `HOME_NET=x.x.x.x/yy` set to internal network.
* `INLINE=l3` operate as IPS.
* `POLICY=balanced` select balanced policy.

The this image does not pass traffic directed to the host to *snort*
or use `iptables` to restrict access. That is, only traffic that is
forwarded is passed through *snort*.

#### Policies

The [registered subscribers rules][snort-rule-download] are grouped
into (overlapping) policies. Each rule that is a member of a policy
has a default action that it should perform (`alert` or
`drop`). However, when the rule set is first downloaded, essentially
the `balanced` is pre-enabled but all actions are set to `alert`.

This is a good configuration for running *snort* as a IDS, but results
when running *snort* as an inline IPS that it does not drop any
packets. Thus, when running as IPS, its essential to set the `POLICY`
variable to a policy.

When `POLICY` is set, it will iterate over the rules and
enable/disable the rules according to the selected policy. When a rule
is enabled, it will also set the action to `alert` or `drop` in
accordance with the meta-data in the rule. Cisco has some [useful
information][cisco-rules] about this.

## Other Bits

Some [useful information][ids] relating to configuring *snort* for the
first time.

Copyright 2019 Karim Kanso

[ids]: https://www.securityarchitecture.com/learning/intrusion-detection-systems-learning-with-snort/configuring-snort-on-linux/ "SecurityArchitecture.com: Configuring Snort on Linux"
[ips-afpacket]: http://sublimerobots.com/2016/02/snort-ips-inline-mode-on-ubuntu/ "SublimeRobots.com: Snort IPS Inline Mode on Ubuntu"
[ips-nfq]: http://sublimerobots.com/2017/06/snort-ips-with-nfq-routing-on-ubuntu/ "SublimeRobots.com: Snort IPS With NFQ (nfqueue) Routing on Ubuntu"
[snort-rules]: https://www.snort.org/faq/why-are-rules-commented-out-by-default "Snort.org: Why are rules commented out by default?"
[cisco-rules]: https://www.cisco.com/c/en/us/support/docs/security/firesight-management-center/117891-config-firewall-00.html "Cisco.com: Determination of the default state for a Sourcefire provided rule in an intrusion policy"
[snort-rule-download]: https://www.snort.org/downloads/#rule-downloads "Snort.org: Snort Rules and IDS Software Download"
[snort-oink]: https://www.snort.org/oinkcodes "Snort.org: Oinkcodes"
[docker-mirror]: https://stackoverflow.com/a/38747127/5660642 "StackOverflow.com: Docker - traffic mirroring"
