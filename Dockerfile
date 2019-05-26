FROM alpine:3.9

# Copyright (C) 2019 Karim Kanso. All Rights Reserved.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Define HOME_NET, used by IDS, must be specified otherwise init will fail
ENV HOME_NET=any
# Default EXTERNAL_NET, can be left unchanged
ENV EXTERNAL_NET="!\$HOME_NET"
# Default interface to listen on
ENV INTERFACE=eth0
# Default mode to operate in. no=IDS, yes=IPS
ENV INLINE=no
# By default do not select a policy: manual, security-ips, balanced-ips, connectivity-ips
ENV POLICY=manual
# Must set to valid OINKCODE, see snort.org
ENV OINKCODE=<oinkcode>
# Log alerts to stdout: none, fast or full
ENV STDOUT=fast
# Location logs and packet captures are stored
ENV LOG_DIR=/var/log/snort/
# Log alerts to file: none, fast or full
ENV LOG_ALERTS=none
# Default base filename for alerts
ENV ALERT_FILENAME=alert.log
# Format used for packet captures: pcap or unified2
ENV PACKET_CAPTURE_FORMAT=pcap
# Default base file name for pcap logs
ENV PCAP_FILENAME=snort.pcap
# Default base file name for unified2 logs
ENV UNIFIED2_FILENAME=snort.u2
# Disable syslog logging by default
ENV SYSLOG=no
# Default syslog server
ENV SYSLOG_SERVER=10.0.0.1:514
# Default syslog facility; LOCAL4 is the same used by ASA
ENV SYSLOG_FACILITY=log_local4
# Default syslog priority
ENV SYSLOG_PRIORITY=log_alert
# Enable portscan detection: yes or no
ENV PORTSCAN=yes

# Persist location rules are stored
VOLUME ["/var/lib/snort/"]

RUN apk add --no-cache ethtool iptables

COPY daq-sfbpf-2.0.6-r4.apk /tmp
RUN apk add --allow-untrusted /tmp/daq-sfbpf-2.0.6*.apk

COPY snort-2.9.13-r3.apk /tmp
RUN apk add --allow-untrusted /tmp/snort-2.9.13*.apk

COPY entrypoint.sh /

ENTRYPOINT ["/entrypoint.sh"]

CMD snort -c /var/lib/snort/etc/snort.conf.patched $(test "${INLINE}" == "no" || echo "-Q")
