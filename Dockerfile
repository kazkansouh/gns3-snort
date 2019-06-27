FROM alpine:edge

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


RUN apk --no-cache add --virtual build-dependencies \
        go git musl-dev && \
        \
        go get github.com/kazkansouh/u2text && \
        cp /root/go/bin/u2text /usr/bin/ && \
        rm -rf /root/go && \
        apk del build-dependencies


# Define HOME_NET, used by IDS, must be specified otherwise init will fail
ENV HOME_NET=any
# Default EXTERNAL_NET, can be left unchanged
ENV EXTERNAL_NET="!\$HOME_NET"
# Default interface to listen on
ENV INTERFACE=eth0
# Default mode to operate in. no=IDS, l2 and l3=IPS
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
ENV PACKET_CAPTURE_FORMAT=unified2
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
# Disable u2text post processor by default
ENV U2_ENABLE=no
# Do not specify a default GELF server (e.g. Graylog)
ENV U2_GELF=
# Do not specify a default syslog server
ENV U2_SYSLOG=
# Enable u2text reports to stdout when u2text is enabled
ENV U2_STDOUT=yes
# Disable u2text reports of packets to indlude hexdumps
ENV U2_STDOUT_HEXDUMP=no
# Disable u2text packetserver by default (set to base url of this host)
ENV U2_PACKETSERVER_URL=

# Persist location rules are stored
VOLUME ["/var/lib/snort/"]

RUN apk add --no-cache ethtool iptables snort tshark

COPY entrypoint.sh /

ENTRYPOINT ["/entrypoint.sh"]

CMD snort -c /var/lib/snort/etc/snort.conf.patched $(test "${INLINE}" == "no" || echo "-Q")
