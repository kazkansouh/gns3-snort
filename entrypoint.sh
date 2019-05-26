#! /bin/sh

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


#
# entrypoint.sh: used to load current ruleset into snort and configure
# essential variables.
#

RULE_DIR=/var/lib/snort/
CONFIG=${RULE_DIR}/etc/snort.conf.patched

PADDING=00000
VERSION=$(apk list snort -I 2>/dev/null \
              | awk -F- '/^snort-/ {print $2}' | sed -e 's/\.//g')
RULE_URL=$(printf \
               "https://www.snort.org/rules/snortrules-snapshot-%s%s.tar.gz" \
               ${VERSION} ${PADDING:${#VERSION}})

echo Preparing SNORT

if test ! -f ${CONFIG} ; then
    echo Initilising rules

    if test "<oinkcode>" == "${OINKCODE}" -o -z "${OINKCODE}" ; then
        echo ERROR: Oinkcode not set, please register on snort.org and set \
             environment variable OINKCODE
        exit 1
    fi

    echo Downloading ${RULE_URL}
    cd ${RULE_DIR}
    if ! wget --quiet ${RULE_URL}?oinkcode=${OINKCODE} -O - | tar xz ; then
        echo ERROR: Failed to download rules
        exit 1
    fi

    # RHEL-7 binaries appear to load ok
    DYN_DETECT=$(realpath /var/lib/snort/so_rules/precompiled/RHEL-7/x86-64/*)
    if test ! -d "${DYN_DETECT}";  then
        echo ERROR: Failed to locate pre-comipled binaries
        exit 1
    fi

    # current version of snort in alpine does not have lzma support,
    # so it needs to be disabled in the config.
    sed -e 's|/usr/local|/usr|' -e "s|\.\./|${RULE_DIR}|" \
        -e 's|lzma||' \
        -e '/^# *config logdir:/a\\nconfig interface: eth0' \
        -e '/^# *unified2/iinclude output.conf\n' \
        -e '/^# *include $SO_RULE_PATH/s/^# *//' \
        -e "s|^# *\(dynamicdetection directory\).*$|\1 ${DYN_DETECT}|" \
        -e '/^# *include $PREPROC_RULE_PATH/s/^# *//' \
        -e 's|^# *\(config daq:\).*$|\1 afpacket|' \
        etc/snort.conf > ${CONFIG} || {
        echo ERROR: Failed to patch config file
        rm -f ${CONFIG}
        exit 1
    }

    echo One-shot generation of ${CONFIG} completed
fi

echo Setting HOME_NET to ${HOME_NET}
sed -i -E -e "s|^(ipvar HOME_NET).*$|\1 ${HOME_NET}|" ${CONFIG}

echo Setting EXTERNAL_NET to ${EXTERNAL_NET}
sed -i -E -e "s|^(ipvar EXTERNAL_NET).*$|\1 ${EXTERNAL_NET}|" ${CONFIG}

case "${INLINE}" in
    no|l2)
        echo Configuring interface ${INTERFACE}
        sed -i -E -e "s|^(# *)?(config interface:).*$|\2 ${INTERFACE}|" \
            -e 's|^(# *)?(config daq:).*$|\2 afpacket|' \
            -e 's|^config daq_var:.*$|# &|' ${CONFIG}
        for int in $(echo ${INTERFACE} | tr ':' '\n') ; do
            if test -n "${int}" ; then
                ethtool -K ${int} gro off
                ethtool -K ${int} lro off
            fi
        done
    ;;
    l3)
        echo Setting up layer 3 ipv4 IPS
        sed -i -E -e 's|^config interface:.*$|# &|' \
            -e 's|^(# *)?(config daq:).*$|\2 nfq|' \
            -e 's|^(# *)?(config daq_var:).*$|\2 queue=1|' ${CONFIG}
        sysctl net.ipv4.ip_forward=1
        iptables -A FORWARD -j NFQUEUE --queue-num=1
        ;;
    *)
        echo ERROR: INLINE should be in: no, l2, l3
        exit 1
esac

if test "${PORTSCAN}" == "yes" ; then
    echo Enabling sfPortscan preprocessor
    sed -i -e '/^# *preprocessor sfportscan/s/# *//' ${CONFIG}
else
    echo Disabling sfPortscan preprocessor
    sed -i -E -e 's|^(preprocessor sfportscan)|# \1|' ${CONFIG}
fi

echo Configuring output modules
case "${STDOUT}" in
    fast|full)
    ;;
    none)
        DISABLE_STDOUT="# "
        ;;
    *)
        echo ERROR: STDOUT should be in: full, fast, none
        exit 1
        ;;
esac
case "${LOG_ALERTS}" in
    fast|full)
    ;;
    none)
        DISABLE_ALERTS="# "
        ;;
    *)
        echo ERROR: LOG_ALERTS should be in: full, fast, none
        exit 1
        ;;
esac
case "${PACKET_CAPTURE_FORMAT}" in
    unified2)
        DISABLE_PCAP="# "
    ;;
    pcap)
        DISABLE_UNIFIED2="# "
    ;;
    *)
        echo ERROR: PACKET_CAPTURE_FORMAT should be either: unified2 or pcap
        exit 1
    ;;
esac
if test "${SYSLOG}" != "yes" ; then
    DISABLE_SYSLOG="# "
else
    # start busybox syslogd and forward messages
    syslogd -R ${SYSLOG_SERVER}
fi
cat - > ${RULE_DIR}/etc/output.conf <<EOF
config logdir: ${LOG_DIR}
${DISABLE_STDOUT}output alert_${STDOUT}: stdout
${DISABLE_ALERTS}output alert_${LOG_ALERTS}: ${ALERT_FILENAME}
${DISABLE_UNIFIED2}output unified2: filename ${UNIFIED2_FILENAME}, limit 128
${DISABLE_PCAP}output log_tcpdump: ${PCAP_FILENAME} 128M
${DISABLE_SYSLOG}output alert_syslog: ${SYSLOG_FACILITY} ${SYSLOG_PRIORITY}
EOF

case "${POLICY}" in
    security|balanced|connectivity|max-detect)
        if test "${INLINE}" == "l2" -o "${INLINE}" == "l3" ; then
            ACTION="\4"
        else
            ACTION="alert"
        fi
        for RULE_PATH in /var/lib/snort/rules/ /var/lib/snort/so_rules/ ; do
            if test ! -d "${RULE_PATH}" ; then
                echo ERROR: ${RULE_PATH} is not a directory
                exit 1
            fi
            for FILE in ${RULE_PATH}*.rules ; do
                if test ! -f "${FILE}" ; then
                    echo ERROR: ${FILE} is not a valid file
                    exit 1
                fi
                echo Applying ${POLICY} policy to ${FILE}
                sed -E -i -f - ${FILE} <<EOF
s/^(# +)?(alert|drop) +(.*${POLICY}-ips +)(alert|drop)(.*)/${ACTION} \3\4\5/
t
s/^[^#](alert|drop).*/# &/
EOF
            done
        done
    ;;
    manual)
        echo Skipping policy configuration
    ;;
    *)
        echo ERROR: POLICY should be in: manual, security, balanced, \
             connectivity, max-detect
        exit 1
esac

echo Continuing boot

cd /
exec "$@"
