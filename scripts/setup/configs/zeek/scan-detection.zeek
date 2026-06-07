##! Minimal port-scan detection for Suburban-SOC (Issue #22, task 1).
##!
##! Modern Zeek no longer ships the legacy Scan framework, so a SYN sweep
##! produces conn.log rows but never a `Scan::Port_Scan` notice — which is the
##! exact signal the validation harness (tests/anomaly_simulation) and the
##! Executive dashboard's MITRE T1046 mapping key on.
##!
##! This script restores that signal: it counts the distinct destination ports
##! each source touches within a window and raises one `Scan::Port_Scan` notice
##! once a source crosses the threshold.
##!
##! Load it alongside the site policy, e.g.:
##!   sudo /opt/zeek/bin/zeek -C -i lo Log::default_logdir=/storage/PCAP/zeek_logs \
##!        LogAscii::use_json=T local \
##!        /home/<you>/projects/Suburban-SOC/scripts/setup/configs/zeek/scan-detection.zeek

@load base/frameworks/notice

module Scan;

export {
    redef enum Notice::Type += {
        ## A single source probed many distinct ports in a short window.
        Port_Scan,
    };

    ## Distinct destination ports from one source that trips the notice.
    option port_scan_threshold: count = 20;

    ## Sliding window over which distinct ports are counted per source.
    option port_scan_interval: interval = 5 min;
}

# Distinct destination ports seen per source, expiring on inactivity.
global ports_per_src: table[addr] of set[port]
    &create_expire = port_scan_interval;

# Sources already alerted on, so we emit one notice per scan, not per port.
global already_flagged: set[addr] &create_expire = port_scan_interval;

# new_connection fires on the initial SYN, so every probed port is counted
# regardless of whether the port is open, closed, or filtered.
event new_connection(c: connection)
    {
    local src = c$id$orig_h;

    if ( src in already_flagged )
        return;

    if ( src !in ports_per_src )
        ports_per_src[src] = set();

    add ports_per_src[src][c$id$resp_p];

    if ( |ports_per_src[src]| >= port_scan_threshold )
        {
        add already_flagged[src];
        NOTICE([$note = Scan::Port_Scan,
                $conn = c,
                $src = src,
                $msg = fmt("%s probed %d+ distinct ports", src, port_scan_threshold),
                $identifier = cat(src)]);
        }
    }
