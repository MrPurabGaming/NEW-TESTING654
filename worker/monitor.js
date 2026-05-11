'use strict';

const { parentPort, workerData } = require('worker_threads');
const { exec } = require('child_process');
const { promisify } = require('util');

const execAsync = promisify(exec);
const isLinux = process.platform === 'linux';

let monitoringInterval = workerData?.interval || 3000;
let running = true;

// Listen for messages from main thread
parentPort.on('message', (msg) => {
    if (msg.type === 'set_interval') {
        monitoringInterval = msg.interval;
    } else if (msg.type === 'stop') {
        running = false;
    } else if (msg.type === 'ping') {
        parentPort.postMessage({ type: 'pong', timestamp: Date.now() });
    }
});

// ==================== MONITORING FUNCTIONS ====================

async function monitorActiveConnections() {
    if (!isLinux) return {};
    try {
        const { stdout } = await execAsync(
            `ss -ntu state established 2>/dev/null | awk 'NR>1 {split($5, a, ":"); print a[1]}' | sort | uniq -c | sort -rn | head -50`,
            { timeout: 5000 }
        );
        const connections = {};
        const lines = stdout.trim().split('\n').filter(l => l.trim());
        for (const line of lines) {
            const parts = line.trim().split(/\s+/);
            if (parts.length >= 2) {
                const count = parseInt(parts[0]);
                const ip = parts[1];
                if (ip && count > 0) connections[ip] = count;
            }
        }
        return connections;
    } catch (err) {
        return {};
    }
}

async function monitorAllConnectionStates() {
    if (!isLinux) return {};
    try {
        const { stdout } = await execAsync(
            `ss -nta 2>/dev/null | awk 'NR>1 {split($4, a, ":"); print $1, a[1]}' | sort | uniq -c | head -200`,
            { timeout: 5000 }
        );
        const states = {};
        const lines = stdout.trim().split('\n').filter(l => l.trim());
        for (const line of lines) {
            const parts = line.trim().split(/\s+/);
            if (parts.length >= 3) {
                const count = parseInt(parts[0]);
                const state = parts[1];
                const ip = parts[2];
                if (!states[ip]) states[ip] = {};
                states[ip][state] = (states[ip][state] || 0) + count;
            }
        }
        return states;
    } catch (err) {
        return {};
    }
}

async function monitorSynFlood() {
    if (!isLinux) return {};
    try {
        const { stdout } = await execAsync(
            `ss -ntu state syn-recv 2>/dev/null | awk 'NR>1 {split($4, a, ":"); print a[1]}' | sort | uniq -c | sort -rn | head -30`,
            { timeout: 5000 }
        );
        const synIPs = {};
        const lines = stdout.trim().split('\n').filter(l => l.trim());
        for (const line of lines) {
            const parts = line.trim().split(/\s+/);
            if (parts.length >= 2) {
                const count = parseInt(parts[0]);
                const ip = parts[1];
                if (ip && count > 0) synIPs[ip] = count;
            }
        }
        return synIPs;
    } catch (err) {
        return {};
    }
}

async function detectPortScanning() {
    if (!isLinux) return {};
    try {
        const { stdout } = await execAsync(
            `ss -ntu 2>/dev/null | awk 'NR>1 {split($4, a, ":"); split($5, b, ":"); print b[1], a[length(a)]}' | sort | uniq | awk '{print $1}' | sort | uniq -c | sort -rn | head -20`,
            { timeout: 5000 }
        );
        const scanners = {};
        const lines = stdout.trim().split('\n').filter(l => l.trim());
        for (const line of lines) {
            const parts = line.trim().split(/\s+/);
            if (parts.length >= 2) {
                const portCount = parseInt(parts[0]);
                const ip = parts[1];
                if (ip && portCount > 5) scanners[ip] = portCount;
            }
        }
        return scanners;
    } catch (err) {
        return {};
    }
}

async function detectUDPFlood() {
    if (!isLinux) return {};
    try {
        const { stdout } = await execAsync(
            `ss -nua 2>/dev/null | awk 'NR>1 {split($5, a, ":"); print a[1]}' | sort | uniq -c | sort -rn | head -20`,
            { timeout: 5000 }
        );
        const udpIPs = {};
        const lines = stdout.trim().split('\n').filter(l => l.trim());
        for (const line of lines) {
            const parts = line.trim().split(/\s+/);
            if (parts.length >= 2) {
                const count = parseInt(parts[0]);
                const ip = parts[1];
                if (ip && count > 20) udpIPs[ip] = count;
            }
        }
        return udpIPs;
    } catch (err) {
        return {};
    }
}

async function detectTimeWaitAbuse() {
    if (!isLinux) return {};
    try {
        const { stdout } = await execAsync(
            `ss -ntu state time-wait 2>/dev/null | awk 'NR>1 {split($4, a, ":"); print a[1]}' | sort | uniq -c | sort -rn | head -20`,
            { timeout: 5000 }
        );
        const twIPs = {};
        const lines = stdout.trim().split('\n').filter(l => l.trim());
        for (const line of lines) {
            const parts = line.trim().split(/\s+/);
            if (parts.length >= 2) {
                const count = parseInt(parts[0]);
                const ip = parts[1];
                if (ip && count > 50) twIPs[ip] = count;
            }
        }
        return twIPs;
    } catch (err) {
        return {};
    }
}

async function detectHighConnectionIPs() {
    if (!isLinux) return {};
    try {
        const { stdout } = await execAsync(
            `ss -ntu 2>/dev/null | awk 'NR>1 {split($5, a, ":"); print a[1]}' | sort | uniq -c | sort -rn | head -30`,
            { timeout: 5000 }
        );
        const highConn = {};
        const lines = stdout.trim().split('\n').filter(l => l.trim());
        for (const line of lines) {
            const parts = line.trim().split(/\s+/);
            if (parts.length >= 2) {
                const count = parseInt(parts[0]);
                const ip = parts[1];
                if (ip && count > 50) highConn[ip] = count;
            }
        }
        return highConn;
    } catch (err) {
        return {};
    }
}

async function getServerStats() {
    const stats = {
        cpu_load: [0, 0, 0],
        memory: { total: 0, used: 0, free: 0, percent: 0 },
        network: { bytes_in: 0, bytes_out: 0 },
        disk: { usage_percent: 0 },
        connections: { total: 0, established: 0, time_wait: 0, syn_recv: 0 },
        uptime: process.uptime()
    };

    if (!isLinux) return stats;

    try {
        const { stdout: loadavg } = await execAsync('cat /proc/loadavg 2>/dev/null', { timeout: 2000 });
        const parts = loadavg.trim().split(/\s+/);
        stats.cpu_load = [parseFloat(parts[0]) || 0, parseFloat(parts[1]) || 0, parseFloat(parts[2]) || 0];
    } catch (e) {}

    try {
        const { stdout: meminfo } = await execAsync("cat /proc/meminfo 2>/dev/null | grep -E 'MemTotal|MemAvailable'", { timeout: 2000 });
        const lines = meminfo.trim().split('\n');
        for (const line of lines) {
            const match = line.match(/(\w+):\s+(\d+)/);
            if (match) {
                const val = parseInt(match[2]) * 1024;
                if (match[1] === 'MemTotal') stats.memory.total = val;
                if (match[1] === 'MemAvailable') stats.memory.free = val;
            }
        }
        stats.memory.used = stats.memory.total - stats.memory.free;
        stats.memory.percent = stats.memory.total > 0 ? (stats.memory.used / stats.memory.total) * 100 : 0;
    } catch (e) {}

    try {
        const { stdout: netdev } = await execAsync("cat /proc/net/dev 2>/dev/null | grep -v 'lo:' | tail -n +3", { timeout: 2000 });
        const lines = netdev.trim().split('\n');
        for (const line of lines) {
            const parts = line.trim().split(/\s+/);
            if (parts.length >= 10) {
                const iface = parts[0].replace(':', '');
                if (iface !== 'lo') {
                    stats.network.bytes_in += parseInt(parts[1]) || 0;
                    stats.network.bytes_out += parseInt(parts[9]) || 0;
                }
            }
        }
    } catch (e) {}

    try {
        const { stdout: connCount } = await execAsync(
            `ss -s 2>/dev/null | grep -E 'TCP:|estab|timewait|synrecv'`,
            { timeout: 2000 }
        );
        const totalMatch = connCount.match(/TCP:\s+(\d+)/);
        const estabMatch = connCount.match(/estab\s+(\d+)/);
        const twMatch = connCount.match(/timewait\s+(\d+)/);
        const synMatch = connCount.match(/synrecv\s+(\d+)/);
        if (totalMatch) stats.connections.total = parseInt(totalMatch[1]);
        if (estabMatch) stats.connections.established = parseInt(estabMatch[1]);
        if (twMatch) stats.connections.time_wait = parseInt(twMatch[1]);
        if (synMatch) stats.connections.syn_recv = parseInt(synMatch[1]);
    } catch (e) {}

    try {
        const { stdout: df } = await execAsync("df / 2>/dev/null | tail -1", { timeout: 2000 });
        const parts = df.trim().split(/\s+/);
        if (parts.length >= 5) {
            stats.disk.usage_percent = parseInt(parts[4]) || 0;
        }
    } catch (e) {}

    return stats;
}

async function getIPTablesCount() {
    if (!isLinux) return 0;
    try {
        const { stdout } = await execAsync('iptables -L INPUT -n 2>/dev/null | wc -l', { timeout: 3000 });
        return Math.max(0, parseInt(stdout.trim()) - 2);
    } catch (e) {
        return 0;
    }
}

// ==================== MAIN MONITORING LOOP ====================

async function runMonitoringCycle() {
    const startTime = Date.now();

    try {
        const [
            activeConnections,
            connectionStates,
            synFlood,
            portScanners,
            udpFlood,
            timeWaitAbuse,
            highConnIPs,
            serverStats,
            iptablesCount
        ] = await Promise.all([
            monitorActiveConnections(),
            monitorAllConnectionStates(),
            monitorSynFlood(),
            detectPortScanning(),
            detectUDPFlood(),
            detectTimeWaitAbuse(),
            detectHighConnectionIPs(),
            getServerStats(),
            getIPTablesCount()
        ]);

        const duration = Date.now() - startTime;

        parentPort.postMessage({
            type: 'monitoring_result',
            data: {
                activeConnections,
                connectionStates,
                synFlood,
                portScanners,
                udpFlood,
                timeWaitAbuse,
                highConnIPs,
                serverStats,
                iptablesCount,
                duration,
                timestamp: Date.now()
            }
        });
    } catch (err) {
        parentPort.postMessage({
            type: 'monitoring_error',
            error: err.message,
            timestamp: Date.now()
        });
    }
}

// ==================== START LOOP ====================

async function monitorLoop() {
    while (running) {
        await runMonitoringCycle();
        await new Promise(resolve => setTimeout(resolve, monitoringInterval));
    }
}

parentPort.postMessage({ type: 'worker_ready', timestamp: Date.now() });
monitorLoop();
