#!/usr/bin/env python3
"""
Phase 6 resilience tests for ipsc2hbp.

Runs automated scenarios:
  1. MSTNAK  → bridge reconnects
  2. MSTCL   → bridge reconnects
  3. Server restart (kill+restart) → bridge reconnects
  4. TRACKING mode: IPSC peer register  → HBP connects
  5. TRACKING mode: IPSC peer lost      → HBP disconnects
  6. SIGTERM graceful shutdown
  7. IPSC peer watchdog (peer stops keepalives → bridge fires peer_lost)

Usage:
    python tests/test_resilience.py [--scenarios 1,2,3]
"""

import argparse
import os
import re
import signal
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

VENV_PY  = '/home/cort/ipsc2hbp/venv/bin/python'
CWD      = '/home/cort/ipsc2hbp'
MASTER   = os.path.join(CWD, 'tests', 'fake_hbp_master.py')
PEER     = os.path.join(CWD, 'tests', 'fake_ipsc_peer.py')
BRIDGE   = os.path.join(CWD, 'ipsc2hbp.py')
CFG      = os.path.join(CWD, 'tests', 'test.toml')
CFG_TRK  = os.path.join(CWD, 'tests', 'test_tracking.toml')

_results = []


def _start(cmd, stdin=None, log=None):
    fout = open(log, 'w') if log else subprocess.DEVNULL
    proc = subprocess.Popen(
        cmd, cwd=CWD, stdout=fout, stderr=fout,
        stdin=subprocess.PIPE if stdin else None,
    )
    return proc


def _kill(*procs):
    for p in procs:
        if p and p.poll() is None:
            p.kill()
            try:
                p.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass


def _log(path):
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        return ''


def _check(log_text, pattern, label):
    found = bool(re.search(pattern, log_text))
    mark  = '✓' if found else '✗'
    print(f'  {mark} {label}')
    return found


def _teardown():
    os.system('pkill -9 -f "fake_hbp_master|fake_ipsc_peer|ipsc2hbp.py" 2>/dev/null')
    time.sleep(1)


def _record(name, passed):
    _results.append((name, passed))
    print(f'{"PASS" if passed else "FAIL"}: {name}\n')


# -----------------------------------------------------------------------
# Scenario 1: MSTNAK → reconnect
# -----------------------------------------------------------------------

def scenario_mstnak():
    name = 'MSTNAK → bridge reconnects'
    print(f'\n{"="*60}\n{name}\n{"="*60}')
    master = bridge = None
    try:
        master = _start([VENV_PY, MASTER, '--port', '62031',
                         '--auto-nak-after', '3'],
                        log='/tmp/r1_master.log')
        time.sleep(0.3)
        bridge = _start([VENV_PY, BRIDGE, '-c', CFG, '--log-level', 'DEBUG'],
                        log='/tmp/r1_bridge.log')
        # Wait for: initial connect + NAK + 5s reconnect delay + reconnect
        time.sleep(13)
    finally:
        _kill(master, bridge)
        _teardown()

    bl = _log('/tmp/r1_bridge.log')
    ml = _log('/tmp/r1_master.log')
    ok = all([
        _check(bl, r'CONNECTED to',        'initial HBP connect'),
        _check(ml, r'auto: sending MSTNAK', 'auto-nak fired'),
        _check(bl, r'MSTNAK',              'bridge received MSTNAK'),
        _check(bl, r'reconnecting in',     'bridge started reconnect'),
        _check(ml, r'RPTL.*peer_id',       'second RPTL seen at master'),
    ])
    _record(name, ok)
    return ok


# -----------------------------------------------------------------------
# Scenario 2: MSTCL → reconnect
# -----------------------------------------------------------------------

def scenario_mstcl():
    name = 'MSTCL → bridge reconnects'
    print(f'\n{"="*60}\n{name}\n{"="*60}')
    master = bridge = None
    try:
        master = _start([VENV_PY, MASTER, '--port', '62031',
                         '--auto-close-after', '3'],
                        log='/tmp/r2_master.log')
        time.sleep(0.3)
        bridge = _start([VENV_PY, BRIDGE, '-c', CFG, '--log-level', 'DEBUG'],
                        log='/tmp/r2_bridge.log')
        time.sleep(13)
    finally:
        _kill(master, bridge)
        _teardown()

    bl = _log('/tmp/r2_bridge.log')
    ml = _log('/tmp/r2_master.log')
    ok = all([
        _check(bl, r'CONNECTED to',         'initial HBP connect'),
        _check(ml, r'auto: sending MSTCL',  'auto-close fired'),
        _check(bl, r'MSTCL',               'bridge received MSTCL'),
        _check(bl, r'reconnecting in',      'bridge started reconnect'),
        _check(ml, r'RPTL.*peer_id',        'second RPTL seen at master'),
    ])
    _record(name, ok)
    return ok


# -----------------------------------------------------------------------
# Scenario 3: Server kill+restart → bridge reconnects
# -----------------------------------------------------------------------

def scenario_server_restart():
    name = 'Server kill+restart → bridge reconnects'
    print(f'\n{"="*60}\n{name}\n{"="*60}')
    master = bridge = master2 = None
    try:
        master = _start([VENV_PY, MASTER, '--port', '62031'],
                        log='/tmp/r3_master.log')
        time.sleep(0.3)
        bridge = _start([VENV_PY, BRIDGE, '-c', CFG, '--log-level', 'DEBUG'],
                        log='/tmp/r3_bridge.log')
        time.sleep(3)   # let initial connection establish
        print('  [test] Killing fake_hbp_master...')
        _kill(master)
        master = None
        time.sleep(7)   # bridge sends RPTPING, gets error_received → reconnects
        print('  [test] Restarting fake_hbp_master...')
        master2 = _start([VENV_PY, MASTER, '--port', '62031'],
                         log='/tmp/r3_master2.log')
        time.sleep(8)   # bridge should reconnect within reconnect_delay (5s)
    finally:
        _kill(master, master2, bridge)
        _teardown()

    bl   = _log('/tmp/r3_bridge.log')
    ml2  = _log('/tmp/r3_master2.log')
    ok = all([
        _check(bl,  r'CONNECTED to',    'initial HBP connect'),
        _check(bl,  r'socket error',    'error detected on master kill'),
        _check(bl,  r'reconnecting in', 'bridge started reconnect'),
        _check(ml2, r'RPTL.*peer_id',   'bridge reached restarted master'),
        _check(ml2, r'CONNECTED',       'restarted master accepted reconnect'),
    ])
    _record(name, ok)
    return ok


# -----------------------------------------------------------------------
# Scenario 4+5: TRACKING mode — peer register/lose drives HBP connect/disconnect
# -----------------------------------------------------------------------

def scenario_tracking():
    name = 'TRACKING: IPSC peer drives HBP connect/disconnect'
    print(f'\n{"="*60}\n{name}\n{"="*60}')
    master = bridge = peer = None
    try:
        master = _start([VENV_PY, MASTER, '--port', '62031'],
                        log='/tmp/r4_master.log')
        time.sleep(0.3)
        bridge = _start([VENV_PY, BRIDGE, '-c', CFG_TRK, '--log-level', 'DEBUG'],
                        log='/tmp/r4_bridge.log')
        time.sleep(2)   # bridge should NOT connect yet (no peer)
        print('  [test] Starting IPSC peer...')
        peer = _start([VENV_PY, PEER, '--host', '127.0.0.1', '--port', '50000',
                       '--radio-id', '3120000'],
                      log='/tmp/r4_peer.log')
        time.sleep(3)   # peer registers → HBP should connect
        print('  [test] Killing IPSC peer...')
        _kill(peer)
        peer = None
        time.sleep(16)  # watchdog (12s) + margin → HBP should disconnect
    finally:
        _kill(master, bridge, peer)
        _teardown()

    bl = _log('/tmp/r4_bridge.log')
    ml = _log('/tmp/r4_master.log')
    ok = all([
        _check(bl, r'HBP client activated',  'HBP activated on peer register'),
        _check(bl, r'CONNECTED to',          'HBP connected after peer registered'),
        _check(ml, r'RPTL.*peer_id',         'master saw RPTL after peer registered'),
        _check(bl, r'IPSC peer lost',        'bridge detected peer loss'),
        _check(bl, r'HBP client deactivated','HBP deactivated on peer lost'),
        _check(ml, r'RPTCL',                 'bridge sent RPTCL to master'),
    ])
    _record(name, ok)
    return ok


# -----------------------------------------------------------------------
# Scenario 6: SIGTERM graceful shutdown
# -----------------------------------------------------------------------

def scenario_sigterm():
    name = 'SIGTERM → graceful shutdown'
    print(f'\n{"="*60}\n{name}\n{"="*60}')
    master = bridge = None
    try:
        master = _start([VENV_PY, MASTER, '--port', '62031'],
                        log='/tmp/r5_master.log')
        time.sleep(0.3)
        bridge = _start([VENV_PY, BRIDGE, '-c', CFG, '--log-level', 'DEBUG'],
                        log='/tmp/r5_bridge.log')
        time.sleep(3)
        print(f'  [test] Sending SIGTERM to bridge pid={bridge.pid}')
        bridge.send_signal(signal.SIGTERM)
        bridge.wait(timeout=5)
        bridge = None
        time.sleep(1)
    finally:
        _kill(master, bridge)
        _teardown()

    bl = _log('/tmp/r5_bridge.log')
    ml = _log('/tmp/r5_master.log')
    ok = all([
        _check(bl, r'CONNECTED to',   'bridge was connected'),
        _check(bl, r'Signal.*received|SIGTERM|shutting down', 'signal logged'),
        _check(ml, r'RPTCL',          'clean RPTCL sent to master'),
        _check(bl, r'stopped',        'bridge logged shutdown'),
    ])
    _record(name, ok)
    return ok


# -----------------------------------------------------------------------
# Scenario 7: IPSC peer watchdog
# -----------------------------------------------------------------------

def scenario_ipsc_watchdog():
    name = 'IPSC peer watchdog → peer_lost fires'
    print(f'\n{"="*60}\n{name}\n{"="*60}')
    master = bridge = peer = None
    try:
        master = _start([VENV_PY, MASTER, '--port', '62031'],
                        log='/tmp/r6_master.log')
        time.sleep(0.3)
        bridge = _start([VENV_PY, BRIDGE, '-c', CFG, '--log-level', 'DEBUG'],
                        log='/tmp/r6_bridge.log')
        time.sleep(2)
        peer = _start([VENV_PY, PEER, '--host', '127.0.0.1', '--port', '50000',
                       '--radio-id', '3120000'],
                      log='/tmp/r6_peer.log')
        time.sleep(3)   # let peer register
        print('  [test] Killing IPSC peer (no more keepalives)...')
        _kill(peer)
        peer = None
        time.sleep(20)  # watchdog = 15s in test.toml, wait for it to fire
    finally:
        _kill(master, bridge, peer)
        _teardown()

    bl = _log('/tmp/r6_bridge.log')
    ok = all([
        _check(bl, r'IPSC peer registered', 'peer registered with bridge'),
        _check(bl, r'IPSC peer lost',       'peer_lost fired after watchdog'),
    ])
    _record(name, ok)
    return ok


# -----------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------

SCENARIOS = {
    1: ('MSTNAK reconnect',       scenario_mstnak),
    2: ('MSTCL reconnect',        scenario_mstcl),
    3: ('Server kill+restart',    scenario_server_restart),
    4: ('TRACKING mode',          scenario_tracking),
    5: ('SIGTERM shutdown',       scenario_sigterm),
    6: ('IPSC peer watchdog',     scenario_ipsc_watchdog),
}


def main():
    ap = argparse.ArgumentParser(description='Phase 6 resilience tests')
    ap.add_argument('--scenarios', default='1,2,3,4,5,6',
                    help='Comma-separated list of scenario numbers to run (default: all)')
    args = ap.parse_args()

    nums = [int(x) for x in args.scenarios.split(',')]

    _teardown()  # clean slate

    for n in nums:
        if n not in SCENARIOS:
            print(f'Unknown scenario {n}')
            continue
        _, fn = SCENARIOS[n]
        fn()

    print(f'\n{"="*60}')
    print('RESULTS')
    print('='*60)
    all_pass = True
    for name, passed in _results:
        mark = 'PASS' if passed else 'FAIL'
        print(f'  {mark}  {name}')
        if not passed:
            all_pass = False
    print('='*60)
    sys.exit(0 if all_pass else 1)


if __name__ == '__main__':
    main()
