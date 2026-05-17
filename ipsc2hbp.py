"""
ipsc2hbp — entry point.

Wires IPSCMasterProtocol/IPSCPeerProtocol, HBPClient, and CallTranslator together and runs
the asyncio event loop.
"""

import argparse
import asyncio
import logging
import pathlib
import signal
import sys

from config import Config, load as load_config

_DEFAULT_CFG = pathlib.Path(__file__).parent / 'ipsc2hbp.toml'


def _setup_logging(level: str):
    fmt = '%(asctime)s %(levelname)s [%(name)s] %(message)s'
    root = logging.getLogger()
    root.setLevel(getattr(logging, level))
    if not root.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(fmt))
        root.addHandler(handler)
    else:
        for h in root.handlers:
            h.setLevel(getattr(logging, level))
            h.setFormatter(logging.Formatter(fmt))


def main():
    ap = argparse.ArgumentParser(description='IPSC to HomeBrew Protocol translator')
    ap.add_argument('-c', '--config', default=str(_DEFAULT_CFG),
                    help='Path to TOML config file (default: ipsc2hbp.toml next to this script)')
    ap.add_argument('--log-level', dest='log_level', default=None,
                    help='Override config log level (DEBUG|INFO|WARNING|ERROR)')
    ap.add_argument('--wire', action='store_true',
                    help='Log raw IPSC hex (SEND/RECV) only; silence all other output')
    args = ap.parse_args()

    try:
        cfg = load_config(args.config)
    except (FileNotFoundError, ValueError) as exc:
        sys.exit(f'Configuration error: {exc}')

    if args.wire:
        # Wire mode: ipsc.wire and hbp.wire at DEBUG; silence everything else.
        logging.getLogger().setLevel(logging.WARNING)
        wire_handler = logging.StreamHandler(sys.stderr)
        wire_handler.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
        for name in ('ipsc.wire', 'hbp.wire'):
            wl = logging.getLogger(name)
            wl.setLevel(logging.DEBUG)
            wl.addHandler(wire_handler)
            wl.propagate = False
    else:
        log_level = args.log_level.upper() if args.log_level else cfg.log_level
        _setup_logging(log_level)

    log = logging.getLogger('ipsc2hbp')
    if cfg.ipsc_mode == 'MASTER':
        log.info(
            'ipsc2hbp starting — ipsc=MASTER  id=%d  listen=%s:%d  '
            'hbp_id=%d  upstream=%s:%d  hbp_mode=%s',
            cfg.ipsc_master_id, cfg.ipsc_bind_ip, cfg.ipsc_bind_port,
            cfg.hbp_repeater_id, cfg.hbp_master_ip, cfg.hbp_master_port, cfg.hbp_mode,
        )
    else:
        log.info(
            'ipsc2hbp starting — ipsc=PEER  id=%d  master=%s:%d  local=%s:%d  '
            'hbp_id=%d  upstream=%s:%d  hbp_mode=%s',
            cfg.ipsc_master_id,
            cfg.ipsc_master_ip, cfg.ipsc_master_port,
            cfg.ipsc_bind_ip, cfg.ipsc_bind_port,
            cfg.hbp_repeater_id, cfg.hbp_master_ip, cfg.hbp_master_port, cfg.hbp_mode,
        )

    from ipsc.protocol import IPSCMasterProtocol, IPSCPeerProtocol
    from hbp.protocol import HBPClient
    from translate.translator import CallTranslator

    translator = CallTranslator(cfg)
    if cfg.ipsc_mode == 'MASTER':
        ipsc_proto = IPSCMasterProtocol(cfg, translator)
    else:
        ipsc_proto = IPSCPeerProtocol(cfg, translator)
    hbp_client = HBPClient(cfg, translator)
    translator.set_protocols(ipsc_proto, hbp_client)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def _shutdown(signum, frame):
        log.info('Signal %d received — shutting down', signum)
        ipsc_proto.stop()
        hbp_client.stop()
        loop.stop()

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, _shutdown)

    ipsc_coro = loop.create_datagram_endpoint(
        lambda: ipsc_proto,
        local_addr=(cfg.ipsc_bind_ip, cfg.ipsc_bind_port),
    )

    try:
        loop.run_until_complete(ipsc_coro)
        if cfg.ipsc_mode == 'MASTER':
            log.info('IPSC master endpoint up — %s:%d', cfg.ipsc_bind_ip, cfg.ipsc_bind_port)
        else:
            log.info('IPSC peer socket bound — %s:%d', cfg.ipsc_bind_ip, cfg.ipsc_bind_port)
        hbp_client.start(loop)
        loop.run_forever()
    except OSError as exc:
        sys.exit(f'Failed to bind IPSC socket: {exc}')
    finally:
        # Cancel all pending tasks and let them handle CancelledError before closing.
        pending = asyncio.all_tasks(loop)
        for task in pending:
            task.cancel()
        if pending:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        log.info('ipsc2hbp stopped')
        loop.close()


if __name__ == '__main__':
    main()
