import logging
import socket
import tomllib
from dataclasses import dataclass

log = logging.getLogger(__name__)

_VALID_LOG_LEVELS = {'DEBUG', 'INFO', 'WARNING', 'ERROR'}
_VALID_HBP_MODES  = {'TRACKING', 'PERSISTENT'}


@dataclass(frozen=True)
class Config:
    # [global]
    log_level: str

    # [ipsc]
    ipsc_bind_ip: str
    ipsc_bind_port: int
    ipsc_master_id: int
    allowed_peer_ids: frozenset   # int; empty = accept any radio ID
    allowed_peer_ips: frozenset   # str; empty = accept any source IP
    auth_enabled: bool
    auth_key: bytes               # 20 bytes, zero-padded from hex config value
    keepalive_watchdog: int

    # [ipsc.capabilities] — wire-format bytes computed by config loader
    ipsc_mode_byte:   bytes   # 1 byte  — MODE field in all IPSC management packets
    ipsc_flags_bytes: bytes   # 4 bytes — FLAGS field in all IPSC management packets
    ipsc_version:     bytes   # 4 bytes — IPSC version field

    # [ipsc] — call stream handling
    ipsc_ts_prefer_call_info: bool  # see ts_prefer_call_info in toml

    # [hbp]
    hbp_master_ip: str
    hbp_master_port: int
    hbp_repeater_id: int          # radio ID this system presents to the HBP master
    hbp_passphrase: bytes
    hbp_mode: str

    # RPTC announcement fields
    options: str
    callsign: str
    rx_freq: str
    tx_freq: str
    tx_power: str
    colorcode: str
    latitude: str
    longitude: str
    height: str
    location: str
    description: str
    url: str
    software_id: str
    package_id: str


def load(path: str) -> Config:
    """Load and validate a TOML config file. Raises on any error."""
    try:
        with open(path, 'rb') as fh:
            raw = tomllib.load(fh)
    except FileNotFoundError:
        raise FileNotFoundError(f'Config file not found: {path}')
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f'Config file parse error: {exc}')

    errors = []

    def get_str(section, key, required=True, default='', choices=None):
        val = raw.get(section, {}).get(key)
        if val is None:
            if required:
                errors.append(f'[{section}] {key}: required')
            return default
        if not isinstance(val, str):
            errors.append(f'[{section}] {key}: must be a string, got {type(val).__name__}')
            return default
        if choices is not None:
            upper = val.strip().upper()
            if upper not in choices:
                errors.append(f'[{section}] {key}: must be one of {sorted(choices)}, got {val!r}')
                return default
            return upper
        return val.strip()

    def get_int(section, key, required=True, default=0, min_val=None, max_val=None):
        val = raw.get(section, {}).get(key)
        if val is None:
            if required:
                errors.append(f'[{section}] {key}: required')
            return default
        if not isinstance(val, int) or isinstance(val, bool):
            errors.append(f'[{section}] {key}: must be an integer, got {type(val).__name__}')
            return default
        if min_val is not None and val < min_val:
            errors.append(f'[{section}] {key}: must be >= {min_val}, got {val}')
        if max_val is not None and val > max_val:
            errors.append(f'[{section}] {key}: must be <= {max_val}, got {val}')
        return val

    def get_bool(section, key, required=True, default=False):
        val = raw.get(section, {}).get(key)
        if val is None:
            if required:
                errors.append(f'[{section}] {key}: required')
            return default
        if not isinstance(val, bool):
            errors.append(f'[{section}] {key}: must be true or false, got {type(val).__name__}')
            return default
        return val

    # [global]
    log_level = get_str('global', 'log_level', choices=_VALID_LOG_LEVELS)

    # [ipsc]
    ipsc_bind_ip   = get_str('ipsc', 'bind_ip')
    ipsc_bind_port = get_int('ipsc', 'bind_port', min_val=1, max_val=65535)
    ipsc_master_id = get_int('ipsc', 'ipsc_master_id', min_val=1)

    # allowed_peer_ids: optional array of integers; empty = accept any radio ID
    raw_peer_ids = raw.get('ipsc', {}).get('allowed_peer_ids', [])
    if not isinstance(raw_peer_ids, list):
        errors.append('[ipsc] allowed_peer_ids: must be an array of integers')
        raw_peer_ids = []
    allowed_peer_ids = frozenset()
    for v in raw_peer_ids:
        if not isinstance(v, int) or isinstance(v, bool):
            errors.append(f'[ipsc] allowed_peer_ids: all entries must be integers, got {v!r}')
        else:
            allowed_peer_ids = allowed_peer_ids | {v}

    # allowed_peer_ips: optional array of strings; empty = accept any source IP
    raw_peer_ips = raw.get('ipsc', {}).get('allowed_peer_ips', [])
    if not isinstance(raw_peer_ips, list):
        errors.append('[ipsc] allowed_peer_ips: must be an array of strings')
        raw_peer_ips = []
    allowed_peer_ips = frozenset()
    for v in raw_peer_ips:
        if not isinstance(v, str):
            errors.append(f'[ipsc] allowed_peer_ips: all entries must be strings, got {v!r}')
        else:
            try:
                socket.inet_aton(v.strip())
                allowed_peer_ips = allowed_peer_ips | {v.strip()}
            except OSError:
                errors.append(f'[ipsc] allowed_peer_ips: not a valid IPv4 address: {v!r}')

    auth_enabled              = get_bool('ipsc', 'auth_enabled')
    keepalive_watchdog        = get_int('ipsc',  'keepalive_watchdog', min_val=5)
    ipsc_ts_prefer_call_info  = get_bool('ipsc', 'ts_prefer_call_info', required=False, default=False)

    auth_key = b'\x00' * 20
    if auth_enabled:
        raw_key = get_str('ipsc', 'auth_key', required=True)
        raw_key = raw_key.strip()
        if len(raw_key) > 40:
            errors.append('[ipsc] auth_key: must be at most 40 hex characters')
        else:
            try:
                auth_key = bytes.fromhex(raw_key.zfill(40))
            except ValueError as exc:
                errors.append(f'[ipsc] auth_key: not valid hex: {exc}')

    # [ipsc.capabilities]
    cap = raw.get('ipsc', {}).get('capabilities', {})
    use_safe_defaults = cap.get('use_safe_defaults', True)
    if not isinstance(use_safe_defaults, bool):
        errors.append('[ipsc.capabilities] use_safe_defaults: must be true or false')
        use_safe_defaults = True

    if use_safe_defaults:
        # Proven working values — do not change without a wire capture to verify.
        ipsc_mode_byte   = b'\x6A'            # OP + DIGITAL + TS1:on + TS2:on
        _flags_b4 = 0x05                      # VOICE_CALL | MSTR_PEER
        if auth_enabled:
            _flags_b4 |= 0x10                 # PKT_AUTH
        ipsc_flags_bytes = b'\x00\x00\x00' + bytes([_flags_b4])
        ipsc_version     = b'\x04\x02\x04\x01'
    else:
        # --- MODE byte ---
        # Operational bit-pair (bits 7-6): only 0b01 is known valid.
        op_bits = 0b01

        raw_radio_mode = cap.get('radio_mode', 'DIGITAL')
        if not isinstance(raw_radio_mode, str):
            errors.append('[ipsc.capabilities] radio_mode: must be a string')
            raw_radio_mode = 'DIGITAL'
        raw_radio_mode = raw_radio_mode.strip().upper()
        mode_bits = {'DIGITAL': 0b10, 'ANALOG': 0b01, 'NO_RADIO': 0b00, 'MIXED': 0b11}.get(raw_radio_mode)
        if mode_bits is None:
            errors.append('[ipsc.capabilities] radio_mode: must be DIGITAL, ANALOG, NO_RADIO, or MIXED')
            mode_bits = 0b10

        ts1 = cap.get('ts1_linked', True)
        ts2 = cap.get('ts2_linked', True)
        if not isinstance(ts1, bool):
            errors.append('[ipsc.capabilities] ts1_linked: must be true or false')
            ts1 = True
        if not isinstance(ts2, bool):
            errors.append('[ipsc.capabilities] ts2_linked: must be true or false')
            ts2 = True
        ts1_bits = 0b10 if ts1 else 0b01
        ts2_bits = 0b10 if ts2 else 0b01

        mode_val = (op_bits << 6) | (mode_bits << 4) | (ts1_bits << 2) | ts2_bits
        ipsc_mode_byte = bytes([mode_val])

        # --- FLAGS bytes ---
        def _cap_bool(key, default=False):
            v = cap.get(key, default)
            if not isinstance(v, bool):
                errors.append(f'[ipsc.capabilities] {key}: must be true or false')
                return default
            return v

        def _cap_hex_byte(key, default=0):
            v = cap.get(key, f'{default:02x}')
            if not isinstance(v, str):
                errors.append(f'[ipsc.capabilities] {key}: must be a 2-character hex string')
                return default
            try:
                val = int(v.strip(), 16)
                if not 0 <= val <= 255:
                    raise ValueError
                return val
            except ValueError:
                errors.append(f'[ipsc.capabilities] {key}: must be a 2-character hex string (e.g. "00")')
                return default

        # FLAGS byte 0 — wireline/MNIS capability bits; safely zero for non-MNIS devices
        b0 = 0x00
        if _cap_bool('slot2_wireline'): b0 |= 0x10
        if _cap_bool('slot1_wireline'): b0 |= 0x08
        if _cap_bool('wireline_svc'):   b0 |= 0x04

        # FLAGS byte 1 — service/capability bits; safely zero for a standard repeater
        b1 = 0x00
        if _cap_bool('mnis'):         b1 |= 0x80
        if _cap_bool('ip_site_freq'): b1 |= 0x40
        if _cap_bool('slot2_phone'):  b1 |= 0x10
        if _cap_bool('slot1_phone'):  b1 |= 0x08
        if _cap_bool('virtual_peer'): b1 |= 0x04
        if _cap_bool('cps_avail'):    b1 |= 0x02

        b2 = 0x00
        if _cap_bool('csbk'):    b2 |= 0x80
        if _cap_bool('rpt_mon'): b2 |= 0x40
        if _cap_bool('con_app'): b2 |= 0x20

        b3 = 0x01                             # MSTR_PEER always set — we are always master
        if _cap_bool('xnl_con'):    b3 |= 0x80
        if _cap_bool('xnl_master'): b3 |= 0x40
        if _cap_bool('xnl_slave'):  b3 |= 0x20
        if auth_enabled:            b3 |= 0x10  # AUTH always mirrors auth_enabled
        if _cap_bool('data'):       b3 |= 0x08
        if _cap_bool('voice', default=True): b3 |= 0x04

        ipsc_flags_bytes = bytes([b0, b1, b2, b3])

        # --- IPSC version ---
        raw_ver = cap.get('ipsc_version', '04020401')
        if not isinstance(raw_ver, str):
            errors.append('[ipsc.capabilities] ipsc_version: must be an 8-character hex string')
            raw_ver = '04020401'
        raw_ver = raw_ver.strip().replace(' ', '')
        if len(raw_ver) != 8:
            errors.append('[ipsc.capabilities] ipsc_version: must be exactly 8 hex characters (4 bytes)')
            raw_ver = '04020401'
        try:
            ipsc_version = bytes.fromhex(raw_ver)
        except ValueError:
            errors.append('[ipsc.capabilities] ipsc_version: not valid hex')
            ipsc_version = b'\x04\x02\x04\x01'

    # [hbp]
    hbp_master_ip   = get_str('hbp', 'master_ip')
    hbp_master_port = get_int('hbp', 'master_port', min_val=1, max_val=65535)
    hbp_mode        = get_str('hbp', 'hbp_mode', choices=_VALID_HBP_MODES)
    hbp_repeater_id = get_int('hbp', 'hbp_repeater_id', required=True, min_val=1)

    raw_passphrase = get_str('hbp', 'passphrase')
    hbp_passphrase = raw_passphrase.encode()

    # RPTC fields (all optional with sensible defaults)
    options     = get_str('hbp', 'options',     required=False, default='')
    callsign    = get_str('hbp', 'callsign',    required=False, default='NOCALL')
    rx_freq     = get_str('hbp', 'rx_freq',     required=False, default='000000000')
    tx_freq     = get_str('hbp', 'tx_freq',     required=False, default='000000000')
    tx_power    = get_str('hbp', 'tx_power',    required=False, default='00')
    colorcode   = get_str('hbp', 'colorcode',   required=False, default='01')
    latitude    = get_str('hbp', 'latitude',    required=False, default='00.0000 ')
    longitude   = get_str('hbp', 'longitude',   required=False, default='000.0000 ')
    height      = get_str('hbp', 'height',      required=False, default='000')
    location    = get_str('hbp', 'location',    required=False, default='')
    description = get_str('hbp', 'description', required=False, default='')
    url         = get_str('hbp', 'url',         required=False, default='')
    software_id = get_str('hbp', 'software_id', required=False, default='ipsc2hbp')
    package_id  = get_str('hbp', 'package_id',  required=False, default='1.0.0')

    if errors:
        raise ValueError('Configuration errors:\n' + '\n'.join(f'  {e}' for e in errors))

    return Config(
        log_level=log_level,
        ipsc_bind_ip=ipsc_bind_ip,
        ipsc_bind_port=ipsc_bind_port,
        ipsc_master_id=ipsc_master_id,
        allowed_peer_ids=allowed_peer_ids,
        allowed_peer_ips=allowed_peer_ips,
        auth_enabled=auth_enabled,
        auth_key=auth_key,
        keepalive_watchdog=keepalive_watchdog,
        ipsc_ts_prefer_call_info=ipsc_ts_prefer_call_info,
        ipsc_mode_byte=ipsc_mode_byte,
        ipsc_flags_bytes=ipsc_flags_bytes,
        ipsc_version=ipsc_version,
        hbp_master_ip=hbp_master_ip,
        hbp_master_port=hbp_master_port,
        hbp_repeater_id=hbp_repeater_id,
        hbp_passphrase=hbp_passphrase,
        hbp_mode=hbp_mode,
        options=options,
        callsign=callsign,
        rx_freq=rx_freq,
        tx_freq=tx_freq,
        tx_power=tx_power,
        colorcode=colorcode,
        latitude=latitude,
        longitude=longitude,
        height=height,
        location=location,
        description=description,
        url=url,
        software_id=software_id,
        package_id=package_id,
    )
