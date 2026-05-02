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

    auth_enabled       = get_bool('ipsc', 'auth_enabled')
    keepalive_watchdog = get_int('ipsc', 'keepalive_watchdog', min_val=5)

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
