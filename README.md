## PROJECT: IPSC to HomeBrew Protocol Translator ##
**C version available: ipsc2hbpc**

**NOTICE:** This software only supports Group Voice traffic at this time. IPSC is not an open standard. Supporting it involves painstaking reverse engineering of IPSC packets, and much is unknown. IPSC is owned by and heavily protected by Motorola Solutions, Inc. Please do not ask for features that require further deciphering of IPSC without providing verified correct, legally obtained information about the protocol necessary to support a feature.

**PURPOSE:** A single, small Python 3 daemon that connects a Motorola MOTOTRBO IPSC system to one upstream DMR network server running the open HomeBrew Repeater Protocol (BrandMeister, DMR+, FreeDMR, HBlink4, etc.).

Two IPSC modes are supported:
- **MASTER** (default) — ipsc2hbp acts as the IPSC master; up to 14 MOTOTRBO repeaters register with it as peers. Remote CPS programming in Master mode on the way.
- **PEER** — ipsc2hbp registers with an existing IPSC master (e.g. a repeater configured as master). All traffic on that IPSC system is forwarded to HBP.

**WHY THIS EXISTS:**

The previous solution to this problem was a pair of Python 2 applications: `IPSC_Bridge` from DMRlink and `HB_Bridge` from HBlink, running as separate processes and talking to each other over local UDP sockets. It worked, but it required four configuration files, careful coordination between two running processes, and always felt fragile and overly complex. Python 2 is now long dead, which only made things worse.

`ipsc2hbp` replaces all of that with one process, one config file, and no inter-process communication. It speaks IPSC to the repeater and HBP to the upstream server and translates between them in memory. Simple and effective!

**DESIGN GOALS:**

- **Transparent translation only.** No routing, bridging, talkgroup filtering, or rewriting. IPSC peers in, one network out, pass everything through unchanged.
- **Single asyncio event loop.** No threads, no subprocesses, no sockets between components. Both protocol stacks run concurrently in one Python process.
- **One config file.** TOML. Copy the sample, fill in your repeater ID, passphrase, and frequencies. Done.
- **Correct over clever.** Protocol behavior is derived from the DMRlink and HBlink source — not the published specs, which contain several errors. Where the spec disagrees with working code, the code wins.
- **TRACKING mode by default.** The HBP connection follows the repeater: it comes up when the repeater registers and drops when the repeater goes away. PERSISTENT mode is available if you'd rather keep the upstream connection up regardless.
- **Native call timing on the IPSC side.** Inbound HBP→IPSC voice is clocked out through a jitter buffer at the exact 60 ms DMR cadence — anchored to the first voice burst so every burst gets the full buffer lead — so the repeater sees a continuous grid identical to real MOTOTRBO equipment. The terminator is held until the buffered tail drains, so the call tail is never clipped. Depth is tunable per link via `[hbp] jitter_buffer_depth` (default 2 = 120 ms; raise it for marginal/high-latency RF backhaul).

**WHAT IT IS NOT:**

This is not a general-purpose bridge, reflector, or network controller. It does not route between talkgroups, filter, or rewrite calls. It works with HBlink4 and should work with any HBP-speaking network server.

**REQUIREMENTS:**

- Python 3.11 or later (uses `tomllib` from stdlib)
- `dmr-utils3` and `bitarray` (see `requirements.txt`)
- One Motorola MOTOTRBO repeater configured with this host as its IPSC master
- One upstream HBP server (BrandMeister, DMR+, HBlink4, etc.)

**PREREQUISITES**

Successful use of ipsc2hbp requires a working knowledge of the Unix command line interface (CLI) and Python, including Python virtual environments (venv). Users without these skills may find it challenging to be successful.

**GETTING STARTED:**

The following will run ipsc2hbp in the global Python environment, but it is highly recommended to use a Python virtual environment. Installation instructions are located in INSTALL.md.

```
pip install -r requirements.txt
cp ipsc2hbp.toml.sample ipsc2hbp.toml
# edit ipsc2hbp.toml for your repeater and network
python ipsc2hbp.py -c ipsc2hbp.toml
```

**PROPERTY:**

This work represents the author's interpretation of the Motorola MOTOTRBO IPSC protocol and the HomeBrew Repeater Protocol. IPSC protocol behavior is derived from reverse-engineering work originally done in DMRlink. HBP behavior is derived from HBlink, HBlink3, and HBlink4. Motorola and MOTOTRBO are registered trademarks of Motorola Solutions, Inc. This project is not affiliated with Motorola Solutions in any way.

### No Support Is Provided

This is not commercial software. It is provided free of charge. The author(s)
received no compensation for creating and maintaining it. Countless hours over
many years have gone into this. If you have problems, the author will try
to help if possible, please have no expectations for support. There is no online
group, such as DVSwitch or groups.io that is an "official" outlet for information.
The only definitive source of information is me. Beware of others claiming to
be authoritative. User-based mutual support is great, and I'm all for it. But
please understand, this is what they are, and I have not sanctioned anyone to be
the "home" of my software packages.

### GitHub "Issues"

Do not use GitHub issues for support. Genuine bugs are accepted as issues. Before
opening one, make sure that it is a true problem with the software and not merely
a misconfiguration, or contention around a feature that was not supported. Issues
should never be used to ask for or recommend features. Issues that do not include
complete details, relevant tracebacks, error messages, configuration snippets,
operational conditions surrounding the event, etc. will be closed without action.

***0x49 DE N0MJS***

Additional IPSC packet structure knowledge — FLAGS byte field names, MODE byte slot states, IPSC version field encoding, call monitor payload layouts, remote programming opcodes, MNIS/Wireline identification, and more — was derived from study of **node-dmr-lib** by rick51231: https://github.com/rick51231/node-dmr-lib

Copyright (C) 2026 Cortney T. Buffington, N0MJS <n0mjs@me.com>

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
