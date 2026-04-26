## PROJECT: IPSC to HomeBrew Protocol Translator ##

**NOTICE:** This software only supports Group Voice traffic at this time. IPSC is not an open standard. Supporting it invovles painstaking reverse engineering of IPSC packets, and much is unknown. IPSC is owned by and heavily protected by Motorola Solutions, Inc. Please to not ask for features that require further deciphering of IPSC without providing verified correct, legally obtained information about the protocol necessary to support a feature.

**PURPOSE:** A single, small Python 3 daemon that connects one Motorola MOTOTRBO repeater — via the proprietary IPSC protocol — to one upstream DMR network server running the open HomeBrew Repeater Protocol (BrandMeister, DMR+, FreeDMR, HBlink4, etc.).

**WHY THIS EXISTS:**

The previous solution to this problem was a pair of Python 2 applications: `IPSC_Bridge` from DMRlink and `HB_Bridge` from HBlink, running as separate processes and talking to each other over local UDP sockets. It worked, but it required four configuration files, careful coordination between two running processes, and always felt fragile and overly complex. Python 2 is now long dead, which only made things worse.

`ipsc2hbp` replaces all of that with one process, one config file, and no inter-process communication. It speaks IPSC to the repeater and HBP to the upstream server and translates between them in memory. Simple and effective!

**DESIGN GOALS:**

- **Transparent translation only.** No routing, bridging, talkgroup filtering, or rewriting. One repeater in, one network out, pass everything through unchanged.
- **Single asyncio event loop.** No threads, no subprocesses, no sockets between components. Both protocol stacks run concurrently in one Python process.
- **One config file.** TOML. Copy the sample, fill in your repeater ID, passphrase, and frequencies. Done.
- **Correct over clever.** Protocol behavior is derived from the DMRlink and HBlink source — not the published specs, which contain several errors. Where the spec disagrees with working code, the code wins.
- **TRACKING mode by default.** The HBP connection follows the repeater: it comes up when the repeater registers and drops when the repeater goes away. PERSISTENT mode is available if you'd rather keep the upstream connection up regardless.

**WHAT IT IS NOT:**

This is not a general-purpose bridge, reflector, or network controller. It does not route between talkgroups, doesn't talk to multiple repeaters. It will be tested to work with HBlink4, but should work with most HBP speaking network servers.

**REQUIREMENTS:**

- Python 3.11 or later (uses `tomllib` from stdlib)
- `dmr-utils3` and `bitarray` (see `requirements.txt`)
- One Motorola MOTOTRBO repeater configured with this host as its IPSC master
- One upstream HBP server (BrandMeister, DMR+, HBlink4, etc.)

**PREREQUISITES**

Successful use of ipsc2hbp reuires a working knowlege of the unix command line interace (CLI) and Python, including python virtual environemens (venv). Users without thse skills may find it challenging to be successful.

**GETTING STARTED:**

The following will run ipsc2hbp in the glocal python enfironent, but it is highly recommended to use a Python virtual environment. Installation intructinos are located in INSTALL.md.

```
pip install -r requirements.txt
cp ipsc2hbp.toml.sample ipsc2hbp.toml
# edit ipsc2hbp.toml for your repeater and network
python ipsc2hbp.py -c ipsc2hbp.toml
```

**PROPERTY:**

This work represents the author's interpretation of the Motorola MOTOTRBO IPSC protocol and the HomeBrew Repeater Protocol. IPSC protocol behavior is derived from reverse-engineering work originally done in DMRlink. HBP behavior is derived from HBlink, HBlink3, and HBlink4. Motorola and MOTOTRBO are registered trademarks of Motorola Solutions, Inc. This project is not affiliated with Motorola Solutions in any way.

**WARRANTY:** None. Use at your own risk.

***0x49 DE N0MJS***

Copyright (C) 2026 Cortney T. Buffington, N0MJS <n0mjs@me.com>

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
