# Installation

Tested on Debian/Ubuntu.  Adapt paths as needed for other distros.

## Requirements

- Python 3.11 or newer (`python3 --version`)
- git

## 1 — Clone and enter the repo
Start in a standard unprivileged user's home directory that will own ipsc2hbp. This is generally the standard user with sudo capability you created when the os was installed.

```
git clone https://github.com/n0mjs710/ipsc2hbp.git
cd ipsc2hbp
```

## 2 — Create a virtual environment and install dependencies

```
python3 -m venv venv
venv/bin/pip install -r requirements.txt
```

## 3 — Create your configuration file

```
cp ipsc2hbp.toml.sample ipsc2hbp.toml
```

Edit `ipsc2hbp.toml` and fill in your IPSC and HBP settings.
The sample file has comments explaining each option.

## 4 — Test it manually (optional but recommended)

```
venv/bin/python ipsc2hbp.py --log-level DEBUG
```

Hit Ctrl-C to stop.

## 5 — Install the systemd service

Open `ipsc2hbp.service` in your editor and replace the two placeholders:

- `__USER__` → your username (e.g. `cort`)
- `__REPO__` → the full path to the cloned repo (e.g. `/home/cort/ipsc2hbp`)

Then copy it into place and enable it:

```
sudo cp ipsc2hbp.service /lib/systemd/system/ipsc2hbp.service
sudo systemctl daemon-reload
sudo systemctl enable --now ipsc2hbp
```

## 6 — Check the logs

```
journalctl -u ipsc2hbp -f
```

## Updating

```
git pull
venv/bin/pip install -r requirements.txt   # pick up any new deps
sudo systemctl restart ipsc2hbp
```
