# Flesh 

Multi Reverse Shell Handler (Python)

Flesh is a lightweight multi-session reverse shell handler written in Python.
It allows you to manage multiple incoming reverse shells from a single console and dynamically generate payloads.

This is a simple handler made for learning, testing, and experimenting with reverse shells.
## Features

- Multi-session shell handling
- Dynamic listeners (multiple ports)
- Interactive shell selection
- TTY / PTY mode switch
- Built-in payload generator
- Python & PowerShell reverse shell templates
- Session logging support
- Kill clients & listeners on the fly
## Installation


```bash
git clone https://github.com/vibebhavv/Flesh.git
cd Flesh
python3 main.py
```
## Installation


Start Listener
```
python3 flesh.py -p 4444
```
Multiple ports
```
python3 flesh.py -p 4444,5555,6666
```
Bind to specific interface
```
python3 flesh.py -l 0.0.0.0 -p 4444
```
Enable logging
```
python3 flesh.py -p 4444 --log logs/
```

## Generate Payload

Flesh can generate reverse shell payloads from templates.

Python payload
```
python3 flesh.py -g py -p 4444 -l YOUR_IP
```
PowerShell payload
```
python3 flesh.py -g ps -p 4444 -l YOUR_IP
```

## Shell Modes

TTY – basic interactive shell

PTY – spawns full /bin/bash (Linux only)

Switch Shell type- 
```
set shell pty
```

## Logging

If enabled, every session is saved as:

```
logs/session_<id>_<ip>.txt
```

Includes:

- Incoming output
- Sent commands
- Timestamps
## Project Structure

```
Flesh/
│
├── main.py
├── assets/
│   ├── template_py.txt
│   └── template_ps.txt
└── logs/
```
## Authors
[@vibebhavv](https://www.github.com/vibebhavv)

⚠️ Disclaimer

This tool is for educational and research purposes only.
Use only on systems you own or have explicit permission to test.

The author is not responsible for misuse.
## Future Ideas

- Encrypted connections
- File upload/download
- Meterpreter-style commands
- Session naming
- Tab completion
