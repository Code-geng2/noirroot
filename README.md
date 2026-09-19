# NoirRoot

Basic web vulnerability checker — CODE GENG.

Runs on Termux and Kali Linux.

## Features
- Common port scanning
- HTTP security header checks
- HTTPS/SSL certificate check
- Subdomain enumeration (common wordlist)
- Directory/path brute-force (common wordlist)
- Basic SQL error-based probe (non-destructive)

## Disclaimer
Only scan domains/servers you own or have explicit authorization to test.
Unauthorized scanning may be illegal in your jurisdiction.

## Install

```bash
git clone https://github.com/YOUR_USERNAME/noirroot.git
cd noirroot
pip install -r requirements.txt
```

## Usage

```bash
python noirroot.py yourdomain.com
```

## Install as a system command (Termux/Kali)

```bash
chmod +x noirroot.py
cp noirroot.py $PREFIX/bin/noirroot      # Termux
# or: sudo cp noirroot.py /usr/local/bin/noirroot   # Kali

noirroot yourdomain.com
```

## License
Built by CODE GENG (@codegengtech).
