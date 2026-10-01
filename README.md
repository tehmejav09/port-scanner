# Port Scanner

A small Python tool that checks which common ports are open on a
machine you own, using plain TCP sockets.

**Only scan devices and networks you own or have written permission
to test.**

## What it does

- Tries to connect to a short list of common ports (FTP, SSH, HTTP,
  HTTPS, MySQL, RDP, and others)
- Reports which ones are open and what they're typically used for
- Times the scan

## How to run it

    python3 port_scanner.py

You'll be asked for a target. For your own machine, use:

    127.0.0.1

Example output:

    Found 1 open port(s):
      443/tcp  open   HTTPS

    Scan finished in 0.31 seconds.

## Why I built it

Part of a series of small security projects on Cipherora
(cipherora.com), where I write up what I built, what broke, and what
I learned.
