# SSH PKI

## What is sshpki ?

sshpki is a small tool wrapping ssh-keygen to help manage ssh
certificate authorities, ssh certificates and key revocation lists.

It can create and keep track of host and user CA, all generated public
keys and associated certificates, their state (valid, expired,
revoked), enrolled yubikeys, etc.


This is still alpha software:
- some features are missing (complete yubikey support, paper backup
  export, commands on parameters, etc.)
- it is possible to instroduce inconsistencies in the database if an
  operation is stopped before it is finished (with Ctrl-C for
  instance)

## Session example

### Running sshpki

First, we create the database file:

```
$ ./sshpki.py -f /tmp/mypki -C
SSH PKI name: mypki
$
```

Then we can use it

```
$ ./sshpki.py -f /tmp/mypki
mypki> help

Documented commands (type help <topic>):
========================================
help  shell

Undocumented commands:
======================
EOF  ca  certs  keys  profiles  python  yubikey
```


### CA command

```
mypki> ca
mypki/CA> create foo
Is this a [H]ost CA or a [U]ser CA ? (h/u) u
Generating public/private rsa key pair.
Your identification has been saved in /dev/shm/tmpr2FFwu/foo.
Your public key has been saved in /dev/shm/tmpr2FFwu/foo.pub.
The key fingerprint is:
SHA256:ozXd+MUM8E5yHnvcZsaa886qwfkFOQ+DkxVzkPJYI5Q foo
The key's randomart image is:
+---[RSA 4096]----+
|          ....+o.|
|           oE ++ |
|          . **.. |
|         . O.@.+ |
|        S o O % *|
|       o o o = % |
|      .     = + o|
|             o = |
|            ..oo+|
+----[SHA256]-----+
Please export secret key to yubikey/file/paper backup. It will then be deleted
mypki/CA/foo/export> file /tmp/foo
Enter new passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved with the new passphrase.
mypki/CA/foo/export> 
Secret key has been exported. It is going to be deleted. Last chance to do another export. Delete? ? (y/n) y
mypki/CA> create bar
Is this a [H]ost CA or a [U]ser CA ? (h/u) h
Generating public/private rsa key pair.
Your identification has been saved in /dev/shm/tmpr2FFwu/bar.
Your public key has been saved in /dev/shm/tmpr2FFwu/bar.pub.
The key fingerprint is:
SHA256:9QYGpxC+ijvuq2oEcQaMaV3UUbchOVzrQYgxl4IOF2A bar
The key's randomart image is:
+---[RSA 4096]----+
|+o.E++*=B+*=     |
|+o+o + =oX+ +    |
|.+  + . o =+     |
|.    . . o.o.    |
|.     . S  .o    |
| . . .     .     |
|. . .            |
| ...             |
|=+=o             |
+----[SHA256]-----+
Please export secret key to yubikey/file/paper backup. It will then be deleted
mypki/CA/bar/export> 
Secret key has not been exported. Are you sure you want to delete it? ? (y/n) y
mypki/CA> ls
foo                              active USER signed  0 keys
bar                              active HOST signed  0 keys
mypki/CA> use foo
mypki/CA/foo> create k1
Enter cert name: k1_0
Generating public/private rsa key pair.
Your identification has been saved in /dev/shm/tmpr2FFwu/k1.
Your public key has been saved in /dev/shm/tmpr2FFwu/k1.pub.
The key fingerprint is:
SHA256:xisJnRIE4dcYQp9yGbaWUleP9a9KWTm749UMDNEB9xA k1
The key's randomart image is:
+---[RSA 2048]----+
| .=o* ... . ooEo |
| . * @   + . o.o |
|  + % . . . o   .|
|   * o o     =   |
|    o o S   + +  |
|     o o . o + + |
|      o . o o . o|
|       . . ..o   |
|          ..o.   |
+----[SHA256]-----+
Please export secret key to yubikey/file/paper backup. It will then be deleted
mypki/CA/foo/k1/export> 
Secret key has not been exported. Are you sure you want to delete it? ? (y/n) y
Choose profile:
 0. Create a new profile
profile:  ? (0) 0
mypki/CA/foo/profiles> create nolimit
Name: nolimit
Principals: 
Force command: 
Enforce source addresses: 
Permit agent forwarding ? (y/n) y
Permit port forwarding ? (y/n) y
Permit X11 forwarding ? (y/n) y
Permit PTY allocation ? (y/n) y
Permit user ~/.ssh/rc file ? (y/n) y
validity interval
    empty or <end> or <start>:<end> ; <start> or <end> being
    - YYYYMMDD
    - YYYYMMDDHHMMSS
    - [+-]([0-9]+[wdhms]){1,}):

mypki/CA/foo/profiles> create 90days
Name: 90days
Principals: root
Force command: 
Enforce source addresses: 1.2.3.4
Permit agent forwarding ? (y/n) y
Permit port forwarding ? (y/n) y
Permit X11 forwarding ? (y/n) y
Permit PTY allocation ? (y/n) y
Permit user ~/.ssh/rc file ? (y/n) y
validity interval
    empty or <end> or <start>:<end> ; <start> or <end> being
    - YYYYMMDD
    - YYYYMMDDHHMMSS
    - [+-]([0-9]+[wdhms]){1,}):
+90d
mypki/CA/foo/profiles> ls
nolimit                        no limits
90days                         principals=root, source_address=1.2.3.4, validity=+90d
mypki/CA/foo/profiles> 
Choose profile:
 0. Create a new profile
 1. nolimit              no limits
 2. 90days               principals=root, source_address=1.2.3.4, validity=+90d
profile:  ? (0/1/2) 1
Where is the private CA key ?
 0. Enter a file path
 1. file /tmp/foo
private key source:  ? (0/1) 1
Signed user key /dev/shm/tmpr2FFwu/tmpnH4fX7-cert.pub: id "k1_0" serial 0 valid forever
mypki/CA/foo> ls
k1                             ACTIVE  2048 bits:
  -> certificate k1_0         0 no limits 
mypki/CA/foo> create k2
Enter cert name: k2_1
Generating public/private rsa key pair.
Your identification has been saved in /dev/shm/tmpr2FFwu/k2.
Your public key has been saved in /dev/shm/tmpr2FFwu/k2.pub.
The key fingerprint is:
SHA256:cMFDsUjaWOi5qGfqbW70bXnHx+KuEL7XqO/eD8x2Hd4 k2
The key's randomart image is:
+---[RSA 2048]----+
|     .oo+.       |
|    .* .oo       |
|   .o.+ o.       |
|    o  o         |
|   . . .S      . |
|  ... . . o   o o|
| .. . .o. +=.. oE|
|. +o . +o+o=oo   |
|o=+o  .oB==++.   |
+----[SHA256]-----+
Please export secret key to yubikey/file/paper backup. It will then be deleted
mypki/CA/foo/k2/export> 
Secret key has not been exported. Are you sure you want to delete it? ? (y/n) y
Choose profile:
 0. Create a new profile
 1. nolimit              no limits
 2. 90days               principals=root, source_address=1.2.3.4, validity=+90d
profile:  ? (0/1/2) 2
Where is the private CA key ?
 0. Enter a file path
 1. file /tmp/foo
private key source:  ? (0/1) 1
Signed user key /dev/shm/tmpr2FFwu/tmpyIZtl_-cert.pub: id "k2_1" serial 1 for root valid from 2018-06-15T03:12:00 to 2018-09-13T03:13:46
mypki/CA/foo> ls
k1                             ACTIVE  2048 bits:
  -> certificate k1_0         0 no limits 
k2                             ACTIVE  2048 bits:
  -> certificate k2_1         1 principals=root, source_address=1.2.3.4, validity=+90d from Fri Jun 15 03:12:00 2018 to Thu Sep 13 03:13:46 2018
mypki/CA/foo> resign k2
Where is the private CA key ?
 0. Enter a file path
 1. file /tmp/foo
private key source:  ? (0/1) 1
Signed user key /dev/shm/tmpr2FFwu/tmplfOigc-cert.pub: id "k2_2" serial 2 for root valid from 2018-06-15T03:13:00 to 2018-09-13T03:13:59
mypki/CA/foo> ls
k1                             ACTIVE  2048 bits:
  -> certificate k1_0         0 no limits 
k2                             ACTIVE  2048 bits:
  -> certificate k2_1         1 principals=root, source_address=1.2.3.4, validity=+90d from Fri Jun 15 03:12:00 2018 to Thu Sep 13 03:13:46 2018
  -> certificate k2_2         2 principals=root, source_address=1.2.3.4, validity=+90d from Fri Jun 15 03:13:00 2018 to Thu Sep 13 03:13:59 2018
mypki/CA/foo> show
cert-authority ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDCmFjufXD7XBKT3nhJctIRenfrBsTquMCLvc6V3AkJazEyb9isOUfa1ntKUhwwnVg36jGnTYBQsPCISPvl/K56lBRUruIP2f8mcGFRiN2huFq/2r7NXWMX0PB2lnC+rRXuCSTrVyZLEm0l/uabG+v38yz1Tq2M8A768JEcdXhsqe6+NNvYcr24p1ksU7C/SWfTzi4NZIfkz1xguWmcsTkyVYu3DNhKO/XgbyspJ753swV9KXw++Pq9bcyxuhDzGDp42J/pbWE3DcKyhRMGJUR7AX0EOZNK1lo4KpWoyH2h+ZTqXfkjH4oWv2IFhOwjtDTfvS/5NQl23HLb+LlkDZtGAAQuyDV7QnTE+n0mg/mvnbRyRpmfze+CnieNfcNJA+p34asyUrz+nJ6r0tqk+8W2aU+Zqa49Hg6lNkQYg+aV5sJQ0MLGeqJZKlsqB95YDYb3cgM8Q/pmy4/Z9Bg6qy06LRTtfbOubvKTvEROoFcmEvQbAdiDX3rwwy8rRpxIxT0XUd03uy/NymSkHixa+JSmLYaaUjntlHmapEKvXh2HzBZ342/Cg29DSut0Ht9CRU/9KHEqJrno/1l7+LA1moqxIqx2X/ipExMWSYGu1zNjdtMluv7OaQFFYOFb3C1JroXYyeG9FBgGNq8d7UDL5DDgN3SpimdTPIBI37LD+pSzkQ== foo

mypki/CA/foo> show_cert k1_0
ssh-rsa-cert-v01@openssh.com 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 k1

mypki/CA/foo> show_key k1
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDgnhWmd9nUahXYwUg/d4by0L4ynxXl/AepzDcfBvWaBCwAC7cLYE2lXlM5BZ/Sfx+9W+b/1QssLmx73Od7wH1wRPQl5zCdqLijShpYdQeLDggO3MQeOGlA/Gs9imF2PwUGbqnu5rtJcb2rd6exXrHjozutF+P+7tzfK6B5ZkwpqeQPOk59+ZM3qdNzHFV24unfgZB8xG9NXFZxxh2DbGJVaQ5N8+BohFixaICdpeQDYbsORH84MzZVAt45waWsy5UkCK0vdLFp+Go4XpF4TBullED1rA/kOvsbMH8bZ5GaxJ+dYWTI2Z+3P3CKrGxJLBZh7/plUvhk1LEN2SE50yQ/ k1

mypki/CA/foo> export
export      export_krl  
mypki/CA/foo> export_krl /tmp/krl
mypki/CA/foo> !hd /tmp/krl
00000000  53 53 48 4b 52 4c 0a 00  00 00 00 01 00 00 00 00  |SSHKRL..........|
00000010  00 00 00 00 00 00 00 00  5b 23 12 71 00 00 00 00  |........[#.q....|
00000020  00 00 00 00 00 00 00 00  00 00 00 00              |............|
0000002c
mypki/CA/foo> revoke k2
Are you sure you want to revoke key [k2] ? (y/n) y
Revoking from /dev/shm/tmpr2FFwu/tmpvPnH2t
Revoking from /dev/shm/tmpr2FFwu/tmp9I1Tzz
mypki/CA/foo> ls
k1                             ACTIVE  2048 bits:
  -> certificate k1_0         0 no limits 
k2                             REVOKED 2048 bits:
  -> certificate k2_1         1 principals=root, source_address=1.2.3.4, validity=+90d from Fri Jun 15 03:12:00 2018 to Thu Sep 13 03:13:46 2018
  -> certificate k2_2         2 principals=root, source_address=1.2.3.4, validity=+90d from Fri Jun 15 03:13:00 2018 to Thu Sep 13 03:13:59 2018
mypki/CA/foo> export_krl /tmp/krl
mypki/CA/foo> !hd /tmp/krl
00000000  53 53 48 4b 52 4c 0a 00  00 00 00 01 00 00 00 00  |SSHKRL..........|
00000010  00 00 00 00 00 00 00 00  5b 23 13 19 00 00 00 00  |........[#......|
00000020  00 00 00 00 00 00 00 00  00 00 00 00 03 00 00 00  |................|
00000030  18 00 00 00 14 ba dd 3e  dd 5f 92 53 86 ff 3b 1c  |.......>._.S..;.|
00000040  e2 51 d9 4e b7 da 2e 3c  4c                       |.Q.N...<L|
00000049
```
### Other commands

```
mypki> keys
mypki/keys> ls
foo                            CA   ACTIVE   4096 bits  
bar                            CA   ACTIVE   4096 bits  
k1                             user ACTIVE   2048 bits  signed by [foo]
k2                             user REVOKED  2048 bits  signed by [foo]
mypki/keys> 
mypki> certs
mypki/certs> ls
k1_0                 key=k1                   foo             0 no limits 
k2_1                 key=k2                   foo             1 principals=root, source_address=1.2.3.4, validity=+90d from Fri Jun 15 03:12:00 2018 to Thu Sep 13 03:13:46 2018
k2_2                 key=k2                   foo             2 principals=root, source_address=1.2.3.4, validity=+90d from Fri Jun 15 03:13:00 2018 to Thu Sep 13 03:13:59 2018
mypki/certs> 
mypki> 
EOF       ca        certs     help      keys      profiles  python    shell     yubikey   
mypki> profiles
mypki/profiles> ls
nolimit                        no limits
90days                         principals=root, source_address=1.2.3.4, validity=+90d
mypki/profiles> 
mypki> yubikey
mypki/yubikey> l
*** Unknown syntax: l
mypki/yubikey> ls
mypki/yubikey> 
EOF     del     enroll  help    ls      python  shell   status  
mypki/yubikey> enroll
Enter yubikey owner: bob
This operation will erase all material on yubikey [3361077]. Continue ? (y/n) y
Set mode to CCID. Please unplug and replug the yubikey and press enter.
Resetting material
Successfully reset the application.
Successfully set new management key.
A new management key has been set
PUK and PIN must be between 6 and 8 digits
Enter new puk: 
Verifying - Enter new puk: 
Successfully changed the puk code.
Enter new pin: 
Verifying - Enter new pin: 
Successfully changed the pin code.
mypki/yubikey> ls
3361077    owned by bob        not used
```
