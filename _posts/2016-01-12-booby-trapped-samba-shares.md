---
layout: post
title:  "Booby Trapping Samba Shares"
categories: samba linux blue_team
description: Simple guide to setting up trapped samba shares to alert you if someone is poking around where they shouldn't be
comments: true
tags:
  - samba
  - linux
  - blue_team
---

# Booby Trapping Samba Shares

This is a simple guide to setting up fake Samba shares that'll send you an email when accessed.  The idea is that an attacker, after getting into your network, is going to search around for the good stuff.  If you mix in low hanging fruit, it can give you an early indicator if someone is in your network.

This guide is assuming you already have a configured Samba server, up and operational.

## Samba Config

Unfortunately, I couldn't find any way to separate out log files based on share.  What we'll need to do is make sure auditing is configured, and look through syslogs for anything suspicious.

### A note about auditing

Fair warning, depending on your normal usage, this will create a lot of log entries.  The settings below will log pretty much everything your users do on the server.  As someone who has dealt with "Well, I don't know what happened, my work just disappeared" a few too many times, I think it is a very fair price to pay.

### Extra settings for [global]

The following extra settings need to be enabled in the [global] section of your smb.conf:

   full_audit:prefix = %u|%I|%S
   full_audit:failure = connect
   full_audit:success = connect disconnect mkdir rmdir open close read pread write pwrite sendfile rename unlink chmod fchmod chown fchown chdir ftruncate lock symlink readlink link mknod realpath
   full_audit:facility = local5
   full_audit:priority = notice
   vfs object = full_audit

This enables full auditing, and has it log to syslog.  If necessary, you can always scale it back by changing what gets actually logged.  The one we definitely use is chdir for the rule below.

### New Share

Next, create the share (or shares) that you want to be traps.  A simple example is below:

	[passwords]
		comment = Centralized Password Storage
		path = /srv/samba/passwords

Create the folder and give it read permissions.

	user@server:~/$ sudo mkdir -p /srv/samba/passwords
	user@server:~/$ sudo chmod a+rX /srv/samba/passwords


Restart samba, and all the audit data should be going to syslog.

## Swatch Config

Swatch is used for actually monitoring the log file, to look for a specific pattern, and take action when it finds a result.  First things first, we'll install swatch.  It is a pretty standard application, and should be available in the package manager of your choice.  For example, also in Ubuntu:

    user@server:~/$ sudo apt-get install swatch

Next, create a config file.  Here is a very simple one:

	user@server:~$ cat /etc/swatch.conf 
	watchfor	/passwords\|chdir\|ok\|chdir/
		echo
		mail = youremail@domain.com

Change out 'passwords' with whatever you have named your share.  The text inside the /data/ is what will be matched by swatch.  You can add other strings to catch on here if you want, but this will notify you the first time a user accesses a share.

NOTE: FOR THE LOVE OF GOD, MAKE SURE YOU PUT THAT BACKSLASH IN FRONT OF THAT PIPE.  Pipe by itself means OR, which means you'll match a lot of things.  Your coworkers will not be happy with 1000s of alerts within a few minutes.

Next, you'll need to set up the init.d/systemd startup script.  Below is a sample of each:

### SystemV


	/etc/init.d/swatch

{% highlight bash %}
#!/bin/sh
# Simple Log Watcher Program

case "$1" in
'start')
		/usr/bin/swatch --daemon --config-file=/etc/swatch.conf --tail-file=/var/log/syslog --pid-file=/var/run/swatch.pid
		;;
'stop')
		PID=`cat /var/run/swatch.pid`
		kill $PID
		;;
*)
		echo "Usage: $0 { start | stop }"
		;;
esac
exit 0
{% endhighlight %}

	user@server:~/$ sudo chmod +x /etc/init.d/swatch
	user@server:~/$ sudo update-rc.d swatch defaults
	user@server:~/$ sudo service swatch start

### Systemd

	/usr/lib/systemd/system/swatch.service

	[Unit]
	Description=Swatch Log Monitoring Daemon
	After=syslog.target

	[Service]
	ExecStart=/usr/bin/swatch --config-file=/etc/swatch.conf --tail-file=/var/log/syslog --pid-file=/var/run/swatch.pid --daemon
	ExecStop=kill -s KILL $(cat /var/run/swatch.pid)
	Type=forking
	PIDFile=/var/run/swatch/pid

	[Install]
	WantedBy=multi-user.target


	user@server:~/$ sudo systemctl enable swatch.service
	user@server:~/$ sudo systemctl start swatch.service



## Further Use

Now that you have your nice booby-trapped Samba share, you can always take it a step further and put some fun items in.

[http://sourceforge.net/p/adhd/wiki/Web%20Bug%20Server/](http://sourceforge.net/p/adhd/wiki/Web%20Bug%20Server/)
