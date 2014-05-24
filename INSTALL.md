## Requirements:
  
  * Python >= 2.4
```bash
sudo apt-get install python
```
  * PyCrypt
```bash
sudo apt-get install python-crypto
```
  * hping3 (client only)
```bash
apt-get install hping3
```

## Installing The Server:

After installing the requirements, the first step is to download, unpack, and install the knockknock tarball:

```bash
wget http://www.thoughtcrime.org/software/knockknock/knockknock-0.5.tar.gz
tar zxvf knockknock-0.5.tar.gz
cd knockknock-0.5
sudo python setup.py install
```

Once this is done, we need to configure the server.
  
## Configuring The Server:

Every (user,machine) tuple that the server wishes to grant port knocking access to gets a 'profile'.  If, for instance, there were a user 'clement' who needed port knocking access from three remote machines -- 'laptop', 'munin' and 'storage', you would create three profiles on the server, perhaps named: 'clement-laptop', 'clement-munin', and 'clement-storage'.  Each profile maintains its own encryption keys and state.  Each profile has its own 'knock port' where the port knock requests are sent.  This has to be a port that you don't plan on using for a running service.

You can create profiles on the server by running:

```bash
sudo knockknock-genprofile <knockPort> <profileName>
```

So, for instance, if we wished to create a profile for 'clement-laptop' that used '666' as a knock port, we'd run

```bash
sudo knockknock-genprofile 666 clement-laptop'
```

That's it, your server is now configured.  To run it, simply execute:

```bash
sudo knockknock-daemon
```

## Configuring The Client:

Follow the server installation instructions to get the software on the client.  To configure the client, however, we need to copy the profile information on the server to the client machine.  If we're configuring the user 'clement' on the client machine 'laptop', the profile on the server might be called 'clement-laptop'.  We'd need to copy the files from /etc/knockknock.d/profiles/clement-laptop/ on to the client machine.  You can copy the values by hand, email the files (securely!), or (if you have root access), scp them.

The default settings for knockknock put the files  in  '~/.knockknock/<serverHostName>/' on the client machine. That is,  if the server is called myserver.com, the profile information would  be copied to '/home/clement/.knockknock/myserver.com/' on the client.

Using scp:

```bash
scp root@myserver.com:/etc/knockknock.d/profiles/laptop-clement/* ~/.knockknock/myserver.com/
```

You can also specify a host folder by using the -d flag. This will allow you to keep your host files seperate from your computer, in an  encrypted volume, or in a folder in a different directory.

## Configuring The Server Firewall Rules:

The goal here is to firewall off all the ports that you don't want to be fully public, and to have connection attempts to firewalled ports be logged to '/var/log/kern.log'.  There is a script called 'minimal-firewall.sh' included with knockknock that will will firewall off everything (but of course any port can be opened by a knockknock request).  Feel free to use or modify this script. Otherwise, you'll want to setup the firewall rules generally as follows.

Let's say that on the server we're running three services: pop3s (995), ssh (22), and httpd (80).  We want httpd to be public, but we want sshd and imapd to only be available to those who send valid port knock requests.  The rules might look as follows.

We want to allow existing open connections and all outgoing traffic:
```bash
sudo iptables -A INPUT -m state --state RELATED,ESTABLISHED -j \
ACCEPT

sudo iptables -A OUTPUT -m state --state NEW,RELATED,ESTABLISHED \
-j ACCEPT

sudo iptables -A OUTPUT -j ACCEPT
```

We want to setup a REJECT logging rule that we'll call REJECTLOG:

```bash
sudo iptables -N REJECTLOG

sudo iptables -A REJECTLOG -j LOG --log-level debug \
--log-tcp-sequence --log-tcp-options --log-ip-options -m limit \
--limit 3/s --limit-burst 8 --log-prefix "REJECT "

sudo iptables -A REJECTLOG -p tcp -j REJECT --reject-with tcp-reset
sudo iptables -A REJECTLOG -j REJECT
```

And finally setup the INPUT rules to allow connections on port 80 but reject everything else:

```bash
sudo iptables -A INPUT -m state --state NEW -p tcp --dport 80 -j \
ACCEPT
sudo iptables -A INPUT -j REJECTLOG
```

## Setting Up The KnockKnock for reboot's

You'll want all of this to be in some sort of script that runs at boot. Otherwise a reboot will bring your host back to its initial state.

First you will want to make sure the knockknock-daemon runs on boot. This is a very simple script that will start knockknock-daemon on boot.

```bash
cp knockBoot /etc/init.d/knockBoot
update-rc.d knockBoot defaults
```

Next you will want to save the firewall profile you created in the last step to a file and have it get reset on boot. To start save your iptables rules.

```bash
iptables-save > /etc/iptables.up.rules
```

Now, set those rules as the default rules to run when the network comes up. Enter the following text into '/etc/network/if-pre-up.d/iptables'.

```bash
#!/bin/sh
/sbin/iptables-restore < /etc/iptables.up.rules
exit 0 
```

Now make that file executable.

```bash
chmod +x /etc/network/if-pre-up.d/iptables
```

## Using knockknock:

Now that you have knockknock-daemon running, the firewall rules configured on the server, and your profile installed on the client, you're ready to open some ports.  On the client, you simply run 'knockknock -p <portToOpen> -s myserver.com'.  To open, for instance, ssh (22):

```bash
sudo knockknock -p 22 -s myserver.com
```

You now have the amount of time specified by the 'delay' parameter in /etc/knockknock.d/config on the server to connect from your client's IP address to port 22 (defaults to 15 seconds).  As soon as you connect, no further connections will be allowed unless another knockknock request is issued.

### Specifying a knockknock profiles:

If you are keeping your knockknock profiles in an encrypted volume or on portable media you can use the "directory" option to specify the directory to use as the profile.

```bash
sudo knockknock -p 22 -s myserver.com -d /media/truecrypt6/myserver_profile
```

This is also useful if you have a host with a dynamic hostname. You can use the -d option to select a profile with a differnt name than the host selected.

### Optionally using knockknock-proxy:

After you have the basic knockknock system running, you might find yourself wishing that you didn't have to type "knockknock -p <whatever> myserver.com" all the time.  It's not such a big deal for opening an ssh session, but what about your pop3 client? That's the kind of software which might want to periodically make connections on its own, and even if it doesn't, opening up a terminal to run 'knockknock' every time you'd like to click 'check mail' is kind of a drag.

So knockknock-proxy is a small SOCKS proxy that is knockknock-aware.  It binds to a port you specify on localhost, and then implements the SOCKS protocol as usual.  However, whenver it sees a request for a connection to a host that you have configured knockknock for, it quickly sends a knock to the server before proxying the connection through.  The upshot is that any application which has SOCKS proxy support will seamlessly auto-knock each time it would like to make a connection.

### To run knockknock-proxy, you simply execute:

```bash
sudo knockknock-proxy <listenPort>
```
Be aware that while knockknock-proxy binds to localhost and isn't accessable from the network, it doesn't support any type of authentication mechanism to differentiate between users on a local system.  This means that it's best suited for personal, single-user systems.

Also note that you CAN NOT use knockknock-proxy and the command-line app 'knockknock' simultaneously.  If knockknock-proxy is running, you should only be using knockknock-proxy.

