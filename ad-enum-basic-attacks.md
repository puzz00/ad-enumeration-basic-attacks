# Active Directory | Enumeration and Basic Attacks

In this repo we will be learning how to enumerate active directory environments and perform basic attacks.

>[!NOTE]
>To gain a high level overview of how active directory works - please see [active-directory-introduction](https://github.com/puzz00/active-directory-introduction/blob/main/active-directory-introduction.md)

## External Information Gathering

Gathering information about targets is a crucial part of any penetration test. This stage can be seen as reconnaisance - getting to understand the target organization, its employees and technology being used.

>[!NOTE]
>We will be covering information gathering techniques in more detail in other repos - hopefully one to look specifically at *web application* info gathering and another more specifically on *open source intelligence gathering* - but for now we can focus our attention on some techniques which can be of use when targetting *active directory* environments being used by our targets

Keeping in mind that information gathering is *huge* we can start to take a look at *some* specific techniques which are of use.

### What are we Looking For?

We are essentialy looking for any information which will be of use to us when we are initially compromising the domain or later looking to elevate our privileges.

Here is a list of useful information to look for:

- IP Space
    - IP netblocks being used by the target
    - Cloud hosting providers being used
    - DNS record entries
    - A valid Autonomous System Number for the target
- Domain Info
    - Who administers the domain
    - Are there any subdomains in scope
    - Can we find publicly accessible domain services such as websites or VPN portals
    - Are there any defenses such as Intrusion Prevention Systems or Intrusion Detection Systems in place
- Schema Format
    - What can we discover about email accounts, AD usernames, password policies etc
- Data Disclosures
    - Can we find leaked data in publicly available resources such as .pdf files or github repos
- Breach Data
    - Are there any credentials already leaked which are from previous breaches of the target

### Where are we Looking?

Now we know *what* we are looking for we can think about *where* we can find it.

There are lots of places we can look for the data we are interested in. Here are some examples:

- ASN / IP Registrars
    - [IANA](https://www.iana.org) and [arin](https://www.arin.net) for targets in the Americas
    - [RIPE](https://www.ripe.net) for targets in Europe
    - [BGP Toolkit](https://bgp.he.net) to gain a comprehensive understanding of the targets network infrastructure
- Domain Registrars and DNS | the following tools can give us data about domain names, IP addresses and related network resources
    - [Domaintools](https://www.domaintools.net)
    - [PTRArchive](https://ptrarchive.com)
    - [ICANN](https://lookup.icann.org/lookup)
- Social Media
    - We can find useful data regarding targets and their employees using social media such as the following
        - Facebook
        - LinkedIn
        - Twitter
        - Online News Articles
- Public Facing Company Websites
    - A great resource - lots of relevant data can be found by *crawling* and *spidering* public facing websites | *About Us* and *Contact* pages are often very useful - as are embedded documents
- Breached Data Resources
    - [HaveIBeenPwned](https://haveibeenpwned.com) | great for checking for target email accounts
    - [Dehashed](https://www.dehashed.com) | great for searching for target emails, passwords, password policies and data useful to assist our spear phishing campaigns
- Google
    - Getting good at using advanced search operators - aka google dorks - is highly recommended as they can be used to find specific data about a target

### How?

Now we know *what* we are looking for and *some* places *where* we can find it, it is worth thinking about *how* we can use the aforementioned tools to find the information we are interested in.

>[!NOTE]
>This is a huge part of penetration testing in general - we will be looking at some useful *passive* techniques here but it is by no means exhaustive - hopefully future repos will go into more detail on areas such as *Open Source INTelligence* gathering techniques

#### Finding Address Spaces

It is useful to know IP ranges which belong to the target organisation since we can then test all of the other IP addresses in the block which they own.

We can use the [BGP Toolkit](https://www.he.net/) on Hurricane Electric to find address spaces for large companies. We just type in an IP address or a domain and see what it can retrieve.

>[!NOTE]
>Smaller companies will be using third-party address spaces such as AWS or Cloudflare | it is important we keep this in mind and check what is in scope to test

#### Website Ownership

Identifying basic information about domains is important as it is useful for the following tests which we perform. Here are some ways we can gain a high-level overview and then further enumeration via DNS *passive* reconnaissance techniques.

##### Whois

Whois queries databases which contain information regarding who owns internet resources such as domain, ip addresses and ip address blocks. We can use it from the command line or via third party web-based tools.

We can use whois to find out lots of useful information at the start of a web penetration test. We can feed it a domain name or an IP address.

A simple command to use form the command line is `sudo whois tesla.com`

>[!NOTE]
>We do not need to specify the protocol as we are looking just at the domain

>[!TIP]
>If we see that an asset is coming up to the end of its registry expiry date and nobody has renewed it - it might suggest to us that the asset is not considered very valuable to its owner

We can find nameservers for the domain. Nameservers translate domain names into IP addresses - they are a key part of DNS. We might get information about proxy servers here since some providers such as cloudflare proxy web server IP addresses so if we use a tool such as `host` to try to find the IP address of a domain we will instead be given the IP address of the cloudflare proxy server.

We can use IP addresses with whois like this: `sudo whois 104.21.44.108` This will let us know who owns the IP address and / or IP block which it belongs to. If the web servers IP address is being hidden by a proxy server, we will get information relating to the proxy server.

We might find that the web server is not hiding behind a proxy server. We will get information about the target web server if this is the case. We can research the registrar and other information we find using whois.

>[!TIP]
>We can use web services such as [domain tools](https://whois.domaintools.com) to perform whois lookups - the results can be easier to read

##### Netcraft

Netcraft can be used to fingerprint websites. It can be found at [netcraft](https://www.netcraft.com/)

There is a free tool on their website called `Whats that site running?`

>[!TIP]
>Since Netcraft gives us a good high level overview of what we are up against when it comes to a target organizations web prescence - it makes sense to run it right at the start of our testing cycle along with `whois`

Netcraft returns lots of useful information. We can get to know more about technologies being used by the target website - this means we get a basic fingerprint of the website just by using netcraft.

We can also find out more about Content Management Systems which might be running on the website from the tracking cookie information. Netcraft will also show us scripting frameworks such as javascript libraries which are being used.

#### DNS

Once we have gained a high level overview of the target organizations online prescence using whois and netcraft, we can turn our attention to DNS enumeration. This allows us to build a more detailed map of the target and its infrastructure.

We can enumerate DNS to try to find hosts which we were not aware of and which we can then ask our clients about if they are not already in our testing scope.

We might find subdomains which are on IP addresses which are in scope and can therefore be tested. These might not have been given to us explicitly but since they are in scope we can test them.

We can use `dnsrecon` from the command line. A simple search can be started using: `sudo dnsrecon -d tesla.com` The IP addresses returned are useful as they widen the attack surface.

A good resource to use which is still considered a *passive* reconnaisance technique is to use [dnsdumpster](https://dnsdumpster.com) This tool also lets us see visible hosts from an attackers perspective. It shows us an excellent map of what it discovers. We can export this map.

>[!NOTE]
>We do not need to specify the protocol when we use dnsdumpster

We can use *google dorks* to look for subdomains passively using a search such as `site:*.tesla.com`

If we find lots of the same subdomain such as `www` being returned we can filter these out using `site:*.tesla.com -www` and then add filters as we find more and more subdomains for example `site:*.tesla.com -www -shop -service`

#### Google Dorks

Google dorks are advanced web searches which use search operators. We can use them to enumerate lots of useful and specific information about target websites.

We can use `site:tesla.com` to limit the results to `tesla.com` and its subdomains. We can combine these advanced search terms with regular search terms like so: `employees site:tesla.com`

We could make the search more specific using `inurl:admin` These search terms can be combined like so: `site:google.com inurl:admin` Another search operator we can use which is similar to `inurl` is `intitle:admin`

We can use *wildcards* to look for specific resources such as subdomains: `site:*.tesla.com`

We can limit results to pages which have specific types of file using `filetype:pdf`

An example of combining dorks to find *pdf* files for a specific organization we could use `filetype:pdf inurl:tezzla.com`

We can search for directory listing using: `intitle:"index of"`

If we want to try to find credentials which have been leaked for a target organization we can try the following google dorks: `inurl:auth_user_file.txt` | `intitle:"index of" "credentials"`

We can try `inurl:wp-config.bak` to search for information leakage via back up files of the wordpress configuration file.

Finding email addresses is always useful, so we could try `intext:"@tezzla.com" inurl:tezzla.com`

There are resources we can use such as [google hacking](https://pentest-tools.com/information-gathering/google-hacking) and the [google-hacking-database](https://www.exploit-db.com/google-hacking-database) which can help us.

We can also automate the process using a tool such as [dork scanner](https://github.com/madhavmehndiratta/dorkScanner)

If we want to have a look at what a website used to look like in the past we can use `cache:tesla.com` or we could visit and use the [wayback machine](https://web.archive.org/)

All in all - by using combinations of advanced search operators aka google dorks we can attempt to gather useful data passively.

It is possible to really target what we are looking for using combinations of google dorks. An example of this - not necessarily related to pen testing target organizations but provided just for interest - would be looking for government websites which have exposed .csv files due to directory listing being enabled: `site:gov.* intitle:"index of" *.csv`

#### Public Websites

Along with the websites of the target company, we can look at social media to find out more about them. We can find valuable information relating to employees and technology being used by target organizations via platforms such as Facebook, Twitter, LinkedIn, Indeed and Glassdoor.

>[!TIP]
>Job postings can reveal data such as technology being used along with versions - looking at job descriptions and person specifications can be well worth our time

It is worth our while looking at a target organizations github presence as sometimes useful data such as hardcoded credentials are leaked via pushes to public repos. The [trufflehog](https://github.com/trufflesecurity/truffleHog) tool is a good way to automate searching for leaked credentials.

##### Target Company Websites

These are great places to look for useful information.

We will often find valuable data such as email addresses, telephone numbers, documents and more.

>[!TIP]
>Checking inside embedded documents for links to *intranet* sites or other internal infrastructure can help us map the internal domain

#### Credential Hunting

Finding usernames and passwords is always of interest, so we can try to find them using a variety of tools and techniques.

One tool we can use to enumerate *linkedin* for an organization is [linkedin2username]('https://github.com/initstring/linkedin2username') This tool will generate possible usernames from data found on *linkedin* which we can use in *password spraying* attacks.

If we want to find passwords in cleartext which have previously been looted, we can use a tool such as [dehashed]('https://dehashed.com/') which might give us old passwords from previous breaches. Many of these will not work but we only need one to be valid in order for us to further our enumeration and attacks.

We can use the data from *dehashed* to assist in creating a username list for our *password spraying* attacks.

>[!TIP]
>We can use `sudo python3 dehashed.py -q tezzla.com -p` from a bash session if we have *dehashed.py* on our machine

## Initial Domain Enumeration

We are going to look at this initial enumeration of a domain from the point of view of having a connection to a linux machine on the domain along with a subnet which is in scope but no other data to work with.

>[!NOTE]
>Organizations we are testing will give us various ways to access their internal networks - the example we are working with here is a common one

We first of all want to get an idea about the network we have been attached to - we can look for:

- Hosts
- Services | e.g. Kerberos, NetBIOS, LDAP, DNS
- AD Users
- AD Joined Computers
- Potential Vulnerabilities

>[!IMPORTANT]
>We need to systematically record all our findings during this initial enumeration stage - all data is useful

In order to enumerate the domain we can use *passive* and if in scope *active* techniques.

We will begin using a *passive* technique as it is best to keep as quiet as we can on networks.

### Listening to the Network Traffic

It is a good idea to listen to network traffic passively using tools such as `tcpdump` and `wireshark`

If we have access to a GUI we can use `wireshark` directly, but this is not always the case as often we only have access to a command line interface. This makes it important to get to know how to use a tool such as *tcpdump* as it is used via the command line and does not use many resources in terms of memory and processing power.

In this example even though we have a remote desktop session and therefore access to a GUI we will begin with *tcpdump* to practise using it.

>[!TIP]
>We can *write* the output from *tcpdump* to a *.pcap* file so we can later analyze it in wireshark | possibly on our own local machine after transferring it across using ssh or ftp for example

First of all we check which *network interfaces* we have available on the remote machine on the companys internal network using `ifconfig | grep -B1 "inet 172"`

We use *172* because we are looking for interfaces on the subnet in our scope which is *172.168.5.0/23*. The first host can be found at *172.168.4.1* and the last at *172.16.5.254*

>[!NOTE]
>The -B1 option specifies to *grep* that we want it to return one line before it finds the string *inet 172* as well as the line with the string in it | this is so we can see the interface name which in this case is one line above the IPv4 address

![ad1](/images/1.png)

We next look at which interfaces are available to use *tcpdump* on using `sudo tcpdump -D`

We see that the interface we want to listen on is *ens224*

![ad2](/images/2.png)

When we run *tcpdump* we specify that we want less data returned by using the `-q` flag since we are just looking for IP addresses at the moment. We write the output to a *.pcap* file using the `-w` flag: `sudo tcpdump -i ens224 -q -w data_1.pcap`

![ad3](/images/3.png)

>[!NOTE]
>There is much more we can do with *tcpdump* | it is worth getting to know it better but here this will do to help us find IP addresses of hosts on the network

After letting *tcpdump* run for a while we can stop it and start *wireshark* from the *terminal* using `sudo -E wireshark` | we then open the *data_1.pcap* file and take a look at its stats for a high level overview of the traffic on the network.

![ad4](/images/4.png)

![ad5](/images/5.png)

When we use the *display filter* functionality in *wireshark* to filter for *arp* frames we start to see IP addresses of interest which we can note down somewhere.

>[!NOTE]
>Display filters are applied in wireshark and do not lose other types of data whereas *capture filters* are specified when wireshark starts and cause it to not capture other types of data at all

![ad6](/images/6.png)

#### Responder

Another tool we can use is *responder* | this tool has lots of functionality and we will see how we can use it to attempt to capture hashes later but for now we are going to run it passively just to check out traffic on the network.

We can use `sudo responder -I ens224 -A` and then look at the captured data for IP addresses we might not have found using *tcpdump* or *wireshark*

>[!NOTE]
>The `-A` flag runs *responder* in its *analyze* mode which means that we can see traffic but we are not poisoning anything

![ad7](/images/7.png)

![ad8](/images/8.png)

### Active Scans

Moving into the realm of *active* scanning where we interact with hosts on the network in different ways we can start by using *ICMP* requests and responses to find live hosts.

>[!IMPORTANT]
>ICMP traffic is frequently dropped so we cannot rely on it alone | we must combine ICMP scans with other methods such as listening to network traffic and half-open SYN scans with a tool such as *nmap*

The *fping* tool is a good choice for checking for hosts using *icmp*

We can use the `-a` flag to return *alive* hosts

The `-s` flag gives us some useful *stats* at the end of the scan

Using the `-g` flag *generates* a target list

The `-q` flag gives us less data as we are just looking for IP addresses at the moment

The final command is `sudo fping -asgq 172.16.5.0/23` and it shows us in this case that it can find *three* alive hosts though as mentioned earlier this needs to be treated cautiously as often *icmp* traffic is dropped so responses are not received even though there are live hosts on the network.

![ad9](/images/9.png)

#### Nmap

The *nmap* tool is awesome | even Trinity uses it whilst fighting the matrix | but because it is awesome there is a lot to learn with it.

This is one tool which is really worth learning in depth. Here we are merely scratching the surface but by doing so we are able to find useful information regarding the target domain and the hosts on it.

There are many different types of scans we can perform using *nmap* and some are more noisy than others.

The default scan is a half-open SYN scan | we call it *half-open* because a TCP *SYN* packet is sent to initiate a connection to services which might be running on ports but if a *SYN-ACK* response is received the connection is closed - no final *ACK* is sent - instead *nmap* sends a *RST* packet.

The thinking here is that this is less noisy than a full TCP connection being established and this is true but it is still going to generate noise.

We can specify the half-open syn scan using the `-sS` flag in our command.

>[!NOTE]
>In this next part of the repo we will be using various flags with our nmap commands - they are not going to be explained here since the focus is on ad enumeration and attacks but they can be researched - hopefully we will get an nmap repo up at some point

We use `sudo nmap -Pn -n -sS --min-rate=250 172.16.5.0/23` to scan for live hosts which our earlier techniques might have missed.

![ad10](/images/10.png)

Once we have a list of targets we can put them into a *.txt* file which we can feed into our *nmap* scans using the `-iL` flag.

In this example we use more aggressive scans with the `-sV` and `-A` flags.

>[!CAUTION]
>Make sure to take the time to understand the *nmap* scans you are using if pentesting an organization and check they are in scope and that the client is happy for them to be used against their networks as sometimes active vuln scans from nmap might cause instability or knock devices offline

![ad11](/images/11.png)

We use `sudo nmap -Pn -n -sV -A --min-rate=250 -iL targets.txt` to enumerate the targeted hosts more thoroughly.

![ad12](/images/12.png)

It is worth noting that generally we want to scan *all* tcp ports on a host to see if there are services listening on higher or non-default ports. We can specify all ports using `-p-`

A command which uses some bashfu with our nmap scan to return just the port numbers of open tcp ports on a host from the entire port range is:

`ports130=$(sudo nmap -n -Pn -p- --min-rate=250 -sS --open 172.16.5.130 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)`

![ad13](/images/13.png)

The returned port numbers are stored in a variable - in this case `$ports130` - which we can use in further scans or put into a *.txt* file.

`sudo nmap -Pn -p$ports130 -sV -A -oA ports_130 172.16.5.130`

![ad14](/images/14.png)

>[!IMPORTANT]
>It is best to save *nmap* scan results into files so we can look back over the returned data and feed it into other tools | the `-oA` flag saves the results in several useful formats

By this point we have gained an initial understanding of the domain along with live hosts on it and potential vulnerabilities or attack paths via those hosts | the *nmap* scan results will show us versions of services and we might notice these are out of date and vulnerable to attack.

>[!NOTE]
>It might seem unlikely that we will find old versions of services or operating systems running but it does happen | some organizations continue to use out of date OS and services in their internal networks

### User Enumeration

Earlier we performed recon on external resources and hopefully created a list of possible users from employee data and perhaps old breach data. This data can be later used for attacks such as *password spraying*.

Another way we can enumerate possible usernames is by using the *kerbrute* tool which takes advantage of kerberos pre-authentication requests. It is often the case that failed attempts will not end up in logs or alerts so we can brute force potential usernames looking for valid ones.

>[!NOTE]
>We are trying to ultimately get valid creds for a domain user | even a low privileged one will allow us to further enumerate AD | so we are trying to find usernames in this stage as they can then be used in credential attacks such as *password spraying*

If we have created a possible username list from our external recon we can use this along with *kerbrute* but if not we can use a generic one such as *jsmith.txt* which can be found at [insidetrust](https://github.com/insidetrust/statistically-likely-usernames)

In order to use *kerbrute* to enumerate valid AD usernames we need to know the *Domain Controller* and the *domain* which we have discovered via our earlier initial enumeration of the domain.

In this example we found the *domain* name in the output of our *nmap* scans and the *Domain Controller* was found via *nmap* via its name and the fact that it had *port 88* open | this port is used for *kerberos* and if it is open it is a good indicator that we have found a dc

`sudo kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.168.5.5 jsmith.txt -o ad_users`

![ad15](/images/15.png)

We now have lots of valid usernames for the domain which we can use later in further attacks.

For an example ctf box in which we use *kerbrute* please see our writeup of [vulnnet:roasted](https://github.com/puzz00/vuln-net-roasted-thm/blob/main/vuln-net-roasted-thm.md)

## Gaining a Foothold in the Domain

We now have completed our initial enumeration of the domain. Our next step is to attempt to gain a foothold in it as this will let use further enumerate it and deepen our compromise of it.

Essentialy, we are attempting to gain cleartext credentials of a domain user - even a low privileged user account will be sufficient at this point.

In this section we will cover two common ways of achieving this foothold - poisoning network traffic with a *man-in-the-middle* attack and *password spraying*.

### Link Local Multicast Name Resolution Poisoning

Before we look at the specific commands involved in carrying out an LLMNR poisoning attack, it is worth our while to take the time to understand how it works at a high-level and why we carry it out.

#### Why?

The *why* is easy - we are attempting to capture NTLMv2 hashes so we can crack them offline and therefore obtain valid credentials for a domain user *or* pass them to other devices so we can impersonate the user we have captured the hash of. In this section we will focus on capturing the hashes in order to crack them and obtain cleartext credentials.

#### How?

Let us know consider *how* this attack works.

>[IMPORTANT]
>Before continuing it makes sense to be familiar with how NT LAN Manager - NTLM - authentication works | this is covered in our [active-directory-introduction](https://github.com/puzz00/active-directory-introduction/blob/main/active-directory-introduction.md#nt-lan-manager) repo

Link Local Multicast Name Resolution is a protocol which enables name resolution to take place on a local network if Domain Name Services do not work or are not used.

A device can send a broadcast (multicast) message to all the other devices on a subnet by using the broadcast address if DNS has failed.

An example of this would be a user typing in `\\FileServer\Documents\account.docx` when they are trying to access a shared resource which is really named `\\FileServer\Documents\accounts.docx`

DNS will fail to resolve this request so by default windows will fall back on LLMNR to attempt to resolve it.

In our example, once DNS has failed, the host will send a multicast message to all the other devices which are on the same local network - link - as it. This message essentialy asks the other devices if they know where to find `\\FileServer\Documents\account.docx`

This is where our attack comes in!

As an attacker on the same local network as the victim host, we can listen for these messages and *respond* to them with a lie - we pretend that we are hosting the resource `\\FileServer\Documents\account.docx`

At this point, we enter the NTLM authentication process and we - the attacker - are pretending to be the legitimate server. This is where we send a challenge including a nonce to the victim. As per normal NTLM authentication the victim then responds to this challenge by sending us an *authenticate* message which of course includes the username, domain name and most importantly for our attack their response to our challenge which is nothing less than an encrypted value which has been created using the nonce and *the users NTLM hash*!

>[!NOTE]
>The NTLM hash might be NTLMv1 but this is unlikely since it is not considered cryptographically secure so most of the time it will be NTLMv2

At this point we have captured a domain users NTLMv2 hash and can proceed to the offline cracking part of the attack.

##### Responder

The *responder* tool we used earlier to sniff network traffic to passively enumerate the domain can be used to perform an LLMNR poisoning attack.

Pentesting distros such as kali and parrot have *responder* built-in. Before using it, we need to check out which network interface we want to run it with by using the `ifconfig` command.

We can run an llmnr poisoning attack using `sudo responder -I eth0` where the `-I` flag lets us specify the interface we want it to listen on.

![ad16](/images/16.png)

There are a number of other flags which can be used but we will not be going into these much at this point since the basic command is sufficient to get *responder* listening to network traffic and responding to events in order to force victim machines to send across their *NTLM* hashes.

With that being said, two common flags are `-w` which starts a *WPAD* rogue server and `-f` which gets *responder* to try to *fingerprint* the victim hosts os and version.

>[!TIP]
>The `-w` flag can be useful as it captures *HTTP* requests sents by users running *IE* if it has *Auto Detect Settings* enabled

Assuming our *responder* captures an ntlm hash we will see it displayed in our terminal window. The hash will be saved to a file for each host - these logs can be found at `/usr/share/responder/logs` and they take the format of `MODULE NAME - HASH TYPE - CLIENT IP.txt`

>[!NOTE]
>Each *NTLMv2* hash captured will be different even if they are for the same user on the same machine since a *timestamp* is included in the hash

![ad17](/images/17.png)

Since we are trying to gain cleartext credentials for a domain user at this point, we can let responder run for quite some time whilst we are working on other tasks.

>[!TIP]
>Setting up a responder when we first being testing an internal network is a good idea | this can be done early in the morning and or during lunch as there will be lots of traffic when users log on to the network

###### Hash Cracking

Once we have harvested some ntlm hashes it is time to attempt to crack them offline. We can use *hashcat* to do this along with either a custom wordlist generated for the specific organization we are targeting or a good generic one.

We will need to use the *hashcat mode* of *5600* for cracking *NTLMv2* hashes which are the most common hash type to capture using this attack.

>[!CAUTION]
>*NTLMv2* hashes are *slow* to crack | be prepared for a long wait even if using a GPU based cracking rig | it can be practically impossible to crack them if strong passwords are used but we can generally rely on people being people and coming up with weak ones so it is worth giving it a go

The basic syntax for running a cracking attempt on ntlmv2 hashes saved into one file called `hashes.txt` and using the `rockyou.txt` wordlist is as follows: `sudo hashcat -a 0 -m 5600 hashes.txt rockyou.txt -O`

![ad18](/images/18.png)

![ad19](/images/19.png)

![ad20](/images/20.png)

>[!IMPORTANT]
>The `-a 0` option specifies that we want to use a basic *dictionary attack* as the *attack mode* and the `-O` flag *optimizes* the kernel for cracking which makes the attack much faster | please be aware that the `-O` flag is a good choice if we know or believe the passwords to be less than 31 characters but will miss things if they are greater than this because *hashcat* will limit the password length to 31 characters

If we successfully crack even *one* hash we can use it to gain a foothold in the domain and this will enable us to deepen own compromise of it even all the way up to full pwnership - when hacking active directory environments it really is a case of a small key opening a big door :smiley: 
