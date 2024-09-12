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

>[!TIP]Since Netcraft gives us a good high level overview of what we are up against when it comes to a target organizations web prescence - it makes sense to run it right at the start of our testing cycle along with `whois`

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

