# THM: Masterminds

In this CTF we will harden our **Brim** skills by analyzing some malicious pcaps. Navigate to this [link](https://tryhackme.com/r/room/mastermindsxlq) to access the room.

### Scenario:

Three machines in the Finance department at Pfeffer PLC were compromised. We suspect the initial source of the compromise happened through a phishing attempt and by an infected USB drive. The Incident Response team managed to pull the network traffic logs from the endpoints. Use Brim to investigate the network traffic for any indicators of an attack and determine who stands behind the attacks. 

- **Table of Content**
    
    [Infection#1](https://www.notion.so/THM-Masterminds-f376c3fcb09647428252257f4e54159d?pvs=21)
    
    [Infection#2](https://www.notion.so/THM-Masterminds-f376c3fcb09647428252257f4e54159d?pvs=21)
    
    [Infection#3](https://www.notion.so/THM-Masterminds-f376c3fcb09647428252257f4e54159d?pvs=21)
    

## Infection 1

Start by loading the **Infection1** packet capture in Brim to investigate the compromise event for the first machine. All the PCAPs can be found here: **/home/ubuntu/Desktop/PCAPs**

### Provide the victim's IP address.

Since Brim comes with pre-loaded **Suricata Alerts** which are IOC’s out-of-the-box is good practice to start there. Once pcap is loaded, navigate to the **Suricata Alerts by Category**.

![Untitled](THM%20Masterminds%20f376c3fcb09647428252257f4e54159d/Untitled.png)

Very good, now use the **alert.category** as filter to get more details.

![Untitled](THM%20Masterminds%20f376c3fcb09647428252257f4e54159d/Untitled%201.png)

**Answer:**  192.168.75.249

### The victim attempted to make HTTP connections to two suspicious domains with the status '404 Not Found'. Provide the hosts/domains requested.

Using following query we will narrow down our search to filter http traffic from our address with code **404** - `192.168.75.249 path==”http” status_code==404`. Once applied, query will reveal our answer.

**Answer:** cambiasuhistoria.growlab.es,www.letscompareonline.com

### The victim made a successful HTTP connection to one of the domains and received the response_body_len of 1,309 (uncompressed content size of the data transferred from the server). Provide the domain and the destination IP address.

Again we will use following query to filter for http traffic with **response_body_len** parameter. 

`192.168.75.249 path=”http” response_body_len==1309` which will speed up the answer seek.

**Answer:** ww25.gocphongthe.com,199.59.242.153

### How many unique DNS requests were made to cab[.]myfkn[.]com domain (including the capitalized domain)?

Inspecting **Unique DNS queries** in Brim will uncover the mystery.

**Answer:** 7

### Provide the URI of the domain bhaktivrind[.]com that the victim reached out over HTTP.

Using mentioned domain as filter will show us the way - u can also click on it and use it as filter navigating to the **Unique DNS queries**.

**Answer:** /cgi-bin/JBbb8/

### Provide the IP address of the malicious server and the executable that the victim downloaded from the server.

Tweaking our previous HTTP query, we will add the **.exe** if we can find something useful.

`192.168.75.249 path=”http” .exe`

**Answer:** 185.239.243.112,/catzx.exe

### Based on the information gathered from the second question, provide the name of the malware using Virus Total.

Using links from the 2nd question, try to find the answer on **Relations** tab.

**Answer:** emotet

## Infection 2

Navigate to the Infection2 packet capture in Brim to investigate the compromise event for the second machine. All the PCAPs can be found here: **/home/ubuntu/Desktop/PCAPs.**

### Provide the IP address of the victim machine.

Again, our beloved pre-loaded **Suricata Alerts** will help us survive, navigate there and use filter options to reveal the victim adress.

**Answer:** 192.168.75.146

### Provide the IP address the victim made the POST connections to.

Using simple query will do the trick. `192.168.75.146 | method==”POST”`

**Answer:** 5.181.156.252

### How many POST connections were made to the IP address in the previous question?

Add `count()` at the end of the last query - or count it by yourself 😃

**Answer:** 3

### Provide the domain where the binary was downloaded from.

Downloading is associated with **HTTP GET** method, construct the query and look for domain address. `_path==”http” | method “GET”`

**Answer:** hypercustom.top

### Provide the name of the binary including the full URI.

Use query from previous question to get the answer.

**Answer:** /jollion/apines.exe

### Provide the IP address of the domain that hosts the binary.

Use query from previous question to get the answer.

**Answer:** 45.95.203.28

### There were 2 Suricata "A Network Trojan was detected" alerts. What were the source and destination IP addresses?

Using **Suricata Alerts** tab, we will reveal the alerts, then use **Brim** filtering features to get the answers.

**Answer:** 192.168.75.146,45.95.203.28

### Taking a look at .top domain in HTTP requests, provide the name of the stealer (Trojan that gathers information from a system) involved in this packet capture using **URLhaus** Database.

Using the .top domain address from earlier question, navigate to the [URLhaus](https://urlhaus.abuse.ch/) ****database and search for that domain and look for details which are simillar with our case.

![Untitled](THM%20Masterminds%20f376c3fcb09647428252257f4e54159d/Untitled%202.png)

**Answer:** Redline stealer

## Infection 3

Load the Infection3 packet capture in Brim to investigate the compromise event for the third machine. All the PCAPs can be found here: **/home/ubuntu/Desktop/PCAPs**

### Provide the IP address of the victim machine.

Once again, using **Suricata Alerts by Category** will help us dig. There are couple of categories but most relevant are Malware based. Use Brim filtering to  navigate to the answer.

![Untitled](THM%20Masterminds%20f376c3fcb09647428252257f4e54159d/Untitled%203.png)

**Answer:** 192.168.75.232

### Provide three C2 domains from which the binaries were downloaded (starting from the earliest to the latest in the timestamp).

Okay, lets circle back to the **Suricata Alerts by Category** and use filter from previous question - output will look similar to this.

![Untitled](THM%20Masterminds%20f376c3fcb09647428252257f4e54159d/Untitled%204.png)

Notice on the bottom, there are 3 alerts from different category - use it as search.

![Untitled](THM%20Masterminds%20f376c3fcb09647428252257f4e54159d/Untitled%205.png)

Now, you have three IP’s which are categorized as malicious and are using http **AND** the destination address is our victim’s computer. This is enough evidence to construct HTTP query which will help us with out answer. There are two hints - use sort of timestamp field and if you want to chain multiple values (like IP addresses)  you can use **OR** operator. query will looks similar to this

`_path==”http” | ip OR ip OR ip | sort ts` 

![Untitled](THM%20Masterminds%20f376c3fcb09647428252257f4e54159d/Untitled%206.png)

**Answer:** efhoahegue.ru,efhoahegue.ru,xfhoahegue.ru

### Provide the IP addresses for all three domains in the previous question.

Straight forward.

**Answer:** 162.217.98.146,199.21.76.77,63.251.106.25

### How many unique DNS queries were made to the domain associated from the first IP address from the previous answer?

By using query `_path==”dns” | ip | count()`  you will get the answer.

**Answer:** 2 

### How many binaries were downloaded from the above domain in total?

Do your math.

**Answer:** 5

### Provided the user-agent listed to download the binaries.

Navigate back to the HTTP query, left-click on any field and enroll **Open details** and search for **User Agent field**.

![Untitled](THM%20Masterminds%20f376c3fcb09647428252257f4e54159d/Untitled%207.png)

**Answer:** Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:25.0) Gecko/20100101 Firefox/25.0

### Provide the amount of DNS connections made in total for this packet capture.

Use query `_path==”dns” | count()`

![Untitled](THM%20Masterminds%20f376c3fcb09647428252257f4e54159d/Untitled%208.png)

**Answer:** 986

### With some OSINT skills, provide the name of the worm using the first domain you have managed to collect from Question 2. (Please use quotation marks for Google searches, don't use .ru in your search, and DO NOT interact with the domain directly).

There is no need to do any OSINT via Google and expose ourselves to a risk, follow the domain traces in Virus Total and take a good look in the **Relations** tab. Good luck.

**Answer:** phorphiex

Decent desert, thanks for tuning in, stay safe.