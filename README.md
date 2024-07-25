Packet Content Filter Demo
==========================

PCFD is a demo to support the validation of *[draft-cui-idr-content-filter-flowspec](https://datatracker.ietf.org/doc/draft-cui-idr-content-filter-flowspec/)*. Based on OpenBGPD-8.3-portable and FRRouting-10.2-dev, it added some adaptations and functions according to the draft. 

The following adaptations have been added to OpenBGPD-8.3-portable: 
* Using **bgpctl** to send flowspec command and announcement containing packet content filter rules

The following adaptations and functions have been added to FRRouting-10.2-dev: 
* Receiving and Analyzing flowspec announcement containing packet content filter rules
* Implementing traffic handling using **Netfilter**

PCFD currently supports analyzing and implementing combinations of the following flowspec options using Netfilter: 
* Source IP Address
* Destination IP Address
* Protocol(only IP/TCP/UDP)
* Content(according to the draft)

And this project only provides the changed files. For the complete software, please see the Installation section. 

Installation
------------

For OpenBGPD-portable, please see the
*[OpenBGPD Mirrors](https://www.openbgp.org/ftp.html)*.

For instructions on building and installing FRR from source for supported platforms, please see the
*[FRR developer docs](http://docs.frrouting.org/projects/dev-guide/en/latest/building.html)*.

To use the new functions implemented in this project, 
please replace the OpenBGPD and FRR files separately with files in the openbgpd/ and frr/ before compiling. 

Use
---

Once installed, please refer to the *[OpenBGPD Manual Pages](http://openbgp.org/manual.html)* and *[FRR user guide](http://docs.frrouting.org/)*
for instructions on use. 

And there is a new flowspec rule keyword '**payload**' according to the draft. 
You can use it in a format like 'payload *ptype* *otype* *offset* *content-length* *content* *mask*'. 
For example, the flowspec rule 'payload 1 2 0 3 0xAABBCC 0xFFFFFF' means
'ptype = 1, otype = 2, offset = 0, content-length = 3, content = 0xAABBCC, mask = 0xFFFFFF'. 

For more details, please refer to the *[draft](https://datatracker.ietf.org/doc/draft-cui-idr-content-filter-flowspec/)*.

Limitations & Contributing
--------------------------

OpenBGPD currently supports announcement of flowspec rules, but does not support reception, analysis, and forwarding. 
In order to quickly verify, FRRouting was used as the client to receive, analyze, and forward. 
And we will improve OpenBGPD's support for Packet Content Filter in the future.

In the future, we will add the following adaptations and functions: 
* Using **bgpd.conf** to send flowspec command and announcement containing packet content filter rules
* Analyzing and implementing **IPv6** packet content filter rules using Netfilter(only **IPv4** supported now)
* Sorting the packet content filter rules received according to the draft(so presently, it is better to input commands in **descending** order of priority)

We welcome and appreciate all contributions to help improve this project! 

Developers
----------
Rui Xu, Yannan Hu, Yujia Gao, and Yong Cui