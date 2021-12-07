# the-transporter (network)

# Challenge description

We are pretty sure that Josephine is extracting classified information from the company servers and selling it to a competitor. However, we need proof of that before accusing her of such an awful crime. Please help us bring the proof to our CISO, so he can take the appropriate measures.

Flag format: CTF{SHA256}.

# Flag proof:

> CTF{5a91dd87aad8a58a90735abe38ea691c6e21b637251dcc7bbe220e49e47fb81a}
> 

# Summary:

We have a pcap file with lots of requests. We see that some requests are made to different subdomains of `evil[dot]com`. By entering the subdomains in CyberChef we can decode the flag

# Details:

We open the file in Wireshark and we see lots of requests. Let's analyze the http ones first. We see some random requests, and some are made to subdomains of `evil[dot]com`. Let's filter those ones with the following query: `http.host contains "evil.com"`. We see multiple subdomains of `evil[dot]com` that look like hex data. We can extract them manually in wireshark or using a script in tshark

```bash
tshark -r capture.pcap -Y 'http.host contains "evil.com"' -Tfields -e http.host | awk -F. -v ORS='' '{ print $1 }'
```

```bash
4354467b356139316464383761616438613538613930373335616265333865613639316336653231623633373235316463633762626532323065343965343766623831617d
```

Decoding it from hex gives us the flag