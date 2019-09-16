# arp-poison
An arp-poisoning tool created in C - Made for Linux

**Usage**

**Compile:**
    
    **$** gcc -o arp-poison arp-poison.c
 
 **Run:**
 
    **$** ./arp-poison <INTERFACE> <TARGET IP> <GATEWAY IP>
    **$** ./arp-poison wlan0 192.168.0.123 192.168.0.1
