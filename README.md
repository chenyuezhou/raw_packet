# raw_packet

Forging Layer 4 packets using Raw Socket

# build 

```
make
```

# example

**Syn packet**

```
$./src/raw_socket -S 127.0.0.1:8080 -D 127.0.0.1:8081 syn
send success

$tcpdump -A -i lo -nnn port 8080 -S
10:21:21.349513 IP 127.0.0.1.8080 > 127.0.0.1.8081: Flags [S], seq 0, win 65535, length 0
E..(..@.@.<.....................P...r...
```

**Rst packet(with specify seq and ack)**

```
$./src/raw_socket -S 127.0.0.1:8080 -D 127.0.0.1:8081 -a 100 -s 101 rst
send success

tcpdump -A -i lo -nnn port 8080 -S
10:28:01.412104 IP 127.0.0.1.8080 > 127.0.0.1.8081: Flags [R.], seq 101, ack 100, win 65535, length 0
E..(..@.@.<................e...dP...q...
```
