import nmap

# create a new nmap scanner object
nm = nmap.PortScanner()

# scan the remote host to get OS and version detection
nm.scan('45.33.32.156', arguments='-O -sV')

# print the extracted information
print("Host: %s (%s)" % (nm['45.33.32.156'].hostname(), nm['45.33.32.156'].state()))
print("OS: %s" % (nm['45.33.32.156']['osmatch'][0]['name']))
print("Ports:")

for port in nm['45.33.32.156']['tcp']:
    print("Port: %s \t State: %s \t Service: %s" % (port, nm['45.33.32.156']['tcp'][port]['state'], nm['45.33.32.156']['tcp'][port]['name']))
