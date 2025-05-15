import nmap

# prompt the user for a target IP address or hostname
target = input("Enter target IP address or hostname: ")

# prompt the user for additional command-line arguments
arguments = input("Enter additional command-line arguments for nmap: ")

# create a new nmap scanner object
nm = nmap.PortScanner()

# scan the remote host with the specified arguments
nm.scan(target, arguments=arguments)

# print the extracted information
print("Host: %s (%s)" % (nm[target].hostname(), nm[target].state()))
print("OS: %s" % (nm[target]['osmatch'][0]['name']))
print("Ports:")

for port in nm[target]['tcp']:
    print("Port: %s \t State: %s \t Service: %s" % (port, nm[target]['tcp'][port]['state'], nm[target]['tcp'][port]['name']))