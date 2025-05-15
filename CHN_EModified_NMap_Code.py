import nmap

# Prompt the user for a target IP address or hostname
target = input("Enter the target IP address or hostname: ")

# Prompt the user for additional command-line arguments
arguments = input("Enter additional command-line arguments for nmap: ")

# Create a new nmap scanner object
nm = nmap.PortScanner()

# Scan the remote host with the specified arguments
nm.scan(target, arguments=arguments)
if not nm[target].state() == 'up':
    print("Error: Target is not up")
    exit(1)

# Print the extracted information
print("Host: %s (%s)" % (nm[target].hostname(), nm[target].state()))
if 'osmatch' in nm[target]:
    print("OS: %s" % (nm[target]['osmatch'][0]['name']))
else:
    print("OS: Unknown")
print("Ports:")
for port in nm[target]['tcp']:
    print("Port: %s \t State: %s \t Service: %s" % (port, nm[target]['tcp'][port]['state'], nm[target]['tcp'][port]['name']))