import nmap

# create a new nmap scanner object
target = input("Enter the target IP address or hostname: ")


args = input("Enter additional command-line arguments for nmap (e.g. -p 80,443 -T3): ")
nm = nmap.PortScanner()

# scan the remote host to get OS and version detection
nm.scan('45.33.32.156', arguments='-O -sV')
results_file = open('nmap_scan_results.txt', 'w')

# print the extracted information
results_file.write("Host: %s (%s)" % (nm['45.33.32.156'].hostname(), nm['45.33.32.156'].state()))
results_file.write("OS: %s" % (nm['45.33.32.156']['osmatch'][0]['name']))
results_file.write("Ports:")

for port in nm['45.33.32.156']['tcp']:
    results_file.write("Port: %s \t State: %s \t Service: %s" % (port, nm['45.33.32.156']['tcp'][port]['state'], nm['45.33.32.156']['tcp'][port]['name']))
results_file.close()

print("Results saved to nmap_scan_results.txt")