# Alexa Arce PID: 6384093
# Diego Avalos PID: 6347463
# Cristian Mantilla PID: 6393437
# Shreya Sureshbabu Banumathi PID: 6472712

# Import socket module
from socket import *
import sys

#Throw exception if usage does not have required amount of parameters
if len(sys.argv) < 3:
    raise IndexError(
        f"Expected 2 arguments! Only found {len(sys.argv) - 1}.\n"
        "Usage: python mydns.py domain-name root-dns-ip"
    )

# Get the domain name and the root DNS IP from the command line
domainName = sys.argv[1]
rootDnsIP = sys.argv[2]

print("Domain Name:", domainName)
print("Root DNS IP:", rootDnsIP)


# Send query to root DNS server

# DNS Query Packet

# Encode the domain name
encodedDomain = b'' # Empty bytes

domainName = domainName.split('.')
for i in range(len(domainName)):
    lenOfDomain = len(domainName[i])
    encodedDomain += bytes([lenOfDomain]) # Length of the domain in bytes
    encodedDomain += domainName[i].encode("ASCII") # Name of domain is ASCII

encodedDomain += bytes([0])

queryType = bytes([0]) + bytes([1]) # = 1 encoded in Big endian format (IN = internet)
queryClass = bytes([0]) + bytes([1]) # = 1 encoded in Big endian format (Record query)


# Create the header
transID = bytes([0]) + bytes([1]) # Transaction ID 2 bytes
flags = bytes([1]) + bytes([0]) # Flags 2 bytes (0x0100 standard query)
questionCount = bytes([0]) + bytes([1]) # Question count 2 bytes (one question)
ansRecCount = bytes([0]) + bytes([0]) # Answer record count 2 bytes (no answers yet)
authRecCount = bytes([0]) + bytes([0]) # Authority record count 2 bytes (no auth records)
addRecCount = bytes([0]) + bytes([0]) # Additional record count 2 bytes (no additional record)

header = transID + flags + questionCount + ansRecCount + authRecCount + addRecCount #header 12 bytes


# DNS packet
packet = header + encodedDomain + queryType + queryClass

# Send the DNS query
udpSocket = socket(AF_INET, SOCK_DGRAM) # Create the new UDP socket
udpSocket.sendto(packet, (rootDnsIP, 53)) # Send the packet to the root DNS IP on port 53

# Receive reply root DNS server
receiveData, receiveServer = udpSocket.recvfrom(512) # Receive at most 512 bytes

# Gets counts from the header
answerCount = int.from_bytes(receiveData[6:8], 'big')
authorityCount = int.from_bytes(receiveData[8:10], 'big')
additionalCount = int.from_bytes(receiveData[10:12], 'big')

# Prints results from root DNS server
print("------------------------------------------------------------")
print("DNS server to query:", rootDnsIP)
print("Reply received. Content overview:")
print("\t", answerCount, "Answers.")
print("\t", authorityCount, "Intermediate Name Servers.")
print("\t", additionalCount, "Additional Information Records.")

# Moves the index past the header 12 bytes
index = 12

# Will move past the question section
while receiveData[index] != 0:
    index += receiveData[index] + 1
index += 1
index += 4


# Will skip over the answer section
for _ in range(answerCount):
    index += 2 # name pointer
    index += 8  # type, class, ttl
    dataLength = int.from_bytes(receiveData[index:index+2], 'big')
    index += 2 + dataLength


# Will skip over the authority section
for _ in range(authorityCount):
    if receiveData[index] == 192:  # compressed name
        index += 2
    else: # uncompressed name
        while receiveData[index] != 0:
            index += receiveData[index] + 1
        index += 1
    index += 8
    dataLength = int.from_bytes(receiveData[index:index + 2], 'big')
    index += 2 + dataLength

# Processes the additional information section
print("Additional Information Section:")

nextDnsIP = None

for _ in range(additionalCount):
    index += 2  # name pointer
    recordType = int.from_bytes(receiveData[index:index+2], 'big')
    index += 2
    index += 2  # class
    index += 4  # ttl
    dataLength = int.from_bytes(receiveData[index:index+2], 'big')
    index += 2

    # If record is an a record and DL is 4 bytes, extract the IP address
    if recordType == 1 and dataLength == 4:
        ipBytes = receiveData[index:index+4]
        ipAddr = ".".join(str(b) for b in ipBytes) # Converts bytes into a legible IP address format

        print("IP:", ipAddr)

        # If a valid IP address is found, set it as the next DNS server to query if one has not already been set
        if nextDnsIP is None:
            nextDnsIP = ipAddr

    index += dataLength


print("------------------------------------------------------------")
print("Next DNS server to query:", nextDnsIP)


while nextDnsIP is not None:
    udpSocket.sendto(packet, (nextDnsIP, 53)) # Send query to the intermediate server
    receiveData, receiveServer = udpSocket.recvfrom(512) # Receive at most 512 bytes

    # Gets the counts from the header
    answerCount = int.from_bytes(receiveData[6:8], 'big')
    authorityCount = int.from_bytes(receiveData[8:10], 'big')
    additionalCount = int.from_bytes(receiveData[10:12], 'big')

    print("------------------------------------------------------------")
    print("DNS server to query:", nextDnsIP)
    print("Reply received. Content overview:")
    print("\t", answerCount, "Answers.")
    print("\t", authorityCount, "Intermediate Name Servers.")
    print("\t", additionalCount, "Additional Information Records.")

    index = 12 # Moves the index past the header 12 bytes

    # Skips the question section
    while receiveData[index] != 0:
        index += receiveData[index] + 1
    index += 1
    index += 4

    # Prints answers if any
    if answerCount > 0:
        print("Answer section:")
        for _ in range(answerCount):
            index += 2
            recordType = int.from_bytes(receiveData[index:index+2], 'big')
            index += 8
            dataLength = int.from_bytes(receiveData[index:index+2], 'big')
            index += 2 + dataLength
            if recordType == 1 and dataLength == 4:
                ipBytes = receiveData[index:index+4]
                ipAddr = ".".join(str(b) for b in ipBytes)
                print("Final IP:", ipAddr)
            index += dataLength
        break

    # Skips the authority section
    for _ in range(authorityCount):
        if receiveData[index] == 192: # compressed
            index += 2
        else:
            while receiveData[index] != 0:
                index += receiveData[index] + 1
            index += 1
        index += 8
        dataLength = int.from_bytes(receiveData[index:index+2], 'big')
        index += 2 + dataLength

    # Processes the additional information section
    print("Additional Information Section:")
    nextDnsIP = None
    for _ in range(additionalCount):
        index += 2
        recordType = int.from_bytes(receiveData[index:index+2], 'big')
        index += 2
        index += 2
        index += 4
        dataLength = int.from_bytes(receiveData[index:index+2], 'big')
        index += 2
        if recordType == 1 and dataLength == 4:
            ipBytes = receiveData[index:index+4]
            ipAddr = ".".join(str(b) for b in ipBytes)
            print("IP:", ipAddr)
            if nextDnsIP is None:
                nextDnsIP = ipAddr
        index += dataLength

    print("------------------------------------------------------------")
    print("Next DNS server to query:", nextDnsIP)

