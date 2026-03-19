# Alexa Arce PID: 6384093
# Diego Avalos PID: 6347463
# Cristian Mantilla PID: 6393437
# Shreya Sureshbabu Banumathi PID: 6472712

# Import socket module
from socket import *
import sys
import dns_parse

#Throw exception if usage does not have required amount of parameters
if len(sys.argv) < 3:
    raise IndexError(
        f"Expected 2 arguments! Only found {len(sys.argv) - 1}.\n"
        "Usage: python mydns.py domain-name root-dns-ip"
    )

# Get the domain name and the root DNS IP from the command line
domainName = sys.argv[1]
rootDnsIP = sys.argv[2]
nextDnsIP = None

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


#Index to iterate through reply
index = 0

# Gets counts from the header

index += 2 #Skip id
index += 2 #Skip flags
questionCount = int.from_bytes(receiveData[index : index + 2], 'big')
index += 2 #Move past questions
answerCount = int.from_bytes(receiveData[index : index + 2], 'big')
index += 2 #Move past answers
authorityCount = int.from_bytes(receiveData[index : index + 2], 'big')
index += 2 #Move past authority count
additionalCount = int.from_bytes(receiveData[index : index + 2], 'big')
index += 2 #Move past additional count





# Print results from root DNS server
print("------------------------------------------------------------")
print("DNS server to query:", rootDnsIP)
print("Reply received. Content overview:")
print("\t", answerCount, "Answers.")
print("\t", authorityCount, "Intermediate Name Servers.")
print("\t", additionalCount, "Additional Information Records.")


# Will move past the question section
for _ in range(questionCount):
    _, index = dns_parse.parse_name(receiveData, index)
    index += 4

#Prints answers
if(answerCount) :
    print("\nAnswers Section:")
    for _ in range(answerCount):
        rr, index = dns_parse.parse_rr(receiveData, index)
        dns_parse.print_rr(rr)


if authorityCount:
    print("\nAuthority Section:")
    for _ in range(authorityCount):
        rr, index = dns_parse.parse_rr(receiveData, index)
        dns_parse.print_rr(rr)

# Parse the additional information section
if additionalCount:
    print("\nAdditional Information Section:")
    for _ in range(additionalCount):
        rr, index = dns_parse.parse_rr(receiveData, index)
        dns_parse.print_rr(rr)
        if rr["type"] == 1 :
            nextDnsIP = rr["rdata"]


while nextDnsIP != None:
    udpSocket.sendto(packet, (nextDnsIP, 53)) # Send query to the intermediate server
    receiveData, receiveServer = udpSocket.recvfrom(512) # Receive at most 512 bytes

    index = 0
    index += 2  # Skip id
    index += 2  # Skip flags
    questionCount = int.from_bytes(receiveData[index: index + 2], 'big')
    index += 2  # Move past questions
    answerCount = int.from_bytes(receiveData[index: index + 2], 'big')
    index += 2  # Move past answers
    authorityCount = int.from_bytes(receiveData[index: index + 2], 'big')
    index += 2  # Move past authority count
    additionalCount = int.from_bytes(receiveData[index : index + 2], 'big')
    index += 2  # Move past additional count

    # Print results from root DNS server
    print("------------------------------------------------------------")
    print("DNS server to query:", nextDnsIP)
    print("Reply received. Content overview:")
    print("\t", answerCount, "Answers.")
    print("\t", authorityCount, "Intermediate Name Servers.")
    print("\t", additionalCount, "Additional Information Records.")
    nextDnsIP = None
    # Will move past the question section
    for _ in range(questionCount):
        _, index = dns_parse.parse_name(receiveData, index)
        index += 4


    # Prints answers
    if (answerCount):
        print("\nAnswers Section:")
        for _ in range(answerCount):
            rr, index = dns_parse.parse_rr(receiveData, index)
            dns_parse.print_rr(rr)

    if authorityCount:
        print("\nAuthority Section:")
        for _ in range(authorityCount):
            rr, index = dns_parse.parse_rr(receiveData, index)
            dns_parse.print_rr(rr)

    # Parse the additional information section
    if additionalCount:
        print("\nAdditional Information Section:")
        for _ in range(additionalCount):
            rr, index = dns_parse.parse_rr(receiveData, index)
            dns_parse.print_rr(rr)
            if rr["type"] == 1 and answerCount == 0:
                nextDnsIP = rr["rdata"]



