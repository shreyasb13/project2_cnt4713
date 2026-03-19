# Alexa Arce PID: 6384093
# Diego Avalos PID: 6347463
# Cristian Mantilla PID: 6393437
# Shreya Sureshbabu Banumathi PID: 6472712

# Import socket module
from socket import *
import sys


#Functions for parsing DNS response

#Returns name, and the index after name.
def parse_name(data: bytes, index: int) -> tuple[str, int]:

    labels = []
    visited = set()  #guard against pointer loops

    while True:
        if index in visited:
            raise ValueError("Pointer loop detected in DNS response")
        visited.add(index)

        if index >= len(data):
            raise ValueError(f"Name parser ran off end of packet at offset {index}")

        length = data[index]

        if length == 0:  #End of name
            index += 1
            break

        #Compression: if the two high bits of a byte are set (0xC0),
        #the next byte forms a 14-bit offset pointer into the message.
        elif (length & 0xC0) == 0xC0:  #Compression pointer
            if index + 1 >= len(data):
                raise ValueError("Truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | data[index + 1]
            index += 2  #Advance past the 2-byte pointer
            #Follow the pointer
            label, _ = parse_name(data, pointer)
            labels.append(label)
            break

        else:  #Normal label
            index += 1
            labels.append(data[index:index + length].decode("ASCII"))
            index += length

    return ".".join(labels), index

#
def parse_rr(data: bytes, index: int) -> tuple[dict, int]:
    name, index = parse_name(data, index)

    rtype = int.from_bytes(data[index:index + 2], "big")
    index += 2 #Move past type
    index += 2 #Skip class
    index += 4 #Skip time to live
    rdlen = int.from_bytes(data[index:index + 2], "big")
    index += 2 #Move past data length
    rdata = data[index:index + rdlen]
    index += rdlen

    # Decode RDATA based on type
    if rtype == 1 and rdlen == 4:  # A record
        decoded = ".".join(str(b) for b in rdata)
    elif rtype == 2:  #NS record
        decoded, _ = parse_name(data, index - rdlen)
    elif rtype == 28: #IPV6
        decoded = "IPV6 - IGNORED"
    else:
        decoded = rdata.hex()

    return {"name": name, "type": rtype, "rdata": decoded}, index

def print_rr(rr: dict) -> None:
    if rr['type'] == 1:
        print(f"\tName : {rr['name']}\tIP : {rr['rdata']}")
    elif rr['type'] == 28:
        None
    else :
        print(f"\tName : {rr['name']}\tName Server: {rr['rdata']}")
    return



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
    _, index = parse_name(receiveData, index)
    index += 4

#Prints answers
if(answerCount) :
    print("\nAnswers Section:")
    for _ in range(answerCount):
        rr, index = parse_rr(receiveData, index)
        print_rr(rr)


if authorityCount:
    print("\nAuthority Section:")
    for _ in range(authorityCount):
        rr, index = parse_rr(receiveData, index)
        print_rr(rr)

# Parse the additional information section
if additionalCount:
    print("\nAdditional Information Section:")
    for _ in range(additionalCount):
        rr, index = parse_rr(receiveData, index)
        print_rr(rr)
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
        _, index = parse_name(receiveData, index)
        index += 4


    # Prints answers
    if (answerCount):
        print("\nAnswers Section:")
        for _ in range(answerCount):
            rr, index = parse_rr(receiveData, index)
            print_rr(rr)

    if authorityCount:
        print("\nAuthority Section:")
        for _ in range(authorityCount):
            rr, index = parse_rr(receiveData, index)
            print_rr(rr)

    # Parse the additional information section
    if additionalCount:
        print("\nAdditional Information Section:")
        for _ in range(additionalCount):
            rr, index = parse_rr(receiveData, index)
            print_rr(rr)
            if rr["type"] == 1 and answerCount == 0:
                nextDnsIP = rr["rdata"]