# Alexa Arce PID: ?
# Diego Avalos PID:6347463
# Christian Montilla PID: ?
# Shreya Sureshbabu PID: ?

#import socket module
from socket import *
import sys

#get the domain name and the root DNS IP from the command line 
domainName = sys.argv[1]
rootDnsIP = sys.argv[2]

print("Domain Name:", domainName)
print("Root DNS IP:", rootDnsIP)


#Send query to root DNS server

#DNS Query Packet

#encode the domain name
encodedDomain = b'' #empty bytes

domainName = domainName.split('.') 
for i in range(len(domainName)):
    lenOfDomain = len(domainName[i])
    encodedDomain += bytes([lenOfDomain]) #length of the domain in bytes
    encodedDomain += domainName[i].encode("ASCII") #name of domain is ASCII

encodedDomain += bytes([0])

queryType = bytes([0]) + bytes([1]) # = 1 encoded in Big endian format (IN = internet)
queryClass = bytes([0]) + bytes([1]) # = 1 encoded in Big endian format (Record query)


#create the heade
transID = bytes([0]) + bytes([1]) #transaction ID 2 bytes
flags = bytes([1]) + bytes([0]) #flags 2 bytes (0x0100 standard query)
questionCount = bytes([0]) + bytes([1]) #question count 2 bytes (one question)
ansRecCount = bytes([0]) + bytes([0]) #answer record count 2 bytes (no answers yet)
authRecCount = bytes([0]) + bytes([0]) #authority record count 2 bytes (no auth records)
addRecCount = bytes([0]) + bytes([0]) #additional record count 2 bytes (no additional record)

header = transID + flags + questionCount + ansRecCount + authRecCount + addRecCount #header 12 bytes


#DNS packet 
packet = header + encodedDomain + queryType + queryClass

#send the DNS query
udpSocket = socket(AF_INET, SOCK_DGRAM) # create the new UDP socket

udpSocket.sendto(packet, (rootDnsIP, 53)) #send the packet to the root dns id on port 53


#Receive reply root DNS server
receiveData, receiveServer = udpSocket.recvfrom(512) #receive at most 512 bytes
