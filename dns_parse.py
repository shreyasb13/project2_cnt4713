#Functions for parsing DNS response

#Returns name, and the index after name.
def parse_name(data: bytes, index: int) -> tuple[str, int]:

    labels = []
    visited = set()  # guard against pointer loops

    while True:
        if index in visited:
            raise ValueError("Pointer loop detected in DNS response")
        visited.add(index)

        if index >= len(data):
            raise ValueError(f"Name parser ran off end of packet at offset {index}")

        length = data[index]

        if length == 0:  # End of name
            index += 1
            break

        #Compression: if the two high bits of a byte are set (0xC0),
        #the next byte forms a 14-bit offset pointer into the message.
        elif (length & 0xC0) == 0xC0:  # Compression pointer
            if index + 1 >= len(data):
                raise ValueError("Truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | data[index + 1]
            index += 2  # Advance past the 2-byte pointer
            # Follow the pointer
            label, _ = parse_name(data, pointer)
            labels.append(label)
            break

        else:  # Normal label
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
    elif rtype == 2:  # NS record
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