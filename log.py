import csv
from collections import defaultdict

#  Read lookup table
def ReadLookupTable(filename):
    lookup = {}
    with open(filename, 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            print(row)
            dstport = row['dstport']
            protocol = row['protocol'].lower()
            tag = row['tag ']

            lookup[(dstport, protocol)] = tag
    return lookup

#  Parse flow logs and map to tags
def ParseFlowLogs(log_filename, lookup):
    tag_count = defaultdict(int)
    port_protocol_count = defaultdict(int)

    with open(log_filename, 'r') as file:
        for line in file:
            parts = line.strip().split()
            if len(parts) < 7:
                continue  # Skip invalid lines
            
            dstport = parts[5]  # dstport is at index 5
            protocol_num = parts[7]  # Protocol number is at index 7

            # Map protocol number to name
            protocol = 'tcp' if protocol_num == '6' else 'udp' if protocol_num == '17' else 'icmp' if protocol_num == '1' else 'unknown'
            
            # Lookup tag
            tag = lookup.get((dstport, protocol), "Untagged")
            
            # Increment the count for the tag
            tag_count[tag] += 1

            # Increment the count for the port/protocol combination
            port_protocol_count[(dstport, protocol)] += 1

    return tag_count, port_protocol_count

#  Write output
def WriteOutput(tag_count, port_protocol_count, output_filename):
    with open(output_filename, 'w') as file:
        #  Tag Counts
        file.write("Tag Counts:\n")
        file.write("Tag,Count\n")
        for tag, count in sorted(tag_count.items()):
            file.write(f"{tag},{count}\n")
        
        #  Port/Protocol Combination Counts
        file.write("\nPort/Protocol Combination Counts:\n")
        file.write("Port,Protocol,Count\n")
        for (dstport, protocol), count in sorted(port_protocol_count.items()):
            file.write(f"{dstport},{protocol},{count}\n")

# Main function to execute the program
if __name__ == "__main__":
    #  file paths
    lookup_table_filename = "lookup_table.csv"
    flow_logs_filename = "flow_logs.txt"
    output_filename = "output.txt"

    # Read the lookup table
    lookup = ReadLookupTable(lookup_table_filename)
    
    # Parse flow logs and generate counts
    tag_count, port_protocol_count = ParseFlowLogs(flow_logs_filename, lookup)
    
    # Write the output to a file
    WriteOutput(tag_count, port_protocol_count, output_filename)

    print("Output written to", output_filename)

