
"""
Tabulate JSON byte frequency files previously generated using 'ida_get_byte_frequency.py' within IDA Pro

Args:
    One or more .json input files.
"""
import sys
import json
from pprint import pprint

assert len(sys.argv) >= 2, "Expected at least one byte frequency .json file input"

# Combine the byte frequency dictionaries into one
tabulated = {}
for i in range(1, len(sys.argv)):
    path = sys.argv[i]
    print(f'Appending: {path}')
    with open(path) as fp:
        tmp = json.load(fp)
        #pprint(tmp)
        for byte, count in tmp.items():
            tabulated[byte] = tabulated.get(byte, 0) + count
#pprint(tabulated)

# Convert dictionary to a sorted list gathering the max count in the process: [byte, count]
largest = 0
byte_list = []
for byte, count in tabulated.items():
    byte_list.append([int(byte), count])
    if count > largest:
        largest = count
print(f'\nLargest byte count: {largest:,}')
byte_list = sorted(byte_list, key=lambda e: e[1])
#pprint(byte_list)

# Dump the values
print('Byte - Percent - Count')
for e in byte_list:
    print(f'{e[0]:02X}: {((e[1] / largest) * 100.0):0.4}  {e[1]:,}')


# Show byte frequency bar graph
"""
import matplotlib.pyplot as plt

byte_list = sorted(byte_list, key=lambda e: e[0])
#x = [x[0] for x in byte_list]
x = [f'{x[0]:02X}' for x in byte_list]
y = [x[1] / largest for x in byte_list]

fig, axs = plt.subplots(1, 1, figsize=(34, 13), tight_layout=True)
axs.bar(x, y)

plt.title('Code byte frequency', fontsize=20)
plt.xlabel('Code Byte', fontsize=18)
plt.ylabel('Count Ratio', fontsize=18)
plt.grid(axis='y', alpha=0.5)
plt.xticks(fontsize=6.5)
plt.xlim(axs.patches[0].get_x()-1, axs.patches[-1].get_x()+1)
#plt.savefig('byte_frequency.png')
plt.show()
"""