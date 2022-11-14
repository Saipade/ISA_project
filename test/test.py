#!/usr/bin/env python3
# should be executed from root project directory
import os
import sys
import random
from itertools import chain
import os.path

os.system("make")
os.system('mkdir -p test/in/generated/')
os.system('mkdir -p test/out/generated/')

length = 1000
n_files = 10
# one of available interfaces
ip = sys.argv[1]

# run dns_receiver in other terminal window via `sudo ./dns_receiver example.com test/does/not/exist`

# invalid input for sender
assert os.system(f'./dns_sender -u {ip}13 example.com somefile test/in/little_test.h > /dev/null') == 256  # incorrect address
assert os.system(f'./dns_sender -u {ip} veryveryveryverylonglabelthatcertainlyexceedsthelimitof63charcters.com somefile test/in/little_test.h > /dev/null') == 256  # incorrect host's base
assert os.system(f'./dns_sender -u {ip} example.com somefile file_does_not_exist > /dev/null') == 256  # non-existent input file

# invalid input for receiver
assert os.system(f'sudo ./dns_receiver veryveryveryverylonglabelthatcertainlyexceedsthelimitof63charcters.com somepath > /dev/null') == 256 # incorrect host's base
# check ability for directory creation
os.system('echo privet | ./dns_sender -u {ip} example.com somefile > /dev/null')
assert os.path.exists('test/does/not/exist/somefile')
os.system('sudo rm -rf test/does')

for cnt in range(n_files):

    charset = ''.join([chr(i) for i in chain.from_iterable([[10], list(range(32, 127))])])
    data = ''.join((random.choice(charset) for x in range(length))) 

    filename = f'{cnt}.txt'
    with open(f'test/in/generated/{filename}', 'w') as f:
        f.write(data)
    
    os.system(f'./dns_sender -u {ip} example.com out/generated/{filename} test/in/generated/{filename} > /dev/null')

    if os.system(f"diff test/in/generated/{filename} test/out/generated/{filename} > /dev/null"):
        print(f'FAILED {filename}')
    else:
        print(f'OK: {filename}', end="\r")

# send big file
# os.system('./dns_sender -u {ip} example.com out/big_test.html test/in/big_test.html')