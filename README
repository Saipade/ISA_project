# Tunneling data transfers with DNS queries

## Brief description

This project focuses on implementing a tool for tunneling data through DNS queries.

Project consists of two applications: receiver and sender.

The client application sends data provided either by file or by standard input to the receiver. Activity is terminated upon the receival of end of file.

The server application listens on the default port for DNS communication (53). Incoming data transfers will be saved to disk in the form of files.

Two applications communicate with IPv4 as a Network protocol and UDP as a Transport protocol.

Both TCP and IPv6 are not supported.


## Project structure 

```
.
├── include
│   ├── base32.c
│   ├── base32.h
│   ├── dns.h
│   ├── logger.h
│   ├── macros.h
│   ├── misc.c
│   └── misc.h
├── Makefile
├── README
├── receiver
│   ├── dns_receiver.c
│   ├── dns_receiver_events.c
│   └── dns_receiver_events.h
├── sender
│   ├── dns_sender.c
│   ├── dns_sender_events.c
│   └── dns_sender_events.h
└── test
    ├── in
    │   └── little_test.html
    └── test.py

```

## Compilation

Build both sender and receiver:

```
make  # or make all
```
  
- Build only sender:
  
```
make sender
```

- Build only receiver:

```
make receiver
```
  
- Archive the content of this folder: 

```
make archive
``` 

## Usage

- Start listening to dns communcation:
  
```
sudo ./dns_receiver <host_base> <dst_filepath>
```

- Send file:
  
```
./dns_sender -u <UPSTREAM_DNS_IP> <host_base> <dst_filepath> <src_filepath>
```

## Author

- Maksim Tikhonov