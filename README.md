## pcap-test
### Requirement
#### Ubuntu
```
sudo apt install libpcap-dev
```
#### Gentoo
```
emerge -a net-libs/libpcap
```
### Usage
```
cmake .
make
./pcap_test <network interface>
```
* <b> You must run as root.</b>
* The program was tested on 5.4.48-gentoo-x86_64.
