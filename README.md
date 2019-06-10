Firewall-2-Firewall
=========

### Requirements
* `Z3` theorem prover from Microsoft Research, version >= `4.4.0`
* `GHC` the Glasgow Haskell Compiler, version >= `7.10.3`
* `cabal-install` command line interface to Cabal and Hackage, version >= `1.22.6.0`
* `python` Python language interpreter, version == 2.7.*
* `virtualenv` tool to create isolated Python environments, version >= 15.1.0
* `pip` tool for installing Python packages, version >= 9.0.1

### Installation
Install the required packages
```
sudo apt install z3 libz3-dev ghc cabal-install python-pip python-virtualenv
```
Update cabal package list and make the virtual environment
```
cabal update
chmod +x setup.py update_libs.sh f2f
make
```
The libraries and executables are installed in the `venv` python virtual environment:
```
source venv/bin/activate
```

the executable is `f2f`.

### Usage
```
usage: f2f SOURCE-SYSTEM INTERFACE-FILE CONFIGURATION-FILE TARGET-SYSTEM

positional arguments:
SOURCE-SYSTEM - the source firewall system, one between iptables, pf and ipfw
INTERFACE-FILE - interface specification file (see the axamples)
CONFIGURATION-FILE - the configuration file for the source firewall system
TARGET-SYSTEM - the target firewall system, one between iptables, pf and ipfw

### Usage Examples
$ source venv/bin/activate
$ f2f iptables interface-file config-file ipfw
```

### Examples

```
$ source venv/bin/activate
$ f2f iptables Example/interfaces Example/iptables.conf ipfw
Solving: [##################################################] (   36/   36) 100.00%
PROBLEM FOUND!
In ipfw the following rule schema is not expressible!
==============================================================================
|  srcIp  |  dstIp  ||   tr_srcIp   : tr_srcPort |   tr_dstIp   : tr_dstPort |
==============================================================================
|  Self   |  Self   || id           : id         | NAT (~Self)  : id         |
==============================================================================
Hence the following is impossible to achieve:
=====================================================================================
||      sIp       | sPort |      dIp       | dPort | prot || tr_src |    tr_dst    ||
=====================================================================================
||   127.0.0.1    |   *   | 151.15.185.183 |   80  | tcp  || - : -  | 10.0.0.8 : - ||
|| 151.15.185.183 |       |                |       |      ||        |              ||
||    10.0.0.1    |       |                |       |      ||        |              ||
||  192.168.0.1   |       |                |       |      ||        |              ||
=====================================================================================

PROBLEM FOUND!
In ipfw the following rule schema is not expressible!
==============================================================================
|  srcIp  |  dstIp  ||   tr_srcIp   : tr_srcPort |   tr_dstIp   : tr_dstPort |
==============================================================================
|  Self   |  Self   || NAT ( Self)  : id         | NAT (~Self)  : id         |
==============================================================================
Hence the following is impossible to achieve:
========================================================================================================
||      sIp       | sPort |      dIp       | dPort | prot ||       tr_src       |        tr_dst       ||
========================================================================================================
||   127.0.0.1    |   *   |   127.0.0.1    |  123  | udp  || 151.15.185.183 : - | 193.204.114.232 : - ||
|| 151.15.185.183 |       | 151.15.185.183 |       |      ||                    |                     ||
||    10.0.0.1    |       |    10.0.0.1    |       |      ||                    |                     ||
||  192.168.0.1   |       |  192.168.0.1   |       |      ||                    |                     ||
========================================================================================================

PROBLEM FOUND!
In ipfw the following rule schema is not expressible!
==============================================================================
|  srcIp  |  dstIp  ||   tr_srcIp   : tr_srcPort |   tr_dstIp   : tr_dstPort |
==============================================================================
|  Self   | ~Self   || NAT ( Self)  : id         | NAT (~Self)  : id         |
==============================================================================
Hence the following is impossible to achieve:
=======================================================================================================================
||      sIp       | sPort |              dIp              | dPort | prot ||       tr_src       |        tr_dst       ||
=======================================================================================================================
||   127.0.0.1    |   *   |       0.0.0.0 - 10.0.0.0      |  123  | udp  || 151.15.185.183 : - | 193.204.114.232 : - ||
|| 151.15.185.183 |       |      10.0.0.2 - 127.0.0.0     |       |      ||                    |                     ||
||    10.0.0.1    |       |   127.0.0.2 - 151.15.185.182  |       |      ||                    |                     ||
||  192.168.0.1   |       |  151.15.185.184 - 192.168.0.0 |       |      ||                    |                     ||
||                |       | 192.168.0.2 - 255.255.255.255 |       |      ||                    |                     ||
=======================================================================================================================
```

```
$ f2f iptables Example/interfaces Example/iptables.conf pf
PROBLEM FOUND!
In pf the following rule schema is not expressible!
==============================================================================
|  srcIp  |  dstIp  ||   tr_srcIp   : tr_srcPort |   tr_dstIp   : tr_dstPort |
==============================================================================
|  Self   |  Self   || id           : id         | NAT (~Self)  : id         |
==============================================================================
Hence the following is impossible to achieve:
=====================================================================================
||      sIp       | sPort |      dIp       | dPort | prot || tr_src |    tr_dst    ||
=====================================================================================
||   127.0.0.1    |   *   | 151.15.185.183 |   80  | tcp  || - : -  | 10.0.0.8 : - ||
|| 151.15.185.183 |       |                |       |      ||        |              ||
||    10.0.0.1    |       |                |       |      ||        |              ||
||  192.168.0.1   |       |                |       |      ||        |              ||
=====================================================================================

PROBLEM FOUND!
In pf the following rule schema is not expressible!
==============================================================================
|  srcIp  |  dstIp  ||   tr_srcIp   : tr_srcPort |   tr_dstIp   : tr_dstPort |
==============================================================================
|  Self   |  Self   || NAT ( Self)  : id         | NAT (~Self)  : id         |
==============================================================================
Hence the following is impossible to achieve:
========================================================================================================
||      sIp       | sPort |      dIp       | dPort | prot ||       tr_src       |        tr_dst       ||
========================================================================================================
||   127.0.0.1    |   *   |   127.0.0.1    |  123  | udp  || 151.15.185.183 : - | 193.204.114.232 : - ||
|| 151.15.185.183 |       | 151.15.185.183 |       |      ||                    |                     ||
||    10.0.0.1    |       |    10.0.0.1    |       |      ||                    |                     ||
||  192.168.0.1   |       |  192.168.0.1   |       |      ||                    |                     ||
========================================================================================================

PROBLEM FOUND!
In pf the following rule schema is not expressible!
==============================================================================
|  srcIp  |  dstIp  ||   tr_srcIp   : tr_srcPort |   tr_dstIp   : tr_dstPort |
==============================================================================
|  Self   | ~Self   || NAT ( Self)  : id         | NAT (~Self)  : id         |
==============================================================================
Hence the following is impossible to achieve:
=======================================================================================================================
||      sIp       | sPort |              dIp              | dPort | prot ||       tr_src       |        tr_dst       ||
=======================================================================================================================
||   127.0.0.1    |   *   |       0.0.0.0 - 10.0.0.0      |  123  | udp  || 151.15.185.183 : - | 193.204.114.232 : - ||
|| 151.15.185.183 |       |      10.0.0.2 - 127.0.0.0     |       |      ||                    |                     ||
||    10.0.0.1    |       |   127.0.0.2 - 151.15.185.182  |       |      ||                    |                     ||
||  192.168.0.1   |       |  151.15.185.184 - 192.168.0.0 |       |      ||                    |                     ||
||                |       | 192.168.0.2 - 255.255.255.255 |       |      ||                    |                     ||
=======================================================================================================================
```
