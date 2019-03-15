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

### Usage Examples
$ source venv/bin/activate
