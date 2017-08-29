salt-channel-python
===================

Python 3 implementation of Salt Channel v2.

WORK IN PROGRESS..


Usage
======

Quick start. Let's see what we can do right now?

`make`


Running unit tests:
    
`make test`


Running benchmarking suite for 'saltlib':
     
`make benchmark_saltlib`



Package 'saltlib'
================
This package is abstraction layer above different NaCl-based crypto libraries with 'pythonized' API style. 

For now next underlying crypto APIs are supported:
* LIB_TYPE_NATIVE - ctypes based bindings to system 'libsodium' library. 
* LIB_TYPE_PYNACL - PyNaCl package.
* LIB_TYPE_TWEETNACL_EXT - Native Python C extension calling original tweetnacl C code.

Current limitation: manual dependency installation required.

* PyNaCl

`python3 -m pip install --user PyNaCl`

* python-tweetnacl

`python3 -m pip install --user git+https://github.com/ppmag/python-tweetnacl.git#egg=tweetnacl`

Project
=======

Notes. Requirements etc.

* For Python 3.

* Implements Salt Channel v2 as specified in 
  [repo salt-channel](https://github.com/assaabloy-ppi/salt-channel).
  See files/spec/, spec-salt-channel-v2-draft4.md is the latest draft.

* Support for Salt Channel v1 is *not* needed.

* Both client and server implementation is needed.

* Salt Channel-over-TCP should be implemented.


Log entries
===========

* 2017-07-05, Alex, SaltLib package (NaCl API layer) is ready 
* 2017-06-15, Frans, repo created on Github. MIT License. 


