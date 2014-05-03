pollyaudit
==========

Audit and test module for Polly, a deterministic Bitcoin hardware wallet adhering to [BIP32]. Polly is still in development, more information to come.

Tested with Python 3.3 and 3.4.


Dependencies
------------

* Python 3.x
* Cython
* cython-hidapi (https://github.com/ngburke/cython-hidapi)
* pycoin (https://github.com/richardkiss/pycoin)


Installing on Windows
---------------------

(Installation is currently quite messy on Windows. Working to streamline the process.)

* Install Python 3.4 (make sure Python34 and Python34/Scripts are in your path)
 
* Clone cython-hidapi (https://github.com/ngburke/cython-hidapi)

* Clone pollyaudit (https://github.com/ngburke/pollyaudit)

* Cython requires a C compiler. Follow the instructions at https://github.com/cython/cython/wiki/64BitCythonExtensionsOnWindows to install a free C compiler that will work on 32 or 64 bit machines.

* Open the SDK command window (Programs > Microsoft Windows SDK v7.x > Microsoft Windows SDK v7.x Command Prompt) and enter the commands below for a 64-bit machine. The setenv line can me modified for 32-bit machines by replacing /x64 with /x86.

 * set DISTUTILS_USE_SDK=1
 * setenv /x64 /release

* From the SDK command window, install cython (pip install cython)

* From the SDK command window, go to the cython-hidapi source folder and install ('setup.py install')

* Install pycoin (pip install "pycoin==0.4")

* Connect Polly via USB

* Go to the pollyaudit source folder and run the auditor (audit.py)


[BIP32]: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
