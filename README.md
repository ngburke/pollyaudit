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

1. Install Python 3.4 (make sure Python34 and Python34/Scripts are in your path)

2. Clone cython-hidapi (https://github.com/ngburke/cython-hidapi)

3. Clone pollyaudit (https://github.com/ngburke/)

4. Cython requires a C compiler. Follow the instructions at https://github.com/cython/cython/wiki/64BitCythonExtensionsOnWindows to install a free C compiler that will work on 32 or 64 bit machines.

5. Open the SDK command window (Programs -> Microsoft Windows SDK v7.x -> Microsoft Windows SDK v7.x Command Prompt) and enter the commands below for a 64-bit machine (replace /x64 with /x86 for 32-bit):

    set DISTUTILS_USE_SDK=1
    setenv /x64 /release

6. From the SDK command window, install cython (pip install cython)

7. From the SDK command window, go to the cython-hidapi folder from step 2 and install ('setup.py install')

8. Install pycoin (pip install "pycoin==0.4")

9. Connect Polly via USB

10. Go to the pollyaudit folder and run the auditor (audit.py)


[BIP32]: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
