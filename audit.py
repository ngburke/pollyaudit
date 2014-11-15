#!/usr/bin/python

"""
Audit and test module for Polly, a deterministic Bitcoin hardware wallet adhering to BIP32.

Requires the pollycom module for basic USB communications.


The MIT License (MIT)

Copyright (c) 2014 by Nathaniel Burke

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

import os
import sys
import io
import random
import hashlib
import binascii

from mnemonic                import Mnemonic
from pollycom.com            import PollyCom

# Pycoin is our reference wallet
from pycoin                  import encoding
from pycoin.key.bip32        import Wallet
from pycoin.tx               import Spendable
from pycoin.tx.tx_utils      import create_signed_tx, create_tx
from pycoin.tx.TxOut         import standard_tx_out_script
from pycoin.tx.script        import der
from pycoin.ecdsa            import ecdsa, intbytes, secp256k1


class PollyAudit():
    """
    Auditing tests and utilities for Polly.
    """
    
    
    def __init__(self, wordfile = 'wordlist.txt'):
        
        # Read create the mnemonic wordlist object
        self.mnemonic = Mnemonic("english")
    
        # Set up a default reference wallet
        self.wallet = Wallet.from_master_secret(bytes(0))
        
        # Set up a Polly communication pipe
        self.polly = PollyCom()
        
        # Default print padding
        self.PAD = "{:35}"
        
    #
    # Tests
    #
        
    def test_set_seed(self, wordlist):
        """
        Sets the wallet seed for Polly and the reference wallet.
        
        Note: Subsequent tests will use the seed set by this routine.
        
        wordlist -  a space separated string of 18 mnemonic words from the Polly wordlist.
                    Note: the checksum must be correct (part of the 18th word) - see BIP0039.
                    gen_wordlist can be used to generate a wordlist including the proper checksum.
        """
        
        assert len(wordlist.split(" ")) == 18, "expecting 18 words"
        assert self.mnemonic.check(wordlist) == True, "invalid word list"
        
        print (self.PAD.format("Set seed"), end='')
        
        # Set polly
        self.polly.send_set_master_seed(wordlist)
        print (self.__outok())
        
        # Set the reference wallet
        seed = self.mnemonic.to_seed(wordlist)
        self.wallet = Wallet.from_master_secret(seed)
        
        
    def test_key(self, keytype, account = 0, chain = 0, address = 0):
        """
        Performs a public key retrieval test, comparing Polly's key against the reference wallet.
       
        keytype - Type of key to retrieve, valid values are KEY_MASTER, KEY_ACCOUNT, KEY_CHAIN, or KEY_ADDRESS.
        account - Account to use for type KEY_ACCOUNT, KEY_CHAIN, KEY_ADDRESS.
        chain   - Chain to use for type KEY_CHAIN, KEY_ADDRESS.
        address - Index (0 - 0x7FFFFFFF) to use for type KEY_ADDRESS.
        """
        
        assert address < 0x80000000, "hardened address keys are not supported"
        
        if keytype == PollyCom.KEY_MASTER:
            print(self.PAD.format("Get master key"), end='')
            refkey = self.wallet
            check_chaincode = False
            
        elif keytype == PollyCom.KEY_ACCOUNT:
            print(self.PAD.format("Get account key m/" + str(account) + "h"), end='')
            refkey = self.wallet.subkey(account, is_hardened = True)
            check_chaincode = True
            
        elif keytype == PollyCom.KEY_CHAIN:
            print(self.PAD.format("Get chain key   m/" + str(account) + "h/" + str(chain)), end='')
            refkey = self.wallet.subkey(account, is_hardened = True).subkey(chain)
            check_chaincode = True
            
        else: # keytype == PollyCom.KEY_ADDRESS
            print(self.PAD.format("Get address key m/" + str(account) + "h/" + str(chain) + "/" + str(address)), end='')
            refkey = self.wallet.subkey(account, is_hardened = True).subkey(chain).subkey(address)
            check_chaincode = False
    
        # Get keypair from Polly 
        (pubx, puby, chaincode) = self.polly.send_get_public_key(keytype, account, chain, address)

        print (self.__outok())

        # Check against reference wallet
        addr       = encoding.public_pair_to_hash160_sec((pubx, puby))
        addr_check = encoding.public_pair_to_hash160_sec(refkey.public_pair)
        
        assert addr == addr_check, "public key mismatch\nexpected: " + self.hexstr(addr_check) + "\nactual:   " + self.hexstr(addr) 
        
        if check_chaincode == True :
            assert refkey.chain_code == chaincode, "chain code mismatch\nexpected: " + self.hexstr(refkey.chain_code) + "\nactual:   " + self.hexstr(chaincode) 
            
        


    def test_sign(self, keynums_satoshi, out_addr, out_satoshi, change_keynum, change_satoshi, prevtx_keynums, prevtx_outputs, prevtx_inputs):
        """
        Performs a tx signing test, comparing Polly's signed tx against the reference wallet.
    
        Basic tx signing parameters:
        
        keynums_satoshi - list of tuples (keynum, satoshis) with key indices and their unspent value to 
                          use as tx inputs. Funding above out_satoshi + change_satoshi will be fees.
        out_addr        - output address in bitcoin address format. 
        out_satoshi     - output amount in satoshis.
        change_keynum   - change key index in the wallet, use None for no change.
        change_satoshi  - change amount in satoshis, use 0 for no change. 
        
        
        Supporting (previous) txs will be created to fund keynums and are controlled by these parameters:
        
        prevtx_keynums  - keynums will show up as outputs of previous txs. A number randomly picked 
                          from this list controls how many keynums are chosen to include per prev tx.
        prevtx_outputs  - in addition to previous tx outputs funding keynums, other outputs may 
                          be present. A number randomly picked from this list controls how many 
                          ignored outputs are injected per keynum. 
        prevtx_inputs   - previous txs need inputs too. A number randomly picked from this list 
                          controls how many inputs are chosen per previous tx.
        """
        
        total_in_satoshi = sum(satoshi for _, satoshi in keynums_satoshi) 
        fee_satoshi      = total_in_satoshi - out_satoshi - change_satoshi
        chain0           = self.wallet.subkey(0, is_hardened = True).subkey(0)
        chain1           = self.wallet.subkey(0, is_hardened = True).subkey(1)
        
        assert total_in_satoshi >= out_satoshi + change_satoshi
        assert len(keynums_satoshi) <= 32
    
        #
        # Step 1: send the inputs and outputs to use in the signed tx
        #
        
        # Create the (key num, compressed public key) tuple, input keys assume an m/0h/0/keynum path for now. 
        keys = [(keynum, encoding.public_pair_to_sec(chain0.subkey(keynum).public_pair)) 
                for (keynum, _) in keynums_satoshi] 
        
        # Convert base58 address to raw hex address
        out_addr_160 = encoding.bitcoin_address_to_hash160_sec(out_addr)
        
        print()
        print("Sign tx parameters:", "")
        for i, (keynum, satoshi) in enumerate(keynums_satoshi):
            print("{:<10}{:16.8f} btc < key {}".format (" inputs" if 0 == i else "", satoshi          / 100000000, keynum))
        print("{:<10}{:16.8f} btc > {}".format         (" output",                   out_satoshi      / 100000000, self.hexstr(out_addr_160)))
        print("{:<10}{:16.8f} btc > key {}".format     (" change",                   change_satoshi   / 100000000, change_keynum))
        print("{:<10}{:16.8f} btc".format              (" fee",                      fee_satoshi      / 100000000))
        print("{:<10}{:16.8f} btc".format              (" total",                    total_in_satoshi / 100000000))
       
        print()
        print(self.PAD.format("Send tx parameters"), end='')
        
        # ---> send to Polly 
        self.polly.send_sign_tx(keys, out_addr_160, out_satoshi, change_keynum, change_satoshi) 

        print(self.__outok())
    
        #
        # Step 2: send previous txs to fund the inputs
        #
    
        print()

        cur = 0
        prevtx_info = []
    
        while cur < len(keynums_satoshi) :
    
            prevtx_outputs_satoshi = []
            
            # Calculate how many keynums will be associated with this prev tx
            end = min(cur + random.choice(prevtx_keynums), len(keynums_satoshi))
            
            # Create the prev tx output list
            for keynum, satoshi in keynums_satoshi[cur:end] :
        
                # Inject a random number of outputs not associated with tx input keynums
                for _ in range(0, random.choice(prevtx_outputs)) :
                    prevtx_outputs_satoshi.append((random.randint(0, 0x7FFFFFFF),  
                                                    random.randint(0, 2099999997690000)))
    
                # Add the outputs funding the tx input keynums 
                prevtx_outputs_satoshi.append((keynum, satoshi))
    
                # Create output script
                addr   = chain0.subkey(keynum, as_private = True).bitcoin_address()
                script = standard_tx_out_script(addr)
    
                # Capture some info we'll use later to verify the signed tx
                prevtx_info.append((keynum, 
                                    satoshi,
                                    script,
                                    0,                                # This is the hash and will be replaced later
                                    len(prevtx_outputs_satoshi) - 1)) # Index of the valid output
                
            print("{:30}{}".format("Make prev tx for keys", " ".join(str(keynum) for (keynum, _, _, _, _) in prevtx_info[cur:])))
            
            # Create the prev tx
            prevtx = self.create_prev_tx(win                 = Wallet.from_master_secret(bytes(0)), # create a dummy wallet 
                                         in_keynum           = list(range(0, random.choice(prevtx_inputs))), 
                                         sources_per_input   = 1, 
                                         wout                = chain0, 
                                         out_keynum_satoshi  = prevtx_outputs_satoshi, 
                                         fees_satoshi        = random.randint(100, 1000))
            
            # We have built the prev tx, calculate its hash (and reverse the bytes) 
            prevtx_hash = encoding.double_sha256(prevtx)[::-1] 
    
            # Update the hashes now that we have a full prev tx
            for i, (keynum, satoshi, script, _, outidx) in enumerate(prevtx_info[cur:]) :
                prevtx_info[i + cur] = (keynum, satoshi, script, prevtx_hash, outidx)
                
            # Create the index table that matches a keynum index with an ouput index in this prev tx
            idx_table = [(keynum_idx + cur, outidx) for keynum_idx, (_, _, _, _, outidx) in enumerate(prevtx_info[cur:])] 
            
            print(self.PAD.format("Send prev tx "), end='')
            
            # ---> send to Polly
            self.polly.send_prev_tx(idx_table, prevtx)
    
            print(self.__outok())
    
            cur = end
        
        #
        # Step 3: generate a signed tx with the reference wallet and compare against Polly's
        #
    
        spendables = []
        wifs       = []
        
        # Make sure that the inputs add up correctly, and prep the input_sources for reference wallet signing
        for (keynum, satoshi, script, prevtx_hash, outidx) in prevtx_info:
            spendables.append(Spendable(satoshi, script, prevtx_hash, outidx))
            wifs.append(chain0.subkey(keynum, as_private = True).wif())
        
        change_addr = chain1.subkey(change_keynum).bitcoin_address()
        
        payables = [(out_addr, out_satoshi), (change_addr, change_satoshi)]
        
        print()
        print(self.PAD.format("Make reference signature"))
    
        signed_tx     = create_signed_tx(spendables, payables, wifs, fee_satoshi)
        signed_tx     = self.get_tx_bytes(signed_tx)
        
        print(self.PAD.format("Get signed tx"), end='', flush = True)
        
        # <--- get the signed tx from Polly
        polly_signed_tx = self.polly.send_get_signed_tx()

        #print(self.txstr(polly_signed_tx))
        #print(self.txstr(signed_tx))
        
        print(self.__outok())
        
        # Compare reference wallet signed tx with polly's 
        assert signed_tx == polly_signed_tx, "test_sign: signature mismatch\nExpected:\n" + self.hexstr(signed_tx) + "\n\nActual:\n" + self.hexstr(polly_signed_tx)


    def test_ref_bip32(self):
        """
        Performs a test of the reference wallet's BIP32 key generation capability.
        """
        
        # BIP32 test vectors, see https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Test_Vectors
        
        # Vector 1
        
        m = Wallet.from_master_secret(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
        
        assert m.wallet_key()                                     == "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
        assert m.wallet_key(as_private=True)                      == "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        assert m.bitcoin_address()                                == "15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma"
        assert m.wif()                                            == "L52XzL2cMkHxqxBXRyEpnPQZGUs3uKiL3R11XbAdHigRzDozKZeW"

        m0h = m.subkey(is_hardened=True)
        assert m0h.wallet_key()                                   == "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
        assert m0h.wallet_key(as_private=True)                    == "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"

        m0h1 = m0h.subkey(i=1)
        assert m0h1.wallet_key()                                  == "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
        assert m0h1.wallet_key(as_private=True)                   == "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"

        m0h1_1_2h = m0h1.subkey(i=2, is_hardened=True)
        assert m0h1_1_2h.wallet_key()                             == "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"
        assert m0h1_1_2h.wallet_key(as_private=True)              == "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"

        m0h1_1_2h_2 = m0h1_1_2h.subkey(i=2)
        assert m0h1_1_2h_2.wallet_key()                           == "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"
        assert m0h1_1_2h_2.wallet_key(as_private=True)            == "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334"

        m0h1_1_2h_2_1000000000 = m0h1_1_2h_2.subkey(i=1000000000)
        assert m0h1_1_2h_2_1000000000.wallet_key()                == "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
        assert m0h1_1_2h_2_1000000000.wallet_key(as_private=True) == "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"

        
        # Vector 2
        
        m = Wallet.from_master_secret(bytes.fromhex("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"))
        
        assert m.wallet_key()                                             == "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
        assert m.wallet_key(as_private=True)                              == "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"

        m0 = m.subkey()
        assert m0.wallet_key()                                            == "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
        assert m0.wallet_key(as_private=True)                             == "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"

        m0_2147483647p = m0.subkey(i=2147483647, is_hardened=True)
        assert m0_2147483647p.wallet_key()                                == "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a"
        assert m0_2147483647p.wallet_key(as_private=True)                 == "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9"

        m0_2147483647p_1 = m0_2147483647p.subkey(i=1)
        assert m0_2147483647p_1.wallet_key()                              == "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon"
        assert m0_2147483647p_1.wallet_key(as_private=True)               == "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef"

        m0_2147483647p_1_2147483646p = m0_2147483647p_1.subkey(i=2147483646, is_hardened=True)
        assert m0_2147483647p_1_2147483646p.wallet_key()                  == "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
        assert m0_2147483647p_1_2147483646p.wallet_key(as_private=True)   == "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc"

        m0_2147483647p_1_2147483646p_2 = m0_2147483647p_1_2147483646p.subkey(i=2)
        assert m0_2147483647p_1_2147483646p_2.wallet_key()                == "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"
        assert m0_2147483647p_1_2147483646p_2.wallet_key(as_private=True) == "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j"

    def test_rfc6979(self):
        """
        Performs a test of the reference wallet's RFC6979 signatures against test vectors.
        """
        
        # Test vectors for RFC 6979 ECDSA (secp256k1, SHA-256).
        # Thanks to the Haskoin developer for these fully formed vectors.
        
        # (private key hex, private key WIF, message, r || r as hex, sig as DER)
        test_vectors = [
        ( 0x0000000000000000000000000000000000000000000000000000000000000001,
          "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn",
          "Everything should be made as simple as possible, but not simpler.",
          "33a69cd2065432a30f3d1ce4eb0d59b8ab58c74f27c41a7fdb5696ad4e6108c96f807982866f785d3f6418d24163ddae117b7db4d5fdf0071de069fa54342262",
          "3044022033a69cd2065432a30f3d1ce4eb0d59b8ab58c74f27c41a7fdb5696ad4e6108c902206f807982866f785d3f6418d24163ddae117b7db4d5fdf0071de069fa54342262"
          ),
        ( 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140,
          "L5oLkpV3aqBjhki6LmvChTCV6odsp4SXM6FfU2Gppt5kFLaHLuZ9",
          "Equations are more important to me, because politics is for the present, but an equation is something for eternity.",
          "54c4a33c6423d689378f160a7ff8b61330444abb58fb470f96ea16d99d4a2fed07082304410efa6b2943111b6a4e0aaa7b7db55a07e9861d1fb3cb1f421044a5",
          "3044022054c4a33c6423d689378f160a7ff8b61330444abb58fb470f96ea16d99d4a2fed022007082304410efa6b2943111b6a4e0aaa7b7db55a07e9861d1fb3cb1f421044a5"
          ),
        ( 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140,
          "L5oLkpV3aqBjhki6LmvChTCV6odsp4SXM6FfU2Gppt5kFLaHLuZ9",
          "Not only is the Universe stranger than we think, it is stranger than we can think.",
          "ff466a9f1b7b273e2f4c3ffe032eb2e814121ed18ef84665d0f515360dab3dd06fc95f5132e5ecfdc8e5e6e616cc77151455d46ed48f5589b7db7771a332b283",
          "3045022100ff466a9f1b7b273e2f4c3ffe032eb2e814121ed18ef84665d0f515360dab3dd002206fc95f5132e5ecfdc8e5e6e616cc77151455d46ed48f5589b7db7771a332b283"
          ),
        ( 0x0000000000000000000000000000000000000000000000000000000000000001,
          "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn",
          "How wonderful that we have met with a paradox. Now we have some hope of making progress.",
          "c0dafec8251f1d5010289d210232220b03202cba34ec11fec58b3e93a85b91d375afdc06b7d6322a590955bf264e7aaa155847f614d80078a90292fe205064d3",
          "3045022100c0dafec8251f1d5010289d210232220b03202cba34ec11fec58b3e93a85b91d3022075afdc06b7d6322a590955bf264e7aaa155847f614d80078a90292fe205064d3"
          ),
        ( 0x69ec59eaa1f4f2e36b639716b7c30ca86d9a5375c7b38d8918bd9c0ebc80ba64,
          "KzmcSTRmg8Gtoq8jbBCwsrvgiTKRrewQXniAHHTf7hsten8MZmBB",
          "Computer science is no more about computers than astronomy is about telescopes.",
          "7186363571d65e084e7f02b0b77c3ec44fb1b257dee26274c38c928986fea45d0de0b38e06807e46bda1f1e293f4f6323e854c86d58abdd00c46c16441085df6",
          "304402207186363571d65e084e7f02b0b77c3ec44fb1b257dee26274c38c928986fea45d02200de0b38e06807e46bda1f1e293f4f6323e854c86d58abdd00c46c16441085df6"
          ),
        ( 0x00000000000000000000000000007246174ab1e92e9149c6e446fe194d072637,
          "KwDiBf89QgGbjEhKnhXJwe1E2mCa8asowBrSKuCaBV6EsPYEAFZ8",
          "...if you aren't, at any given time, scandalized by code you wrote five or even three years ago, you're not learning anywhere near enough",
          "fbfe5076a15860ba8ed00e75e9bd22e05d230f02a936b653eb55b61c99dda4870e68880ebb0050fe4312b1b1eb0899e1b82da89baa5b895f612619edf34cbd37",
          "3045022100fbfe5076a15860ba8ed00e75e9bd22e05d230f02a936b653eb55b61c99dda48702200e68880ebb0050fe4312b1b1eb0899e1b82da89baa5b895f612619edf34cbd37"
          ),
        ( 0x000000000000000000000000000000000000000000056916d0f9b31dc9b637f3,
          "KwDiBf89QgGbjEhKnhXJuH7LrciVrZiib5S9h4knkymNojPUVsWN",
          "The question of whether computers can think is like the question of whether submarines can swim.",
          "cde1302d83f8dd835d89aef803c74a119f561fbaef3eb9129e45f30de86abbf906ce643f5049ee1f27890467b77a6a8e11ec4661cc38cd8badf90115fbd03cef",
          "3045022100cde1302d83f8dd835d89aef803c74a119f561fbaef3eb9129e45f30de86abbf9022006ce643f5049ee1f27890467b77a6a8e11ec4661cc38cd8badf90115fbd03cef"
          )
        ]
        
        for (secret_exponent, _, message, _, expected_sig) in test_vectors:
    
            h = hashlib.sha256(message.encode('utf-8')).digest()
            val = intbytes.from_bytes(h)        
            
            # This will use deterministic values of k based on 'val'
            r, s = ecdsa.sign(secp256k1.generator_secp256k1, secret_exponent, val)
                
            # Ensure that 's' is even to prevent attacks - see https://bitcointalk.org/index.php?topic=285142.msg3295518#msg3295518
            if s > (secp256k1.generator_secp256k1.order() / 2):
                s = secp256k1.generator_secp256k1.order() - s
            
            sig = der.sigencode_der(r, s)
            
            assert sig == bytes.fromhex(expected_sig), "ECDSA signature using RFC 6979 failed\nExpected: " + expected_sig + "\nActual:   " + self.hexstr(sig)
            
            
    def test_txhash(self):
        """
        Performs a test of the reference wallet's tx hashing against a known blockchain tx.
        """
        
        # 's' and 'expected' are from: 
        # https://blockchain.info/rawtx/a8196acaf3938b988f9816ae3e9da1df5a04afff0b5b460e4c1dc4a08dd52109?format=hex
    
        s = ("0100000002bca066b9cfe1eb81e667f219a442acdc5c5e2e470610659a314"
             "74dfb5e29c552000000008c493046022100b2857170045d5e59112e0d5200"
             "4a8f65d18945e52d42c2eb12f7d3c2314600b802210098bdab40dfe38b5d4"
             "fe02e1fa3057ada3e0a982a5c7979eabff86395e2a911e8014104a8075344"
             "0c651f7191f46085411679545486f1dc6bf34cdaba453966c5fe7cc34f3dd"
             "c15ae321974f426807faa34b3fc10034e129222067ec053c409a6ac1f30ff"
             "ffffffe047c65f9e560d799580f6a965c12a059ca1e82cebc3e220659ba29"
             "ee31c8d0a010000008b48304502206b7eaa2dec17b53022b57a55b48ac245"
             "6f1c22d87b0170aa969de04146b80bbc022100d6700f6eb9bde89c35b0545"
             "588c06dcfed95e0502941d79786b5ea24eafc2cfe01410435d1d08c6f5296"
             "0d056e60c3b5c858e5299c1a688395b589dbde6b58861b20fdd7ee58832b3"
             "528845973765038cafc1c81280dc635ee202ce06aa4a373db012fffffffff"
             "0200f2052a010000001976a914315bfd9ee07d6779e44b8e07229650f039f"
             "0942788aced931600000000001976a91484004861f9a742fc83ad4ab83c42"
             "e709b512df1888ac00000000")
    
        expected = "a8196acaf3938b988f9816ae3e9da1df5a04afff0b5b460e4c1dc4a08dd52109"
        expected = bytes.fromhex(expected)
    
        actual = encoding.double_sha256(bytes.fromhex(s))
        
        # Reverse the bytes to flow lsb -> msb
        actual = actual[::-1]
        
        assert actual == expected, "tx hash calculation mismatch\n" + "Expected: " + self.hexstr(expected) + "\nActual:   " + self.hexstr(actual)
        
    #
    # Utilities
    #
        
    def create_prev_tx(self, win, in_keynum, sources_per_input, wout, out_keynum_satoshi, fees_satoshi):
        """
        Creates and returns a supporting 'previous' tx of 100KB or less
    
        win                 - wallet to use for input addresses
        in_keynum           - key nums from win
        sources_per_input   - how many sources are used to fund each input
        wout                - wallet to use for output addresses
        out_keynum_satoshi  - list of key nums from wout and satoshis to spend in tuples of (num, satoshis)
        
        Returns a bytes object containing the previous tx.
        """
    
        # Calculate the total output
        payables = []
        total_spent = 0
    
        for (out_key_id, out_satoshi) in out_keynum_satoshi:
    
            address = wout.subkey(out_key_id).bitcoin_address()
            payables.append((address, out_satoshi))
            
            total_spent += out_satoshi
    
        # Split the total to spend across all of the inputs
        spendables  = []
        total_value = 0
    
        satoshi_per_input = int(total_spent + fees_satoshi) / len(in_keynum)
    
        for keynum in in_keynum:
    
            # Grab the address for the current key num
            addr = win.subkey(keynum, as_private = True).bitcoin_address();
            
            # Generate fake sources for funding the input coin
            spendables.extend(self.fake_sources_for_address(addr, sources_per_input, satoshi_per_input))

            total_value += satoshi_per_input
       
        # Calculate the fee
        tx_fee = total_value - total_spent
        
        assert tx_fee >= 0, "fee < 0: " + str(tx_fee)
    
        # Create and 'sign' the transaction
        unsigned_tx = create_tx(spendables, payables, tx_fee)
        signed_tx   = self.__sign_fake(unsigned_tx)
    
        return self.get_tx_bytes(signed_tx)


    def fake_sources_for_address(self, addr, num_sources, total_satoshi):
        """
        Returns a fake list of funding sources for a bitcoin address.
        
        Note: total_satoshi will be split evenly by num_sources
        
        addr          - bitcoin address to fund
        num_sources   - number of sources to fund it with
        total_satoshi - total satoshis to fund 'addr' with 
    
        Returns a list of Spendable objects
        """
    
        spendables     = []
        satoshi_left   = total_satoshi
        satoshi_per_tx = satoshi_left / num_sources   
        satoshi_per_tx = int(satoshi_per_tx)
    
        # Create the output script for the input to fund 
        script = standard_tx_out_script(addr)
    
        while satoshi_left > 0:
            if satoshi_left < satoshi_per_tx:
                satoshi_per_tx = satoshi_left
            
            # Create a random hash value 
            rand_hash = bytes([random.randint(0, 0xFF) for _ in range(0, 32)])
    
            # Create a random output index
            # This field is 32 bits, but typically transactions dont have that many, limit to 0xFF
            rand_output_index = random.randint(0, 0xFF)
    
            # Append the new fake source 
            spend = Spendable(satoshi_per_tx, script, rand_hash, rand_output_index)
            
            spendables.append(spend)
            
            satoshi_left -= satoshi_per_tx
            
        assert satoshi_left == 0, "incorrect funding"
    
        return spendables


    def get_tx_bytes(self, tx):
        """
        Takes a Tx object and returns a bytes object containing the tx bytes.
        """
        
        s = io.BytesIO()
        tx.stream(s)
        return s.getvalue()


    def gen_wordlist(self, seed):
        """
        Generates a polly mnemonic wordlist from a seed, including the checksum.
        
        seed -  a string of 24 hex bytes (for a strength of 192 bits)
        
        Returns a space separated string of 18 words from the wordlist.
        """
        
        assert len(seed) == 24, "incorrect seed length, expecting 24 bytes"
        
        return self.mnemonic.to_mnemonic(seed)


    def hexstr(self, data):
        """
        Takes a bytes object and returns a packed hex string.
        """
        
        # Hexlify the bytes object and strip off the leading b' and trailing '
        return str(binascii.hexlify(data))[2:-1]
    

    def txstr(self, tx):
        """
        Takes a tx bytes object and prints out its details field by field.
        """
       
        def hexy(tag, data):
            print ("{0:<20s} : {1}".format(tag, self.hexstr(data)))
            
        print("\n[tx details]\n")

        s = 0
        
        hexy("version",     tx[s:s + 4])
        s += 4
        
        in_count = ord(tx[s:s + 1])
        hexy("in count", tx[s:s + 1])
        s += 1
        
        for _ in range(0, in_count) :
            
            print(" -------------------")
        
            hexy(" prev out hash", tx[s:s + 32])
            s += 32
            
            hexy(" prev out index", tx[s:s + 4])
            s += 4
            
            scriptlen = ord(tx[s:s + 1])
            hexy(" scriptlen", tx[s:s + 1])
            s += 1
        
            hexy(" script", tx[s:s + scriptlen])
            s += scriptlen
            
            hexy(" sequence", tx[s:s + 4])
            s += 4
            
        print()
        out_count = ord(tx[s:s + 1])
        hexy("out count", tx[s:s + 1])
        s += 1
        
        for _ in range(0, out_count) :
            
            print(" -------------------")
        
            hexy(" value", tx[s:s + 8])
            s += 8
            
            scriptlen = ord(tx[s:s + 1])
            hexy(" pk scriptlen", tx[s:s + 1])
            s += 1
        
            hexy(" pk script", tx[s:s + scriptlen])
            s += scriptlen
            
        print()
        hexy("lock time", tx[s:s + 4])
        s += 4
        
    #
    # Private
    #

    def __outok(self):
        """
        Creates a standard successful completion string for Polly operations
        """
        return "ok (" + self.polly.get_cmd_time() + ")"

    def __sign_fake(self, tx):
        """
        Sign a transaction using a fake randomly generated signature.
        """
        
        # Create a fake ecdsa signature from 0x68 - 0x6b bytes
        rand_script = bytes([random.randint(0,0xFF) for _ in range(0, random.randint(0x68, 0x6b))])

        tx.check_unspents()
        for idx, tx_in in enumerate(tx.txs_in):
            if tx.unspents[idx]:
                tx_in.script = rand_script
                
        return tx


def main():
    """
    Basic test scenarios.
    """
    
    # Seed the PRNG to get deterministic results
    random.seed(0)

    audit = PollyAudit()
    
    try:
        
        print()
        print("Internal coherency tests")
        print("------------------------")
        
        print("Testing tx hashing.")
        audit.test_txhash()
        
        print("Testing RFC6979 ECDSA signatures.")
        audit.test_rfc6979()
        
        print("Testing reference wallet (pycoin) BIP32 compliance.")
        audit.test_ref_bip32()

        # BIP 32 test vectors:
        print()
        print("Polly test vector 1")
        print("------------")
        
        audit.test_set_seed("skill versus increase replace april inherent fiction bundle minute oxygen promote sheriff weekend being welcome operator genre simple")
        audit.test_key(PollyCom.KEY_MASTER)
        audit.test_key(PollyCom.KEY_ACCOUNT, 0)
        audit.test_key(PollyCom.KEY_CHAIN,   0, 0)
        audit.test_key(PollyCom.KEY_CHAIN,   0, 1)
        
        audit.test_key(PollyCom.KEY_ADDRESS, 0, 0, 1)
        audit.test_key(PollyCom.KEY_ADDRESS, 0, 0, 1000)
        audit.test_key(PollyCom.KEY_ADDRESS, 0, 1, 300000)
        audit.test_key(PollyCom.KEY_ADDRESS, 0, 1, 12345678)
        
        audit.test_sign(keynums_satoshi  = [(1, 100000), 
                                            (2, 110000)],
                        out_addr         = "1Q6eZELkUUcbQ4Rn68Qm3AfDriBvuxz5Qr", 
                        out_satoshi      = 200000,
                        change_keynum    = 1, 
                        change_satoshi   = 5000,

                        prevtx_keynums   = [1],
                        prevtx_outputs   = [1],
                        prevtx_inputs    = [1]) 
        

        print()
        print("Polly test vector 2")
        print("------------")
        
        audit.test_set_seed(audit.gen_wordlist(os.urandom(24)))
        audit.test_key(PollyCom.KEY_MASTER)
        audit.test_key(PollyCom.KEY_ACCOUNT, 0)
        audit.test_key(PollyCom.KEY_CHAIN,   0, 0)
        audit.test_key(PollyCom.KEY_CHAIN,   0, 1)
        
        audit.test_key(PollyCom.KEY_ADDRESS, 0, 0, 23456789)
        audit.test_key(PollyCom.KEY_ADDRESS, 0, 0, 200000)
        audit.test_key(PollyCom.KEY_ADDRESS, 0, 1, 2000)
        audit.test_key(PollyCom.KEY_ADDRESS, 0, 1, 2)
        
        # Sign a tx with the max number supported by polly (32).
        # Total input value is 52800000 satoshis
        audit.test_sign(keynums_satoshi  = [(1111, 1000000), 
                                            (2222, 2000000),
                                            (3333, 3000000),
                                            (4444, 4000000),
                                            (5555, 5000000),
                                            (6666, 6000000),
                                            (7777, 7000000),
                                            (8888, 8000000),
                                            (9999, 9000000),
                                            (11010, 10000000),
                                            (11111, 11000000),
                                            (11212, 12000000),
                                            (11313, 13000000),
                                            (11414, 14000000),
                                            (11515, 15000000),
                                            (11616, 16000000),
                                            (11717, 17000000),
                                            (11818, 18000000),
                                            (11919, 19000000),
                                            (22020, 20000000),
                                            (22121, 21000000),
                                            (22222, 22000000),
                                            (22323, 23000000),
                                            (22424, 24000000),
                                            (22525, 25000000),
                                            (22626, 26000000),
                                            (22727, 27000000),
                                            (22828, 28000000),
                                            (22929, 29000000),
                                            (33030, 30000000),
                                            (33131, 31000000),
                                            (33232, 32000000)],
                        out_addr         = "1Q6eZELkUUcbQ4Rn68Qm3AfDriBvuxz5Qr", 
                        out_satoshi      = 520000000,
                        change_keynum    = 33232, 
                        change_satoshi   = 7000000,

                        prevtx_keynums   = [1,2,4],
                        prevtx_outputs   = [2,4,6],
                        prevtx_inputs    = [2]) 
        
        print()
        print("Polly signing stress test")
        print("------------")
        
        for seed in range(1000) :
            
                print ("\n--> Seed", seed)
                random.seed(seed)
            
                keynums_satoshi = []
                total_satoshi = 0
                
                # Create 1 - 32 input key numbers and corresponding unspent value
                for _ in range(random.randint(1, 33)) :
                    keynum = random.randint(1, 0x7FFFFFFF)
                    satoshi = random.randint(100000, 100000000000)
                    
                    keynums_satoshi.append((keynum, satoshi))
                    
                    total_satoshi += satoshi
                
                # Pick a random fraction of the total input value to spend
                out_satoshi = int(float(total_satoshi) * random.uniform(0.1, 1))
                
                # Pick a random fraction of the remaining to send as change, the rest will be fees
                change_satoshi = int(float(total_satoshi - out_satoshi) * random.uniform(0.5, 0.95))
                
                
                audit.test_sign(keynums_satoshi  = keynums_satoshi, 
                                out_addr         = "1Q6eZELkUUcbQ4Rn68Qm3AfDriBvuxz5Qr", 
                                out_satoshi      = out_satoshi,
                                change_keynum    = random.randint(1, 0x7FFFFFFF), 
                                change_satoshi   = change_satoshi,

                                prevtx_keynums   = [1,1,1,2,3,6],
                                prevtx_outputs   = [1,1,1,2,3,6],
                                prevtx_inputs    = [1,1,1,2,3,6]) 
                    
            
        print("\nPASS: Tests completed successfully")
    
    except KeyboardInterrupt:
        print ("\n User exit")
        
if __name__ == '__main__':
    status = main()
    sys.exit(status)
