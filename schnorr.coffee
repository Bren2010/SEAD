# CoffeeScript implementation of the Schnorr Signature algorithm.
crypto = require 'crypto'
bigdecimal = require 'bigdecimal'

class exports.Sign
    # Mimic normal crypto.Sign interface.
    constructor: (@alg) -> @digest = crypto.createHash @alg
    write: (buff, enc, cb) -> @digest.write buff, enc, cb
    end: (buff, enc, cb) -> @write buff, enc, cb
    
    # Requires a crypto.DiffieHellman containing the signer's private key.
    # Optional:  Output format.  Can be binary, base64, or hex.
    sign: (dh, outputFormat) ->
        # Choose random r, and raise to g.
        dhK = crypto.createDiffieHellman dh.getPrime()
        dhK.generateKeys()
        
        # Calculate H(M || g^r)
        @digest.end dhK.getPublicKey()
        @digest = @digest.read()
        
        # Create buffer of appropriate length, and write digest to it.
        output = new Buffer @digest.length + dh.getPrime().length + 1
        output.writeUInt8 @digest.length, 0
        @digest.copy output, 1
        
        zero = new bigdecimal.BigInteger '0', 10
        one = new bigdecimal.BigInteger '1', 10
        
        # Calculate Phi(p) = p - 1
        p = new bigdecimal.BigInteger dh.getPrime('hex'), 16
        p = p.subtract one
        
        # Calculate s = r - ae (mod Phi(p))
        r = new bigdecimal.BigInteger dhK.getPrivateKey('hex'), 16
        
        eN = new bigdecimal.BigInteger @digest.toString('hex'), 16
        eN = eN.remainder p
        
        s = new bigdecimal.BigInteger dh.getPrivateKey('hex'), 16
        s = s.remainder p
        s = s.multiply eN
        s = r.subtract s
        s = s.remainder p
        
        if s.compareTo(zero) is -1 then s = s.add p
        s = s.toString(16)
        if s.length % 2 is 1 then s = '0' + s
        
        output.write s, @digest.length + 1, 'hex'
        
        if outputFormat? then output.toString outputFormat else output

class exports.Verify
    # Mimic normal crypto.Verify interface.
    constructor: (@alg) -> @digest = crypto.createHash @alg
    write: (buff, enc, cb) -> @digest.write buff, enc, cb
    end: (buff, enc, cb) -> @write buff, enc, cb
    
    # Requires a crypto.DiffieHellman containing the signer's public key.
    # Requires the signature to be verified.
    # Optional:  Signature format.  Can be binary, base64, or hex.
    verify: (dh, sig, sigFormat) ->
        # Prepare and dissect signature.
        sig = new Buffer sig, sigFormat if sigFormat?
        
        n = sig.readUInt8 0
        e = sig.slice 1, n + 1
        s = sig.slice n + 1
        
        # Calculate g^s
        dh1 = crypto.createDiffieHellman dh.getPrime()
        dh1.setPrivateKey s
        dh1.generateKeys()
        left = dh1.getPublicKey 'hex'
        
        # Calculate (g^a)^e = g^(ae)
        dh2 = crypto.createDiffieHellman dh.getPrime()
        dh2.setPrivateKey e
        dh2.generateKeys()
        right = dh2.computeSecret dh.getPublicKey(), null, 'hex'
        
        # Calculate g^s * g^(ae) = g^r'
        p = new bigdecimal.BigInteger dh.getPrime('hex'), 16
        left = new bigdecimal.BigInteger left, 16
        right = new bigdecimal.BigInteger right, 16
        rv = left.multiply(right).remainder(p)
        
        # Calculate H(M' || g^r')
        @digest.end rv.toString(16), 'hex'
        @digest = @digest.read()
        
        # H(M || g^r) ?= H(M' || g^r')
        @digest.toString() is e.toString()
