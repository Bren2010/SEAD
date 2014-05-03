# Customized CoffeeScript implementation of SEAD.
crypto = require 'crypto'
config = require 'config'
{EventEmitter} = require 'events'
caesar = require 'caesar'
schnorr = require './schnorr'

exports.prime = '/SxBVGXvC3DMj7x4F1HlLz9cwyCrUWxvr5C8jMbS/WGI7FHrccsHsBbsGgu+rDmkEMuIP/Py31rljvxipc7NYw=='

class exports.Router extends EventEmitter
    constructor: ->
        @dh = crypto.createDiffieHellman exports.prime, 'base64'
        @dh.generateKeys()
        
        # Our public id is the public component of our keypair.
        @id = @dh.getPublicKey 'hex'
        
        @conns = {}
        @table = {}
        @cache = {}
        
        @configure()
        
        # Every 5 seconds, distribute our routing table.
        setInterval @network, config.sead.period, @conns, @table
    
    configure: ->
        sq = if @table[@id]? then @table[@id].sq + 1 else 0
        
        if sq % config.sead.n is 0
            # Create a signing object for later.
            signer = new caesar.kts.Signer 1
            @oldSecret = @secret
            @secret = signer.getPrivateKey()[1]
            
            # Generate n random hash chains.
            anchors = []
            
            until anchors.length is config.sead.n
                val = @secret + ':' + anchors.length
                anchors.push caesar.hash.chain val, config.sead.m + 1, 'sha1'
            
            # Add the signer's public key as the last object.
            anchors.push signer.getPublicKey()
            
            # Sign the commitment cheaply.
            if @oldSecret?
                signer = new caesar.kts.Signer 1, @oldSecret
                msg = Math.floor(sq / config.sead.n).toString() + commit
                sig = signer.sign msg
                
                proof = @committer.getProof(config.sead.n - 1)
                
                ver = [sig, proof]
            else ver = null
            
            # Commit to all of it with a Merkle tree.
            @committer = new caesar.tree.Committer anchors, 'sha1'
            commit = @committer.getCommit()
            proof = @committer.getProof 0
            
            # Sign the commitment expensively.
            sig = new schnorr.Sign 'sha1'
            sig.write Math.floor(sq / config.sead.n).toString()
            sig.end commit
            sig = sig.sign @dh, 'hex'
            
            # Create our entry.
            first = caesar.hash.chain @secret + ':0', 1, 'sha1'
            
            @table[@id] =
                metric: 0 # Metric number.
                next: null # Next peer in route.
                sq: sq # Sequence number.
                element: first # Current element of hash chain.
                proof: proof # Merkle tree proof that this chain is valid.
                verification: ver # Cheap verification of the root.
                signature: sig # Expensive verification of the root.
        else
            val = @secret + ':' + (sq % config.sead.n)
            first = caesar.hash.chain val, 1, 'sha1'
            
            @table[@id].sq = sq
            @table[@id].proof = @committer.getProof(sq % config.sead.n)
            @table[@id].element = first
    
    # Feeds the router a new connection.
    #
    # @param Stream  conn  The Read/Write stream to feed to the router.
    feed: (conn, fn) ->
        close = (conn, fn) ->
            conn.end()
            if fn? then fn false
        
        tid = setTimeout close, 5000, conn, fn
        conn.on 'data', (data) =>
            data = JSON.parse data.toString()
            if data.type is 'id' and data.id?
                key = @dh.computeSecret data.id, 'hex'
                
                clearTimeout tid
                id = data.id
                @conns[id] = conn
                @conns[id].key = key
                
                
                @configure()
                
                conn.removeAllListeners 'data'
                @conns[id].on 'data', (data) =>
                    data = data.toString()
                    candidateHmac = data.substr -44
                    data = data.substr 0, data.length - 44
                    
                    hmac = crypto.createHmac 'sha256', @conns[id].key
                    hmac.end data
                    hmac = hmac.read().toString 'base64'
                    
                    if candidateHmac isnt hmac then return
                    data = JSON.parse data.toString()
                    
                    if data.type is 'data' and data.to is @id
                        @emit 'data', data.cargo
                    else if data.type is 'data' and data.to isnt @id
                        @write data.to, data.cargo
                    else if data.type is 'update'
                        @update id, data.updates
                
                @conns[id].on 'close', =>
                    # Make sure metric is null.
                    @table[id].metric = Infinity
                    
                    delete @conns[id]
                    #delete @table[id]
                
                if fn? then fn true
        
        conn.on 'error', -> # Do nothing.
        
        data = type: 'id', id: @id
        conn.write JSON.stringify data
    
    write: (addr, data, fn) ->
        if @table[addr]? and @table[addr].metric isnt Infinity
            packet = JSON.stringify type: 'data', to: addr, cargo: data
            
            # Create an HMAC on the shared key, and MAC the packet with it.
            # Provides neighbor authentication.
            hmac = crypto.createHmac 'sha256', @conns[@table[addr].next].key
            hmac.end packet
            hmac = hmac.read().toString 'base64'
            
            @conns[@table[addr].next].write packet + hmac
            if fn? then fn true
        else if fn? then fn false
    
    update: (sender, cands) ->
        better = (cand, curr) ->
            # If candidate's sq is less than current, always ignore.
            # If equal, accept if metric is lower.
            # If higher, always accept.
            res = curr? and cand.sq is curr.sq and cand.metric + 1 < curr.metric
            res = res and curr.metric isnt Infinity
            res = res or not curr? or cand.sq > curr.sq
            
            res
        
        for id, entry of cands when better entry, @table[id]
            # Generate candidate entry.  Increase metric and hash chain by 1.
            cand =
                metric: entry.metric + 1
                next: sender
                sq: entry.sq
                element: entry.element
                proof: entry.proof
                verification: entry.verification
                signature: entry.signature
            
            cand.element = caesar.hash.chain cand.element, 1, 'sha1'
            
            # Verify types of values.
            
            x = config.sead.m - cand.metric
            if x < 0 then continue
            
            anchor = caesar.hash.chain cand.element, x, 'sha1'
            root = caesar.tree.forward anchor, cand.proof, 'sha1'
            
            # Verify cand.proof is of correct number.
            
            if @table[id]? # Have knowledge of this user.
                oldItr = Math.floor(@table[id].sq / config.sead.n)
                newItr = Math.floor(cand.sq / config.sead.n)
                
                if newItr is (oldItr + 1)
                    ver = new caesar.kts.Verifier()
                    
                    msg = newItr + root
                    [pub, temp] = ver.forward msg, cand.verification[0]
                    old = caesar.tree.forward pub, cand.verification[1], 'sha1'
                    
                    if old isnt @cache[id] then continue
                else if newItr is oldItr and root isnt @cache[id] then continue
                else continue
            else # Have no knowledge of this user.
                # Verify the root.
                dh = crypto.createDiffieHellman exports.prime, 'base64'
                dh.setPublicKey id, 'hex'
                
                ver = new schnorr.Verify 'sha1'
                ver.write Math.floor(cand.sq / config.sead.n).toString()
                ver.end root
                ver = ver.verify dh, cand.signature, 'hex'
                if not ver then continue
            
            @table[id] = cand
            @cache[id] = root
    
    network: (conns, table) ->
        # Push a copy of the routing table to all neighbors.
        for id, conn of conns
            packet = JSON.stringify type: 'update', updates: table
            
            hmac = crypto.createHmac 'sha256', conn.key
            hmac.end packet
            hmac = hmac.read().toString 'base64'
            
            conn.write packet + hmac

