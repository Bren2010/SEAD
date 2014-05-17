# Customized CoffeeScript implementation of SEAD.
crypto = require 'crypto'
config = require 'config'
{EventEmitter} = require 'events'
caesar = require 'caesar'
sjcl = require './sjcl'

getProofNumber = (proof) ->
    num = ''
    num = (1 - line[0]) + num for line in proof
    num = parseInt num, 2
    
    num

class Packet
    constructor: (@boxed) ->
        @__defineGetter__ 'type', ->
            type = @boxed.readUInt8 0
            
            if type is 0 and @boxed.length is 49 then return 'id'
            if type is 1 and @boxed.length >= 49 then return 'data'
            if type is 2 and @boxed.length is 698 then return 'update'
            
            return 'bad'
        
        @__defineSetter__ 'type', (type) ->
            if type is 'id'
                @boxed = new Buffer 49
                @boxed.fill 0
            else if type is 'data'
                @boxed = new Buffer 49
                @boxed.fill 0
                
                @boxed.writeUInt8 1, 0
            else if type is 'update'
                @boxed = new Buffer 698
                @boxed.fill 0
                
                @boxed.writeUInt8 2, 0
            else return false
        
        # type: 'id', id: ...
        # type: 'update', id: id, cargo: ...
        @__defineGetter__ 'id', ->
            if @type is 'id' or @type is 'update'
                return @boxed.slice(1, 49).toString 'base64'
            else return null
        
        @__defineSetter__ 'id', (id) ->
            if @type is 'id' or @type is 'update'
                @boxed.write id, 1, 48, 'base64'
            else return null
        
        # type: 'data', to: addr, cargo: ...
        @__defineGetter__ 'to', ->
            if @type is 'data'
                return @boxed.slice(1, 49).toString 'base64'
            else return null
        
        @__defineSetter__ 'to', (to) ->
            if @type is 'data'
                @boxed.write to, 1, 48, 'base64'
            else return null
        
        @__defineGetter__ 'cargo', ->
            if @type is 'data' or @type is 'update'
                return @boxed.slice(49)
            else return null
        
        @__defineSetter__ 'cargo', (cargo) ->
            if @type is 'data' or @type is 'update'
                cargo = new Buffer cargo
                @boxed = Buffer.concat [@boxed.slice(0, 49), cargo]
            else return null

class Entry
    constructor: (entry) ->
        @boxed = new Buffer 649
        @boxed.fill 0
        
        @__defineGetter__ 'metric', ->
            m = @boxed.readUInt8 0
            return if m is 255 then Infinity else m
        
        @__defineSetter__ 'metric', (metric) ->
            if metric is Infinity then metric = 255
            @boxed.writeUInt8 metric, 0
        
        @__defineGetter__ 'next', -> @boxed.slice(1, 49).toString('base64')
        @__defineSetter__ 'next', (next) ->@boxed.write next, 1, 48, 'base64'
        
        @__defineGetter__ 'sq', -> @boxed.readUInt32BE(49)
        @__defineSetter__ 'sq', (sq) -> @boxed.writeUInt32BE sq, 49
        
        @__defineGetter__ 'element', -> @boxed.slice(53, 73).toString('hex')
        @__defineSetter__ 'element', (el) -> @boxed.write el, 53, 20, 'hex'
        
        @__defineGetter__ 'timestamp', -> @boxed.readUInt32BE 73
        @__defineSetter__ 'timestamp', (ts) -> @boxed.writeUInt32BE ts, 73
        
        @__defineGetter__ 'signature', ->
            @boxed.slice(77, 125).toString('base64')
        
        @__defineSetter__ 'signature', (signature) ->
            @boxed.write signature, 77, 48, 'base64'
        
        @__defineGetter__ 'proof', ->
            [c, i, proof] = [125, 0, []]
            j = Math.log(config.sead.n + 1) / Math.log(2)
            
            until i is j
                p = []
                p[0] = @boxed.readUInt8 c
                p[1] = @boxed.slice(c + 1, c + 21).toString('hex')
                
                proof.push p
                
                c += 21
                ++i
            
            proof
        
        @__defineSetter__ 'proof', (proof) ->
            c = 125
            for part in proof # A Merkle proof.
                @boxed.writeUInt8 part[0], c
                @boxed.write part[1], (c + 1), 20, 'hex'
                
                c += 21
        
        @__defineGetter__ 'verification', ->
            [c, i, verification] = [125, 0, [[], []]]
            j = Math.log(config.sead.n + 1) / Math.log(2)
            c += 21 * j
            
            until i is 22
                verification[0].push @boxed.slice(c, c + 20).toString('hex')
                
                c += 20
                ++i
            
            i = 0
            until i is j
                p = []
                p[0] = @boxed.readUInt8 c
                p[1] = @boxed.slice(c + 1, c + 21).toString('hex')
                
                verification[1].push p
                
                c += 21
                ++i
            
            verification
        
        @__defineSetter__ 'verification', (verification) ->
            c = 125
            j = Math.log(config.sead.n + 1) / Math.log(2)
            c += 21 * j
            
            for part in verification[0] # A KTS sig.
                @boxed.write part, c, 20, 'hex'
                c += 20
            
            for part in verification[1] # Another proof.
                @boxed.writeUInt8 part[0], c
                @boxed.write part[1], (c + 1), 20, 'hex'
                
                c += 21
        
        if not entry? then return
        
        @metric = entry.metric
        if entry.next? then @next = entry.next
        @sq = entry.sq
        @element = entry.element
        @signature = entry.signature
        @proof = entry.proof
        if entry.verification? then @verification = entry.verification
        @timestamp = entry.timestamp


class exports.Router extends EventEmitter
    constructor: (nowRemote) ->
        @deltaT = nowRemote - Math.floor(Date.now() / 1000)
        
        @ttl = config.sead.timeouts.interval * config.sead.n
        @ttl += config.sead.m * config.sead.period
        @ttl += config.sead.timeouts.grace
        @ttl = Math.floor(@ttl / 1000)
        
        c = sjcl.ecc.curves.c192
        @keys = elGamal: sjcl.ecc.elGamal.generateKeys(c)
        
        @keys.ecdsa =
            pub: @keys.elGamal.pub.get()
            sec: @keys.elGamal.sec.get()
        
        @keys.ecdsa.pub = new sjcl.ecc.ecdsa.publicKey(c, sjcl.codec.hex.toBits(
            sjcl.codec.hex.fromBits(@keys.ecdsa.pub.x) +
            sjcl.codec.hex.fromBits(@keys.ecdsa.pub.y)
        ))
        
        @keys.ecdsa.sec = new sjcl.ecc.ecdsa.secretKey(c, sjcl.bn.fromBits(
            @keys.ecdsa.sec
        ))
        
        # Our public id is the public component of our keypair.
        @id = sjcl.codec.hex.fromBits @keys.elGamal.pub.get().x
        @id += sjcl.codec.hex.fromBits @keys.elGamal.pub.get().y
        @id = sjcl.codec.base64.fromBits sjcl.codec.hex.toBits @id
        
        @conns = {}
        @table = {}
        @cache = {}
        
        # Every 5 seconds, distribute our routing table.
        setInterval @network, config.sead.period, @conns, @table
        
        # Push up sequence number every so often.
        run = => if @table[@id]? then @configure()
        setInterval run, config.sead.timeouts.interval
        
        # Clean up routing table.
        clean = =>
            curr = Math.floor(Date.now() / 1000) + @deltaT
            
            for id, entry of @table
                if (curr - entry.timestamp) > @ttl then delete @table[id]
        
        setInterval clean, config.sead.timeouts.cleanup
    
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
            
            # Commit to all of it with a Merkle tree.
            @oldCommitter = @committer
            @committer = new caesar.tree.Committer anchors, 'sha1'
            commit = @committer.getCommit()
            proof = @committer.getProof 0
            
            ts = Math.floor(Date.now() / 1000) + @deltaT
            tsStr = ts.toString()
            
            # Sign the commitment cheaply.
            if @oldSecret?
                signer = new caesar.kts.Signer 1, @oldSecret
                msg = Math.floor(sq / config.sead.n).toString() + commit + tsStr
                sig = signer.sign msg
                
                oldProof = @oldCommitter.getProof(config.sead.n)
                
                ver = [sig, oldProof]
            else ver = null
            
            # Sign the commitment expensively.
            sig = Math.floor(sq / config.sead.n).toString() + commit + tsStr
            sig = @keys.ecdsa.sec.sign sjcl.hash.sha256.hash sig
            sig = sjcl.codec.base64.fromBits sig
            
            # Create our entry.
            first = caesar.hash.chain @secret + ':0', 1, 'sha1'
            
            @table[@id] = new Entry({
                metric: 0 # Metric number.
                next: null # Next peer in route.
                sq: sq # Sequence number.
                element: first # Current element of hash chain.
                proof: proof # Merkle tree proof that this chain is valid.
                verification: ver # Cheap verification of the root.
                signature: sig # Expensive verification of the root.
                timestamp: ts # Timestamp of entry's creation.
            })
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
            data = new Packet data
            
            if data.type is 'id'
                try
                    c = sjcl.ecc.curves.c192
                    pubKey = new sjcl.ecc.elGamal.publicKey(c, 
                        sjcl.codec.base64.toBits(data.id)
                    )
                    
                    key = @keys.elGamal.sec.dh pubKey
                    key = sjcl.misc.pbkdf2(
                        key,
                        config.sead.pbkdf.salt,
                        config.sead.pbkdf.count,
                        256
                    )
                    
                    key = sjcl.codec.hex.fromBits key
                    
                    clearTimeout tid
                    id = data.id
                    @conns[id] = conn
                    @conns[id].key = key
                    
                    @configure()
                    
                    @conns[id]._expectedLen = 0
                    @conns[id]._store = new Buffer 0
                    
                    conn.removeAllListeners 'data'
                    @conns[id].on 'data', (data) =>
                        if @conns[id]._store.length isnt 0
                            tmp = [@conns[id]._store, data]
                            @conns[id]._store = Buffer.concat tmp
                            
                            if @conns[id]._store >= @conns[id]._expectedLen
                                data = @conns[id]._store
                                
                                if data.length > @conns[id]._expectedLen
                                    excess = data.slice @conns[id]._expectedLen
                                    data = data.slice 0, @conns[id]._expectedLen
                                    
                                    @conns[id].emit 'data', excess
                                
                                @conns[id]._expectedLen = 0
                                @conns[id]._store = new Buffer 0
                            else return
                        else
                            mlen = data.readUInt16BE 0
                            if mlen is 0 then return
                            
                            data = data.slice 2
                            
                            if data.length < mlen
                                @conns[id]._expectedLen = mlen
                                @conns[id]._store = data
                                
                                return
                            else if data.length > mlen
                                excess = data.slice mlen
                                data = data.slice 0, mlen
                                
                                @conns[id].emit 'data', excess
                        
                        candidateHmac = data.slice data.length - 32
                        candidateHmac = candidateHmac.toString 'base64'
                        
                        data = data.slice 0, data.length - 32
                        
                        hmac = crypto.createHmac 'sha256', @conns[id].key
                        hmac.end data
                        hmac = hmac.read().toString 'base64'
                        
                        if candidateHmac isnt hmac then return
                        data = new Packet data
                        
                        if data.type is 'data' and data.to is @id
                            @emit 'data', data.cargo
                        else if data.type is 'data' and data.to isnt @id
                            @write data.to, data.cargo
                        else if data.type is 'update'
                            @update id, data.id, data.cargo
                    
                    @conns[id].on 'close', =>
                        # Make sure metric is null.
                        @table[id]?.metric = Infinity
                        
                        delete @conns[id]
                        #delete @table[id]
                    
                    if fn? then fn null
                catch err then if fn? then fn err
        
        conn.on 'error', -> # Do nothing.
        
        packet = new Packet()
        packet.type = 'id'
        packet.id = @id
        
        conn.write packet.boxed
    
    write: (addr, data, fn) ->
        if @table[addr]? and @table[addr].metric isnt Infinity
            packet = new Packet()
            packet.type = 'data'
            packet.to = addr
            packet.cargo = data
            
            # Create an HMAC on the shared key, and MAC the packet with it.
            # Provides neighbor authentication.
            hmac = crypto.createHmac 'sha256', @conns[@table[addr].next].key
            hmac.end packet.boxed
            hmac = hmac.read()
            
            buff = new Buffer 2
            buff.writeUInt16BE packet.boxed.length + hmac.length, 0
            buff = Buffer.concat [buff, packet.boxed, hmac]
            
            @conns[@table[addr].next].write buff
            if fn? then fn true
        else if fn? then fn false
    
    update: (sender, id, cargo) ->
        if id is @id then return
        
        # Generate candidate entry.
        cand = new Entry()
        cand.boxed = cargo
        
        if @table[id]?
            now = Math.floor(Date.now() / 1000) + @deltaT
            if (now - cand.timestamp) > @ttl then return
            
            # If candidate's sq is less than current, always ignore.
            if cand.sq < @table[id].sq then return
            
            # If equal, accept if metric is lower, but not if metric is Inf.
            if cand.sq is @table[id].sq and @table[id].metric is Infinity
                return
            
            if cand.sq is @table[id].sq and (cand.metric+1) >= @table[id].metric
                return
        
        # If sequence number is higher, always accept.
        
        # Increase metric and hash chain by 1.
        cand.metric = cand.metric + 1
        cand.next = sender
        cand.element = caesar.hash.chain cand.element, 1, 'sha1'
        
        x = config.sead.m - cand.metric
        if x < 0 then return
        
        anchor = caesar.hash.chain cand.element, x, 'sha1'
        root = caesar.tree.forward anchor, cand.proof, 'sha1'
        
        # Verify cand.proof is of correct number.
        num = getProofNumber cand.proof
        if num isnt (cand.sq %  config.sead.n) then return
        
        try
            oldItr = Math.floor(@table[id]?.sq / config.sead.n)
            newItr = Math.floor(cand.sq / config.sead.n)
            
             # Have recent knowledge of this user.
            if @table[id]? and newItr is (oldItr + 1)
                if config.sead.n isnt getProofNumber cand.verification[1]
                    return
                
                ver = new caesar.kts.Verifier()
                
                msg = newItr + root + cand.timestamp.toString()
                [tmp, fin] = ver.forward msg, cand.verification[0]
                old = caesar.tree.forward fin, cand.verification[1], 'sha1'
                
                if old isnt @cache[id] then return
            else if @table[id]? and newItr is oldItr
                if root isnt @cache[id] then return
            else # Have no recent knowledge of this user.
                # Verify the root.
                c = sjcl.ecc.curves.c192
                pubKey = new sjcl.ecc.ecdsa.publicKey(c, 
                    sjcl.codec.base64.toBits(id)
                )
                
                h = Math.floor(cand.sq / config.sead.n).toString() + root
                h += cand.timestamp.toString()
                
                h = sjcl.hash.sha256.hash h
                sig = sjcl.codec.base64.toBits cand.signature
                
                ver = pubKey.verify h, sig
                if not ver then return
        catch err then return
        
        @table[id] = cand
        @cache[id] = root
        
        return
    
    network: (conns, table) ->
        # Push a copy of the routing table to all neighbors.
        for id, conn of conns
            for peerId, cargo of table
                packet = new Packet()
                packet.type = 'update'
                packet.id = peerId
                packet.cargo = cargo.boxed
                
                hmac = crypto.createHmac 'sha256', conn.key
                hmac.end packet.boxed
                hmac = hmac.read()
                
                buff = new Buffer 2
                buff.writeUInt16BE packet.boxed.length + hmac.length, 0
                buff = Buffer.concat [buff, packet.boxed, hmac]
                
                conn.write buff

