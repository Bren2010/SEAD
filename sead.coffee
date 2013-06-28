# Customized CoffeeScript implementation of SEAD.
crypto = require 'crypto'
{EventEmitter} = require 'events'
schnorr = require './schnorr'

exports.prime = '/SxBVGXvC3DMj7x4F1HlLz9cwyCrUWxvr5C8jMbS/WGI7FHrccsHsBbsGgu+rDmkEMuIP/Py31rljvxipc7NYw=='
hash = (val, n) ->
    i = 0
    while i < n
        h = crypto.createHash 'sha256'
        h.end val
        val = h.read().toString 'hex'
        ++i
    
    val

class exports.Router extends EventEmitter
    constructor: ->
        @dh = crypto.createDiffieHellman exports.prime, 'base64'
        @dh.generateKeys()
        
        # Our public id is the public component of our keypair.
        @id = @dh.getPublicKey 'hex'
        
        @conns = {}
        @table = {}
        
        @configure()
        
        # Every 5 seconds, distribute our routing table.
        setInterval @network, 5000, @conns, @table
    
    configure: ->
        sq = if @table[@id]? then @table[@id].sq + 1 else 0
        
        # Generate a random string as h0, and calculate h100.
        r = crypto.randomBytes(32).toString 'hex'
        c = hash r, 100
        
        # Sign the sequence number and h100.
        sig = new schnorr.Sign 'sha256'
        sig.write sq.toString()
        sig.end c
        sig = sig.sign @dh, 'hex'
        
        # Create our entry.
        @table[@id] =
            metric: 0
            next: null
            sq: sq
            auth: r
            chain: c
            signature: sig
    
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
                auth: entry.auth
                chain: entry.chain
                signature: entry.signature
            
            cand.auth = hash cand.auth, 1
            
            # Verify the signature on the chain cap.
            dh = crypto.createDiffieHellman exports.prime, 'base64'
            dh.setPublicKey id, 'hex'
            
            ver = new schnorr.Verify 'sha256'
            ver.write cand.sq.toString()
            ver.end cand.chain
            ver = ver.verify dh, cand.signature, 'hex'
            if not ver then continue
            
            # Verify the authentication element.
            if cand.metric >= 100 then continue
            cap = hash cand.auth, 100 - cand.metric
            if cap isnt cand.chain then continue
            
            # Accept entry.
            @table[id] = cand
    
    network: (conns, table) ->
        # Push a copy of the routing table to all neighbors.
        for id, conn of conns
            packet = JSON.stringify type: 'update', updates: table
            
            hmac = crypto.createHmac 'sha256', conn.key
            hmac.end packet
            hmac = hmac.read().toString 'base64'
            
            conn.write packet + hmac

