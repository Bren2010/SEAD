# Example client.
net = require 'net'
readline = require 'readline'

sead = require './sead'
router = new sead.Router(Math.floor(Date.now() / 1000))
console.log 'Id: ', router.id
router.on 'data', (data) ->
    console.log 'New Message: ', data.toString()

server = net.createServer (conn) -> router.feed conn
server.listen ->
    console.log 'Listening on port ' + server.address().port
    rl = readline.createInterface input: process.stdin, output: process.stdout
    rl.on 'line', (line) ->
        line = line.trim().split ' '
        
        if line[0] is 'connect' and line[1] isnt ''
            [host, port] = line[1].split ':'
            conn = net.connect port, host, -> router.feed conn
            conn.on 'error', (err) -> console.log err
        else if line[0] is 'peers'
            for id, entry of router.table
                console.log id
                console.log '    metric: ', entry.metric
                console.log '    sq: ', entry.sq
        else if line[0] is 'send' and line[1] isnt '' and line[2] isnt ''
            msg = line.splice(2).join ' '
            router.write line[1], msg, (ok) ->
                if not ok then console.log 'Failed!'
        
        rl.prompt true
    
    rl.prompt true
