# Example client.
net = require 'net'
readline = require 'readline'

sead = require './sead'

time = #A tiny time abstraction.
    difference: 0
    set: (now) -> @difference = now - Math.floor(Date.now() / 1000)
    get: () -> @difference + Math.floor(Date.now() / 1000)

router = new sead.Router(time)

console.log 'Id: ', router.id
router.on 'data', (data) ->
    console.log 'New Message: ', data.toString()

router.on 'broadcast', (id, data, forward) ->
    console.log 'New broadcast', id, ':', data.toString()
    forward()

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
        else if line[0] is 'broadcast' and line[1] isnt '' and line[2] isnt ''
            msg = line.slice(2).join ' '
            router.broadcast line[1], msg

        rl.prompt true

    rl.prompt true
