exports.sead = {
    period: 5000, // Send periodic updates every 5 seconds.
    m: 15, // Maximum network diameter.
    n: 15, // Number of sequence numbers to prepare for.  (= 2^n - 1)
    pbkdf: { // PBKDF settings for keys between peers.
        salt: 'yOJFVshLUL',
        count: 1000
    },
    timeouts: { // ttl = (interval * n) + (m * period) + grace
        interval: 60000, // On what interval to push up sequence number manually.
        grace: 30000, // Grace to give a node to push a new routing entry.
        cleanup: 10000 // On what interval to clean the routing table.
    },
}
