class CircularBuffer {
    constructor(size, init) {
        size = size || 100;
        this.buffer = new Array(size);
        this.buffer.fill(init);
        this.size = size;
        this.pointer = 0;
    }

    put(item) {
        var p = this.pointer;
        this.buffer[p] = item;
        this.pointer = (p + 1) % this.size;
    }

    last10() {
        var p = this.pointer + this.size - 10;
        var items = []
        for (var i = 0; i < 10; i++) {
            items.push(this.buffer[(i + p) % this.size]);
        }

        return items;
    }

    forEach(func) {
        var size = this.size;
        for (var i = size + this.pointer; i > this.pointer; i--) {
            func(this.buffer[i % size]);
        }
    }
}

var buffer = new CircularBuffer();
var ips = new Map();
var local_ips = new Set();

var query_callbacks = new Map();
var topic_subscribers = new Map();

// connects to rust websockets server
// and emits events
function connect_packet_server(handler) {
    ws = new WebSocket("ws://localhost:3012")
    ws.onmessage = (m) => {
        try {
            var data = JSON.parse(m.data);

            var type = data.type;
            if (type) {
                notify(type, data);

                switch (type) {
                    case 'lookup_addr':
                        request_once_handler('lookup' + data.ip, data.hostname);
                        ips.set(data.ip, data.hostname);
                        break;
                    case 'local_addr':
                        local_ips.add(data.ip);
                        break;
                    case 'traceroute':
                        var cb_key = 'traceroute ' + data.destination;
                        notify_once(cb_key, data);
                        break;
                    case 'geoip':
                        notify_once('geoip' + data.ip, data);
                        break;
                    default:
                        console.log(data);
                }

                return;
            }

            const { src, dest, len, src_port, dest_port, t } = data;

            check_host(src);
            check_host(dest);

            if (t === 't' | t == 'u') {
                // ignore other types like ja4 for now
                handler(data);
            }
            buffer.put(data);
        } catch (e) {
            console.log('error', m, e);
        }
    }
    ws.onopen = () => {
        console.log('connected');
        query_host_ip();
        // TODO add open callback handler
    }
    ws.onclosed = () => console.log('disconnected');
}

// calls

function query(payload) {
    ws.send(JSON.stringify(payload));
}

function query_lookup(ip, cb) {
    request_once_handler('lookup' + ip, cb);
    query({req: 'lookup', value: ip, type: ''});
}

function query_host_ip() {
    query({req: 'local_addr', value: '', type: ''});
}

function query_geo_ip(ip, cb) {
    request_once_handler('geoip' + ip, cb);
    query({req: 'geoip', value: ip, type: ''});
}

/* pub sub system */
function subscribe(topic, handler) {
    if (!topic_subscribers.has(topic)) {
        topic_subscribers.set(topic, []);
    }

    topic_subscribers.get(topic).push(handler);
}

function unsubscribe(topic, handler) {
    var subscribers = topic_subscribers.get(topic);
    subscribers.splice(subscribers.indexOf(handler), 1);
}

function notify(topic, data) {
    var subs = topic_subscribers.get(topic);
    if (subs) {
        subs.forEach(s => s(data));
    }
}

/* single use req system, notify and unsub */
function notify_once(cb_key, data) {
    var cb = query_callbacks.get(cb_key);
    if (cb) {
        cb(data);
        query_callbacks.delete(cb_key);
    }
}

function request_once_handler(key, cb) {
    if (cb) {
        query_callbacks.set(key, cb);

        // TODO add timeout cleanup
    }
}

function query_traceroute(ip, cb) {
    request_once_handler('traceroute ' + ip, cb);
    query({req: 'traceroute', value: ip, type: ''})

}

function check_host(ip) {
    if (!ips.has(ip)) {
        ips.set(ip, null);

        query_lookup(ip);
    }
}

function is_local(ip) {
    return local_ips.has(ip);
}

function lookup(ip) {
    return ips.get(ip);
}