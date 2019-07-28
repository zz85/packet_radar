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

// connects to rust websockets server
// and emits events
function connect_packet_server(handler) {
    ws = new WebSocket("ws://localhost:3012")
    ws.onmessage = (m) => {
        try {
            var data = JSON.parse(m.data);
            handler(data);
            buffer.put(data);
        } catch (e) {
            console.log('error', m);
        }
    }
    ws.onopen = () => console.log('connected');
    ws.onclosed = () => console.log('disconnected');
}
