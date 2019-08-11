/**
 * Part of my network/packet visualization experiments
 * 1. packet fight
 * 2. bandwidth usage / packet count over time
 * 3. handshake timeline
 *
 * Packet Fight visualize the exchange of packets
 * across multiple nodes
 *
 * The size of each packet is visualized as the size
 * of the balls moving from one host to another
 *
 * Scaling of time may be required to allow human
 * perception of the movement of packets. A buffer
 * of events can be stored to allow replay and
 * time travel
 *
 * Components
 * - event log processor
 * - model post processing (eg. host vs packets)
 * - graphical object modelling
 * - the physics simulation
 * - the rendering (canvas)
 */
/**
 * Improvements
 * - give an initial velocity on packet firing
 * - [x] identify own host
 * - more random-ness?
 * - alter size based on recent activity?
 * - click interactivity
 * - panning controls
 * - refactor layout management
 */


class EventManager {
    constructor() {
        this.hosts = new Map();
        this.links = new Links()
        setInterval(() => {
            this.cleanup()
        }, 1000);

        this._inside_count = 0;
        this._outside_count = 0;
    }

    cleanup() {
        // when links get clean up
        this.links.cleanup(15 * 1000);
        const hosts = this.links.unique()

        // keep track of nodes ttl, remove nodes when idle activity is detected
        canvas.nodes.forEach(node => {
            if (!hosts.has(node.label)) {
                // console.log('remove ', node.label);
                this.removeHost(node);
            }
        })
    }

    process(event) {
        // packet from a, b
        var packet = this.packet(event.src, event.dest, event.len);
        // packet.color = is_local(event.src) ? 'blue' : 'red'
        packet.color = event.t === 't' ? 'green' : 'orange';
    }

    packet(src, dst, size) {
        var a = this.getHost(src);
        var b = this.getHost(dst);

        if (!a) {
            a = this.createHost(src, b);
        }

        if (!b) {
            b = this.createHost(dst, a);
        }

        // this.links.update(src, dst, size);
        // update links
        var key = Links.key(src, dst);
        var link = this.links.findOrCreateLink(key);
        link.update(size);

        // TODO if a and b are too close, defer animation
        // setTimeout(() => a.isSending(b, size), 100);
        return a.isSending(b, size)
    }

    getHost(host) {
        return this.hosts.get(host);
    }

    createHost(host, target) {
        var tx = rand(200);
        var ty = rand(200);
        if (target) {
            tx += target.x;
            ty += target.y;
        }
        var node = new qNode(tx, ty);
        node.label = host;

        // pin

        /*
        // separate left <> right, with y randomness
        if (is_local(host)) {
            node.x = -200
            node.y = rand(500);
        } else {
            node.x = 200
            node.y = rand(500);
        }
        */

        /*
        // separate left <> right, with increased y
        if (is_local(host)) {
            node.x = -200
            node.y = this._inside_count++ * 100
        } else {
            node.x = 200
            node.y = this._outside_count++ * 100
        }
        */

        if (is_local(host)) {
            node.set(0, this._inside_count++ * 100);
        } else {
            var angle = this._outside_count++ / 10 * Math.PI * 2;
            node.set(Math.cos(angle) * 300, node.y = Math.sin(angle) * 300);
        }

        canvas.add(node);
        this.hosts.set(host, node);
        return node;
    }

    removeHost(host) {
        this.hosts.delete(host.label);
        canvas.remove(host);
    }
}




// Init
canvas = new qCanvas();
manager = new EventManager();

document.body.appendChild(canvas.dom);

var last_step = Date.now();
setInterval(()  => {
    var now = Date.now();
    var diff = (now - last_step) / 1000;
    last_step = now;
    // simulate
    // canvas.simulate(diff);

    canvas.nodes.forEach(n => n.update())

    // render
    canvas.render();
}, 60);