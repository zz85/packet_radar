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

class qNode {
    constructor(x, y, label) {
        this.set(x, y);

        this.dx = 0;
        this.dy = 0;

        // display attr
        this.r = 40;
        this.label = label || '';
        this.color = '';
    }

    set(x, y) {
        this.x = x;
        this.y = y;
        this.px = x; // previous x
        this.py = y; // previous y
    }

    // shoots packet
    isSending(target, size) {
        var packet = new qNode(this.x + rand(this.r  * 4), this.y + rand(this.r * 4));
        size = size || 100;
        packet.r = Math.sqrt(size) * 0.6 + 2;
        // sizing 5, 10, 15, 20
        // packet.r = 5 * Math.max(Math.log(size) / Math.log(10), 0.5);
        // packet.r = 5 + size / 1500 * 10;
        packet.target = target;
        packet.life = 0 + Math.random() * 50 | 0;
        if (!this.fires) this.fires = [];
        this.fires.push(packet);

        return packet;
    }

    // physics update
    update(delta) {
        if (this.fires) {
            this.fires.forEach(n => {
                var dx = n.target.x - n.x;
                var dy = n.target.y - n.y;
                /*
                var amp = Math.sqrt(dx * dx + dy * dy);
                if (amp === 0) amp = 0.001;

                n.x += dx / amp * 40;
                n.y += dy / amp * 40;
                */

                // // use easing function
                // n.x += dx * 0.15;
                // n.y += dy * 0.15;

                /// take max life = 200
                var k = (n.life / 200);
                k = 1 - k;
                k = 1 - k * k * k;

                n.x += dx * k;
                n.y += dy * k;

                n.life++;

                // animate size?
                // if (n.r > 1) n.r -= 4 * delta;

                // when it reaches target, or simply remove when it's ttl has died.
                if (Math.abs(dx) / 2 < 4 && Math.abs(dy) / 2 < 4
                    || n.life > 1000
                ) {
                    this.fires.splice(this.fires.indexOf(n));
                }
            })
        }

        this.x += this.dx * delta;
        this.y += this.dy * delta;

        var DAMP = 0.4;
        // damping
        this.dx *= (1 - DAMP * delta);
        this.dy *= (1 - DAMP * delta);
        if (Math.abs(this.dx) < 0.001) this.dx = 0;
        if (Math.abs(this.dy) < 0.001) this.dy = 0;
    }

    react(delta, node, spread, force, maxSpread) {
        // push apart
        force = force || 1000;
        const dx = node.x - this.x;
        const dy = node.y - this.y;
        const d2 = dx * dx + dy * dy;
        if (d2 === 0) return;

        const minSpread = spread || 150;
        const minSpread2 = minSpread * minSpread;
        maxSpread = 10000;
        const maxSpread2 = maxSpread * maxSpread;

        if (d2 > minSpread2) return;

        const d = Math.pow(d2, 0.5);
        // if (d == 0) d = 0.000001;
        var f = force / d2;

        // if (f > 100) f = 100;

        this.dx -= dx / d * f * delta * 100;
        this.dy -= dy / d * f * delta * 100;

    }

    attract(delta, node) {
        const dx = node.x - this.x;
        const dy = node.y - this.y;

        let d2 = dx * dx + dy * dy;
        if (d2 === 0) return;

        const target = 1000;
        // if (d2 < target * target) return;
        if (d2 < 100) d2 = 10000;

        const d = Math.pow(d2, 0.5);

        // TODO check attraction equation
        var pull = target / d2 * 100; // mass

        // pull together
        this.dx += dx / d * pull * delta;
        this.dy += dy / d * pull * delta;

        // var m = dx / d * pull * delta;
        // if (Math.abs(m) > 1) console.log(m);

    }

    render(ctx) {
        ctx.globalCompositeOperation = 'lighter'
        ctx.save();
        ctx.beginPath();
        ctx.arc(this.x, this.y, this.r, 0, Math.PI * 2);

        if (this.color) {
            ctx.fillStyle = this.color;
            ctx.fill();
        } else {
            ctx.strokeStyle = '#fff'
            ctx.stroke();
        }

        if (this.fires) {
            this.fires.forEach(f => f.render(ctx));
        }

        var label = this.label;
        if (label) {
            // hack, this should be done in a better way
            if (is_local(label)) label = '*** ' + label + ' ***'
            label = lookup(label) || label
            ctx.fillText(label, this.x, this.y + this.r + 12);
        }

        // debug vectors
        ctx.beginPath();
        ctx.strokeStyle = '#f00'
        ctx.beginPath();
        ctx.moveTo(this.x, this.y);
        // if (Math.random() < 0.1) console.log(this.y, this.dy);
        ctx.lineTo(this.x + this.dx * 10, this.y + this.dy * 10);
        ctx.stroke();
        ctx.restore();
    }
}

class qCanvas {
    constructor() {
        const canvas = document.createElement('canvas');
        const dpr = devicePixelRatio;
        const w = innerWidth;
        const h = innerHeight;
        canvas.width = w * dpr;
        canvas.height = h * dpr;
        canvas.style.width = w;
        canvas.style.height = h;

        const ctx = canvas.getContext('2d');
        this.dom = canvas;
        this.ctx = ctx;
        this.w = w;
        this.h = h;
        ctx.strokeStyle = '#fff';
        ctx.fillStyle = '#fff';

        ctx.scale(dpr, dpr);

        this.nodes = [];

        // track last viewport
        this.viewx = 0;
        this.viewy = 0;
        this.zoom = 1;
    }

    add(node) {
        this.nodes.push(node);
    }

    remove(node) {
        this.nodes.splice(this.nodes.indexOf(node), 1);
    }

    simulate(delta) {
        const nodes = this.nodes;

        var nodeA, nodeB;

        // fake gravity to bring stuff together
        nodeB = { x: 0, y: 0 }
        for (var i = 0; i < nodes.length; i++) {
            nodeA = nodes[i];
            nodeA.react(delta, nodeB, 5000, -10000);
        }

        // keep things slightly apart
        for (var i = 0; i < nodes.length; i++) {
            nodeA = nodes[i];
            for (var j = i + 1; j < nodes.length; j++) {
                nodeB = nodes[j];
                nodeA.react(delta, nodeB, 80, 4000);
                nodeB.react(delta, nodeA, 80, 4000);
            }
        }

        // charge between links
        for (let key of manager.links.all_links.keys()) {
            const [a, b] = key.split('_');
            nodeA = manager.getHost(a);
            nodeB = manager.getHost(b);
            if (nodeA && nodeB) {
                nodeA.react(delta, nodeB, 200, 400);
                nodeB.react(delta, nodeA, 200, 400);

                nodeA.react(delta, nodeB, 500, -800);
                nodeB.react(delta, nodeA, 500, -800);

                // nodeA.attract(delta, nodeB);
                // nodeB.attract(delta, nodeA);
            }
        }

        canvas.nodes.forEach(node => node.update(delta));
    }

    render() {
        const { ctx, w, h, nodes } = this;
        ctx.save();
        // ctx.clearRect(0, 0, w, h);
        // ctx.fillStyle = '#000';
        ctx.clearRect(0, 0, w, h);
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';

        //  point the view port to the center for now
        var ax = 0;
        var ay = 0;
        var packets = 0;

        nodes.forEach(node => {
            ax += node.x;
            ay += node.y;
            if (node.fires) packets += node.fires.length;
        });
        ax /= nodes.length;
        ay /= nodes.length;

        this.viewx += (ax - this.viewx) * 0.65;
        this.viewy += (ay - this.viewy) * 0.65;

        // ctx.translate(w / 2 - this.viewx, h / 2 - this.viewy);
        // ctx.translate(w / 2 - ax, h / 2 - ay);

        ctx.translate(w / 2, h / 2);

        ctx.scale(this.zoom, this.zoom);

        nodes.forEach(node => node.render(ctx))

        // debug center point
        ctx.beginPath();
        ctx.fillStyle = '#0f0'
        ctx.arc(0, 0, 2, 0, Math.PI * 2);
        ctx.fill();

        ctx.restore();
        // debug labels
        ctx.fillText(`Nodes: ${nodes.length}\n
        Packets in flight: ${packets}
        `, w - w/5, h - h/5);

    }
}

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


function rand(n) {
    // returns -0.5,0.5
    return (Math.random() - 0.5) * n;
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
    canvas.simulate(diff);

    // render
    canvas.render();
}, 60);