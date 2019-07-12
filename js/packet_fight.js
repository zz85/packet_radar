/**
 * Part of my Quic visualization experiments
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
 * - identify own host
 * - more random-ness?
 * - alter size based on recent activity?
 */

class qNode {
    constructor(x, y, label) {
        this.x = x;
        this.y = y;
        this.dx = 0;
        this.dy = 0;

        // display attr
        this.r = 40;
        this.label = label || '';
    
    }

    // shoots packet
    isSending(target, size) {
        var packet = new qNode(this.x + rand(this.r), this.y + rand(this.r));
        size = size || 100;
        packet.r = Math.sqrt(size);
        packet.target = target;
        if (!this.fires) this.fires = [];
        this.fires.push(packet);
    }

    // physics update
    update() {
        if (this.fires) {
            this.fires.forEach(n => {
                var dx = n.target.x - n.x;
                var dy = n.target.y - n.y;
                var amp = Math.sqrt(dx * dx + dy * dy);
                if (amp === 0) amp = 0.001;

                n.x += dx / amp * 40;
                n.y += dy / amp * 40;

                if (Math.abs(dx) < n.target.r && Math.abs(dy) < n.target.r) {
                    console.log('removing');
                    this.fires.splice(this.fires.indexOf(n));
                }
            })
        }

        this.x += this.dx;
        this.y += this.dy;
        // damping
        this.dx *= 0.9;
        this.dy *= 0.9;
        if (this.dx < 0.001) this.dx = 0;
        if (this.dy < 0.001) this.dy = 0;
    }

    react(node) {
        const dx = node.x - this.x;
        const dy = node.y - this.y;
        const d = dx * dx + dy * dy;

        const minSpread = 200;
        const minSpread2 = minSpread * minSpread;
        if (d < minSpread2) {
            // push apart
            this.dx -= Math.sign(dx) * (minSpread2 - dx * dx) / minSpread2 * 10;
            this.dy -= Math.sign(dy) * (minSpread2 - dy * dy) / minSpread2 * 10;
        }
        else if (d > minSpread2 * 2) {
            // TODO attraction equation doesn't look right
            // also, attract to the CG, not individual lols.
            var pull = (d - minSpread2 * 3) / d * 1;

            // pull together
            this.dx += Math.sign(dx) * pull;
            this.dy += Math.sign(dy) * pull;
        }
    }

    render(ctx) {
        ctx.beginPath();
        ctx.arc(this.x, this.y, this.r, 0, Math.PI * 2);
        ctx.stroke();

        if (this.fires) {
            this.fires.forEach(f => f.render(ctx));
        }

        if (this.label) ctx.fillText(this.label, this.x, this.y);
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

        ctx.scale(dpr, dpr);

        this.nodes = [];
    }

    add(node) {
        this.nodes.push(node);
    }

    remove(node) {
        this.nodes.splice(this.nodes.indexOf(node), 1);
    }

    simulate() {
        const nodes = this.nodes;

        var nodeA, nodeB;
        for (var i = 0; i < nodes.length; i++) {
            nodeA = nodes[i];
            for (var j = i + 1; j < nodes.length; j++) {
                nodeB = nodes[j];
                nodeA.react(nodeB);
                nodeB.react(nodeA);
            }
        }

        canvas.nodes.forEach(node => node.update());
    }

    render() {
        const { ctx, w, h, nodes } = this;
        ctx.save();
        ctx.clearRect(0, 0, w, h);
        
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

        ctx.translate(w / 2 - ax, h / 2 - ay);

        nodes.forEach(node => node.render(ctx))

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
        setInterval(() => this.cleanup(), 1000);
    }

    cleanup() {
        // keep track of nodes ttl, remove nodes when idle activity is detected 
        const now = Date.now();
        canvas.nodes.forEach(node => {
            if (now - node.lastActivity > 10000) {
                this.removeHost(node.label);
            }
        })
    }

    process(event) {
        // packet from a, b
        this.packet(event.src, event.dest, event.length);
    }

    packet(src, dst, size) {
        var a = this.getHost(src);
        var b = this.getHost(dst);
        a.lastActivity = Date.now()
        b.lastActivity = Date.now()
        // TODO if a and b are too close, defer animation
        setTimeout(() => a.isSending(b, size), 100);
        
    }

    getHost(host) {
        if (this.hosts.has(host)) return this.hosts.get(host);

        var node = new qNode(rand(100), rand(100));
        node.label = host;

        canvas.add(node);
        this.hosts.set(host, node);
        return node;
    }

    removeHost(host) {
        this.hosts.delete(host);
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

node1 = new qNode(rand(100), rand(100))
node2 = new qNode(rand(100), rand(100))
node3 = new qNode(rand(100), rand(100))

// canvas.add(node1);
// canvas.add(node2);
// canvas.add(node3);

// for (var i = 0; i < 4; i++) {
//     canvas.add(new qNode(rand(100), rand(100)));
// }

document.body.appendChild(canvas.dom);

setInterval(()  => {
    // simulate
    canvas.simulate();

    // render
    canvas.render();
}, 60);