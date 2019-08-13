
class qNode {
    constructor(x, y, label) {
        this.set(x, y);

        // this.dx = 0;
        // this.dy = 0;

        // display attr
        this.r = 40;
        
        this.label = label || '';
        
        // for d3
        this.ax = 0;
        this.ay = 0;

        this.life = 100000;

        this.color = '';
    }

    set(x, y) {
        this.x = x;
        this.y = y;
        this.px = x; // previous x
        this.py = y; // previous y
    }

    // shoots packet TODO move this out
    isSending(target, size) {
        var packet = new qNode(this.x + rand(this.r  * 4), this.y + rand(this.r * 4));
        size = size || 100;
        // packet.r = Math.sqrt(size) * 0.6 + 2;
        // sizing 5, 10, 15, 20
        packet.r = 5 * Math.max(Math.log(size) / Math.log(10), 0.5);
        // packet.r = 5 + size / 1500 * 10;
        packet.target = target;
        packet.life = 0 + Math.random() * 50 | 0;
        if (!this.fires) this.fires = [];
        this.fires.push(packet);

        return packet;
    }

    // physics update
    update(delta) {
        // bullet simulation
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
            ctx.strokeStyle = this.rim ? this.rim : '#fff'
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

function rand(n) {
    // returns -0.5,0.5
    return (Math.random() - 0.5) * n;
}

function samp_log(...args) {
    if (Math.random() < 0.01) console.log(...args);
}