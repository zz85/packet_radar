class DownAndDragAction {
    constructor(dom, cb) {
        this.cb = cb;
        this.down = false;
        this.dom = dom;

        this.to_release = {
            mousedown: dom.addEventListener('mousedown', this.mousedown.bind(this)),
            mousemove: dom.addEventListener('mousemove', this.mousemove.bind(this)),
            mouseup: dom.addEventListener('mouseup', this.mouseup.bind(this))
        };
    }

    mousedown(e) {
        this.down = true;
        console.log(e.x, e.y);
        this.cb(e.x, e.y);
    }

    mousemove(e) {
        if (!this.down) return;
        console.log(e.x, e.y);
        this.cb(e.x, e.y);
    }

    mouseup(e) {
        this.down = false;
        console.log(e.x, e.y);
        this.cb(e.x, e.y);
    }

    release() {
        for (var k in this.to_release) {
            this.dom.removeEventListener(k, this.to_release[k]);
        }

        this.to_release = null;
        this.dom = null;
        this.cb = null;
    }
}


class OnUpAction {
    constructor(dom, cb) {
        this.cb = cb;
        this.down = false;
        this.dom = dom;

        this.to_release = {
            mouseup: dom.addEventListener('mouseup', this.mouseup.bind(this))
        };
    }

    mouseup(e) {
        this.cb(e.x, e.y);
    }

    release() {
        for (var k in this.to_release) {
            this.dom.removeEventListener(k, this.to_release[k]);
        }

        this.to_release = null;
        this.dom = null;
        this.cb = null;
    }
}

class OnDownAction {
    constructor(dom, cb) {
        this.cb = cb;
        this.down = false;
        this.dom = dom;

        this.to_release = {
            mouseup: dom.addEventListener('mousedown', this.mousedown.bind(this))
        };
    }

    mousedown(e) {
        this.cb(e.x, e.y);
    }

    release() {
        for (var k in this.to_release) {
            this.dom.removeEventListener(k, this.to_release[k]);
        }

        this.to_release = null;
        this.dom = null;
        this.cb = null;
    }
}