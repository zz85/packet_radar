class Links {
    constructor() {
        this.all_hosts = new Map();
        this.all_links = new Map();
    }

    static key(a, b) {
        if (a < b) return `${a}_${b}`;
        return `${b}_${a}`;
    }

    // return a link
    findOrCreateLink(key) {
        var link = this.all_links.get(key)
        if (link) return link;

        link = new LinkUsage(key);
        this.all_links.set(key, link);
        return link;
    }

    cleanup(threshold) {
        threshold = threshold || 5 * 1000;
        // remove "inactive" links based on last seen threshold
        var cutoff = Date.now() - threshold;
        for (var [key, item] of this.all_links) {
            if (item.last < cutoff) {
                this.all_links.delete(key);
            }
        }
        // TODO emit events when link is removed
    }

    unique() {
        var set = new Set();
        for (let item of this.all_links.values()) {
            const [a, b] = item.name.split('_')
            set.add(a);
            set.add(b);
        }
        return set;
    }
}

class LinkUsage {
    constructor(name) {
        this.name = name;
        this.in = new Counter();
        // this.out = new Counter();
    }

    update(bytes) {
        this.in.inc(bytes);
        this.last = Date.now();
    }

    calc() {
        this.rx_bytes = this.in.reset()
        this.rx_packets = this.in.resetCount()
    }
}
