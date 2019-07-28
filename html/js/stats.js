class CountManager {
    constructor() {
        this.labels = new Map();
    }

    add(id, label) {
        const counter = new Counter(label);
        this.labels.set(id, counter);
    }

    inc(name, value) {
        return this.get(name).inc(value);
    }

    reset(name) {
        return this.get(name).reset();
    }

    get(name) {
        return this.labels.get(name);
    }

    forEach(func) {
        this.labels.forEach(func);
    }
}

class Counter {
    constructor(label, units) {
        this.label = label || '';
        this.units = units;
        this.value = 0;
        this.count = 0;
    }

    inc(number) {
        number = number === undefined ? 1 : number;
        this.value += number;
        this.count++;
    }

    reset() {
        const value = this.value;
        this.value = 0;
        if (this.units) return this.units(value);
        return value;
    }

    resetCount() {
        const count = this.count;
        this.count = 0;
        if (this.units) return this.units(count);
        return count;
    }

    val() {
        return this.value;
    }

    n() {
        return this.count;
    }
}