function simulate(dt) {
    // stability around rings
    const nodes = canvas.nodes;

    var cx = 0;
    var cy = 0;

    nodes.forEach(o => {
        cx += o.x;
        cy += o.y;
    });

    cx /= nodes.length;
    cy /= nodes.length;

    // Calculate CG with max

    // var cr = 0;

    // nodes.forEach(o => {
    //     var amp = Math.sqrt(o.x * o.x + o.y * o.y);
    //     cx += o.x * o.x / amp * o.r;
    //     cy += o.y * o.y / amp * o.r;
    //     cr += o.r;
    // });

    // cx /= nodes.length / (cr / nodes.length);
    // cy /= nodes.length / (cr / nodes.length);
    // // (3, 3) * 2, (1, 1) * 1 = 2, 2

    var GRAVITY_FORCE = 0.15 // 0.15

    // gravitate
    nodes.forEach(o => {
        var mx = (cx - o.x);
        var my = (cy - o.y);

        mx = mx * GRAVITY_FORCE * dt;
        my = my * GRAVITY_FORCE * dt;

        var max_amp = dt * 30;
        mx = Math.max(-max_amp, Math.min(max_amp, mx))
        my = Math.max(-max_amp, Math.min(max_amp, my))

        o.x += mx;
        o.y += my;

        // samp_log(dt);

        // var d2 = mx * mx + my * my;
        // var d = Math.sqrt(d2);
        // if (d == 0) return;
        // o.x += mx / d2 * 0.15;
        // o.y += my / d2 * 0.15;
    });

    // move apart
    nodes.forEach((o, i) => {
        var dx = 0;
        var dy = 0;
        nodes.forEach((p, j) => {
            // TODO subtract radius -  + p.r * 0.5 + o.r * 0.5+
            var lx = p.x - o.x
            var ly = p.y - o.y

            var d2 = lx * lx + ly * ly;
            var d = Math.sqrt(d2);

            if (lx == 0 ) return;
            if (ly == 0 ) return;

            var force = 1.5; // 0.5, 1.5
            // A
            // dx -= lx * force / d2;
            // dy -= ly * force / d2;

            // dx -= lx * 0.005 / d;
            // dy -= ly * 0.005 / d;

            dx -= lx * 0.01 / d;
            dy -= ly * 0.01 / d;

            // B
            // dx -= lx * 2.5 / d2;
            // dy -= ly * 2.5 / d2;

            // dx -= lx * 4.5 / d2;
            // dy -= ly * 4.5 / d2;
        })

        // A
        o.ax += dx;
        o.ay += dy;

        // B
        // o.x += dx;
        // o.y += dy;
    });

    // link constraints
    links.forEach((link, i) => {
        // take target link len to be 100
        var l = 300;
        var a = link.start;
        var b = link.end;

        // current distance apart
        var dx = b.x - a.x;
        var dy = b.y - a.y;
        var d2 = dx * dx + dy * dy;
        var d = Math.sqrt(d2);

        var nudge = d / l - 1;
        nudge = nudge * 0.5 * dt * d;
        // easing to len size in 1 second

        var mx = nudge * dx / d
        var my = nudge * dy / d
        a.x += mx
        a.y += my

        b.x -= mx
        b.y -= my
    })

    // Update positions
    var friction = 1 - 1.5 * dt; // approx 0.95
    // samp_log('friction', friction)

    nodes.forEach(o => {
        var dx = o.x - o.px;
        var dy = o.y - o.py;

        o.px = o.x;
        o.py = o.y;
        o.x += dx * friction + o.ax + dt * dt;
        o.y += dy * friction + o.ay + dt * dt;
        
        // o.life--;
        o.ax *= friction
        o.ay *= friction

        // if (o.life < 0) {
        //     canvas.remove(o);
        // }
    });
}