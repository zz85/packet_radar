// connects to rust websockets server
// and emits events
function connect_packet_server(handler) {
    ws = new WebSocket("ws://localhost:3012")
    ws.onmessage = (m) => {
        try {
            var data = JSON.parse(m.data);
            handler(data);
        } catch (e) {
            console.log('error', m);
        }
    }
    ws.onopen = () => console.log('connected');
    ws.onclosed = () => console.log('disconnected');
}

