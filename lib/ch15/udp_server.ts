import dgram from "dgram";

const PORT = 41234; // Choose a port
const HOST = "0.0.0.0"; // Listen on all available network interfaces

const server = dgram.createSocket("udp4");

server.on("message", (msg, rinfo) => {
  console.log(`Received: ${msg} from ${rinfo.address}:${rinfo.port}`);

  // Send a response back to the client
  const response = Buffer.from("Message received");
  server.send(response, rinfo.port, rinfo.address, (err) => {
    if (err) {
      console.error("Error sending response:", err);
    } else {
      console.log("Response sent!");
    }
  });
});

server.on("listening", () => {
  const address = server.address();
  console.log(`UDP server listening on ${address.address}:${address.port}`);
});

server.on("error", (err) => {
  console.error(`Server error:\n${err.stack}`);
  server.close();
});

// Start the server
server.bind(PORT, HOST);