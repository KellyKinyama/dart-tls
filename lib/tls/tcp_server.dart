import 'dart:io';

import 'handshaker/aes_gcm_128_sha_256.dart';

void main() async {
  final host = '127.0.0.1'; // Localhost
  final port = 4040; // Port for the server to listen on

  try {
    // Start the TCP server
    final server = await ServerSocket.bind(host, port);
    print('Listening on $host:$port');
    HandshakeManager handshakeManager = HandshakeManager(server);
    // Handle incoming connections
    await for (var client in server) {
      print(
          'New client connected: ${client.remoteAddress.address}:${client.remotePort}');

      // Handle communication with the client
      client.listen(
        (data) {
          // Print the data received from the client
          print('Received from client...}');

          handshakeManager.processDtlsMessage(data);

          // Send a response back to the client
          client.write('Hello, client!\n');
        },
        onDone: () {
          print('Client disconnected');
          client.close();
        },
        onError: (error) {
          print('Error: $error');
        },
      );
    }
  } catch (e) {
    print('Error starting server: $e');
  }
}
