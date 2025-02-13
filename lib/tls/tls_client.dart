import 'dart:io';

void main() async {
  final host = '127.0.0.1'; // Change this to your website
  final port = 4040; // HTTPS default port

  try {
    // Connect to the website using SecureSocket (SSL/TLS)
    final socket = await SecureSocket.connect(host, port);

    // Send a simple HTTP GET request to the server
    final request =
        'GET / HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n';
    socket.write(request);

    // Listen for the server's response
    await for (var data in socket) {
      print(String.fromCharCodes(data));
    }

    // Close the socket when done
    await socket.close();
  } catch (e) {
    print('Error: $e');
  }
}
