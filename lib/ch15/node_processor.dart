import 'dart:io';

void main() async {
  var result = await Process.run('tsx', ['.\\lib\\ch15\\udp_server.ts']);
  print(result.stdout); // Output: Hello, World!
}
