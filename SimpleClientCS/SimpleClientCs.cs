using System.Net.Security;
using System.Net.Sockets;
using System.Text;

// This is a simple example using .NET SslStream
// It connects to a web server, exchanges a couple of messages, then exits
// This corresponds to the SimpleClient C++ example.
const string serverName = "www.google.com";
// Create a TCP/IP client socket.
TcpClient tcpClient = new TcpClient(serverName, 443);
Console.WriteLine("Socket connected to server, initializing SSL.");
// Create an SSL stream that will close the client's stream.
SslStream sslStream = new SslStream(tcpClient.GetStream());
sslStream.AuthenticateAsClient(serverName);
Console.WriteLine("Connected to {0}, protocol: {1}", serverName, sslStream.SslProtocol);
// Encode a test message into a byte array.
byte[] message = Encoding.UTF8.GetBytes("GET HTTP/1.1\n");
// Send hello message to the server.
sslStream.Write(message);
sslStream.Flush();
// Read message from the server.
byte[] buffer = new byte[100];
int bytes = sslStream.Read(buffer, 0, buffer.Length);
string serverMessage = Encoding.UTF8.GetString(buffer, 0, bytes);
int newlineIndex = serverMessage.IndexOf('\n');
if (newlineIndex != -1)
    serverMessage = serverMessage.Remove(newlineIndex);
Console.WriteLine("Server says: {0}", serverMessage);
// Close the client connection.
tcpClient.Close();
Console.WriteLine("Client closed. Press Enter to finish");
Console.ReadKey(); // wait
return 0;