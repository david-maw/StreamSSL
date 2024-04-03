using System;
using System.Collections;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.IO;

namespace SimpleClientCs;

public class SslTcpClient
{
    // The following method is invoked by the RemoteCertificateValidationDelegate.
    public static bool ValidateServerCertificate(
          object sender,
          X509Certificate certificate,
          X509Chain chain,
          SslPolicyErrors sslPolicyErrors)
    {
        if (sslPolicyErrors == SslPolicyErrors.None)
            return true;

        Console.WriteLine("Certificate error: {0}", sslPolicyErrors);

        // Do not allow this client to communicate with unauthenticated servers.
        return false;
    }
    public static int Main(string[] args)
    {
        const string serverName = "www.google.com";
        // Create a TCP/IP client socket.
        // machineName is the host running the server application.
        TcpClient tcpClient = new TcpClient(serverName, 443);
        Console.WriteLine("Client connected.");
        // Create an SSL stream that will close the client's stream.
        SslStream sslStream = new SslStream(
            tcpClient.GetStream(),
            false,
            new RemoteCertificateValidationCallback(ValidateServerCertificate),
            null
            );
        // The server name must match the name on the server certificate.
        try
        {
            sslStream.AuthenticateAsClient(serverName);
        }
        catch (AuthenticationException e)
        {
            Console.WriteLine("Exception: {0}", e.Message);
            if (e.InnerException != null)
            {
                Console.WriteLine("Inner exception: {0}", e.InnerException.Message);
            }
            Console.WriteLine("Authentication failed - closing the connection.");
            tcpClient.Close();
        }
        Console.WriteLine("Connected.");
        // Encode a test message into a byte array.
        // Signal the end of the message using the "<EOF>".
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
        Console.WriteLine("Client closed.");
        Console.ReadKey(); // wait
        return 0;
    }
}