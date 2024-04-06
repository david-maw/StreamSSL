using System.Collections;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Diagnostics;

namespace StreamClientCs;

public class SslTcpClient
{
    private static Hashtable certificateErrors = new Hashtable();

    // The following method is invoked by the RemoteCertificateValidationDelegate.
    public static bool ValidateServerCertificate(
          object sender,
          X509Certificate certificate,
          X509Chain chain,
          SslPolicyErrors sslPolicyErrors)
    {
        if (sslPolicyErrors == SslPolicyErrors.None)
        {
            Console.WriteLine("Server certificate returned with no errors, {0}", certificate.Subject);
            return true;
        }
        else
        {
            Console.WriteLine("Certificate error: {0}", sslPolicyErrors);
            // Do not allow this client to communicate with unauthenticated servers.
            return false;
        }
    }
    public static X509Certificate SelectLocalCertificate(
        object sender,
        string targetHost,
        X509CertificateCollection localCertificates,
        X509Certificate remoteCertificate,
        string[] acceptableIssuers)
    {
        X509Certificate cert = null;
        Console.WriteLine("SelectLocalCertificate called to select a local certificate, remoteCertificate {0}", (remoteCertificate == null) ? "<null>" : remoteCertificate.Subject);
        if (acceptableIssuers?.Length > 0 && localCertificates?.Count > 0)
        {
            // Use the first certificate that is from an acceptable issuer.
            foreach (X509Certificate certificate in localCertificates)
            {
                string issuer = certificate.Issuer;
                if (Array.IndexOf(acceptableIssuers, issuer) != -1)
                {
                    cert = certificate;
                    break;
                }
            }
        }
        else if (localCertificates?.Count > 0)
            cert = localCertificates[0];

        if (remoteCertificate != null) // second call for a local cert 
        {
            string userName = System.Security.Principal.WindowsIdentity.GetCurrent().Name;

            Console.WriteLine("SelectLocalCertificate could not locate a certificate easily, so try and pick one with a reasonable subject name");
            string simpleName = System.Security.Principal.WindowsIdentity.GetCurrent().Name.Split('\\').Last(); ;
            X509Store myX509Store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            myX509Store.Open(OpenFlags.ReadWrite);
            cert = myX509Store.Certificates.OfType<X509Certificate2>().FirstOrDefault(localCert =>
                localCert.HasPrivateKey &&
                localCert.GetNameInfo(X509NameType.SimpleName, false) == simpleName);
        }
        Console.WriteLine("SelectLocalCertificate is returning cert {0}", (cert == null) ? "<null>" : cert.Subject);
        return cert;
    }
    public static int RunClient(string serverName, string serverCertificateName)
    {
        // Create a TCP/IP client socket.
        // machineName is the host running the server application.
        TcpClient tcpClient = new TcpClient(serverName, 41000);
        NetworkStream tcpStream = tcpClient.GetStream();
        Console.WriteLine("Client connected.");
        // Create an SSL stream that will close the client's stream.
        SslStream sslStream = new SslStream(
            tcpStream,
            false,
            new RemoteCertificateValidationCallback(ValidateServerCertificate),
            new LocalCertificateSelectionCallback(SelectLocalCertificate)
            );
        // The server name must match the name on the server certificate.
        try
        {
            sslStream.AuthenticateAsClient(serverCertificateName);
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
            return 1;
        }
        Console.WriteLine("Connected to {0}", serverName);

        string sentMsg = "Hello from client";
        Console.WriteLine("Sending greeting '{0}'", sentMsg);
        sslStream.Write(Encoding.ASCII.GetBytes(sentMsg));
        sslStream.Flush();

        sentMsg = "Hello again from client";
        Console.WriteLine("Sending second greeting '{0}'", sentMsg);
        sslStream.Write(Encoding.ASCII.GetBytes(sentMsg));
        sslStream.Flush();

        Console.WriteLine("Listening for message from server");
        byte[] readBuffer = new byte[200];
        int readBytes = sslStream.Read(readBuffer);
        string serverMessage = Encoding.ASCII.GetString(readBuffer, 0, readBytes);
        Console.WriteLine("Received'{0}'", serverMessage);

        Console.WriteLine("Listening for message from server");
        readBytes = sslStream.Read(readBuffer);
        serverMessage = Encoding.ASCII.GetString(readBuffer, 0, readBytes);
        Console.WriteLine("Received'{0}'", serverMessage);

        // Shut down SSL without closing the client TCP connection.
        Console.WriteLine("Shutting down SSL");
        Thread.Sleep(1000); // Give the shutdown message a chance to arrive at the server separately
        sslStream.ShutdownAsync().Wait();
        
        sentMsg = "First block of unencrypted data from client";
        Console.WriteLine("Sending first unencrypted data message '{0}'", sentMsg);
        tcpStream.Write(Encoding.ASCII.GetBytes(sentMsg));
        tcpStream.Flush();
        Console.WriteLine("Sleeping before sending second unencrypted data message");
        Thread.Sleep(1000); // Give the previous message time to arrive at the server, for the server socket to receive it and hand to the caller
        Thread.Sleep(4000); // Allow the next server-side receive to time out
        
        sentMsg = "Second block of unencrypted data from client";
        Console.WriteLine("Sending second unencrypted data message '{0}'", sentMsg);
        tcpStream.Write(Encoding.ASCII.GetBytes(sentMsg));
        tcpStream.Flush();
        
        Console.WriteLine("Sleeping before sending termination to give the last message time to arrive");
        Thread.Sleep(3000); // Give the previous message time to arrive at the server and for the server socket to receive it and hand to the caller
        sslStream.Close(); // not strictly necessary, because garbage collection would eventually handle it
        return 0;
    }
    private static void DisplayUsage()
    {
        Console.WriteLine("To start the client specify:");
        Console.WriteLine("StreamClientCs [serverName]");
        Environment.Exit(1);
    }
    public static int Main(string[] args)
    {
        string serverCertificateName = null;
        string serverName = null;
        if (args.Length > 1)
            DisplayUsage();
        // User can specify the server name (DNS name of the server). the server name must match the name on the server's certificate.
        serverName = args.Length > 0 ? args[0] : "localhost";
        serverCertificateName = serverName;
        SslTcpClient.RunClient(serverName, serverCertificateName);

        Console.WriteLine("Press any key to pause, Q to exit immediately");
        Stopwatch sw = new Stopwatch();
        sw.Start();
        while ((!Console.KeyAvailable) && sw.ElapsedMilliseconds < 30_000)
            Task.Delay(250).Wait(); // Loop until input is entered.
        if (Console.KeyAvailable && Console.ReadKey().Key != ConsoleKey.Q)
        {
            Console.WriteLine("The program will pause until you press enter");
            Console.ReadKey();
        }
        return 0;
    }
}