using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

class Server
{
    public static void Main()
    {

        string ip = "127.0.0.1";
        int port = 80;
        var server = new TcpListener(IPAddress.Parse(ip), port);

        string swkaSha1Base64 = "";
        byte[] response = new byte[1];
        server.Start();
        Console.WriteLine("Server has started on {0}:{1}, Waiting for a connection...", ip, port);


        TcpClient client = server.AcceptTcpClient();
        Console.WriteLine("A client connected.");

        NetworkStream stream = client.GetStream();

        while (true)
        {
            while (!stream.DataAvailable) ;
            while (client.Available < 3) ; // match against "get"

            byte[] bytes = new byte[client.Available];
            stream.Read(bytes, 0, client.Available);
            string s = Encoding.UTF8.GetString(bytes);

            if (Regex.IsMatch(s, "^GET", RegexOptions.IgnoreCase))
            {

                Console.WriteLine("=====Handshaking from client=====\n{0}", s);
                string swk = Regex.Match(s, "Sec-WebSocket-Key: (.*)").Groups[1].Value.Trim();
                string swka = swk + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
                byte[] swkaSha1 = System.Security.Cryptography.SHA1.Create().ComputeHash(Encoding.UTF8.GetBytes(swka));
                swkaSha1Base64 = Convert.ToBase64String(swkaSha1);

                // HTTP/1.1 defines the sequence CR LF as the end-of-line marker
                response = Encoding.UTF8.GetBytes(
                    "HTTP/1.1 101 Switching Protocols\r\n" +
                    "Connection: Upgrade\r\n" +
                    "Upgrade: websocket\r\n" +
                    "Sec-WebSocket-Accept: " + swkaSha1Base64 + "\r\n\r\n");

                string x = Encoding.UTF8.GetString(response);
                Console.WriteLine(x);

                stream.Write(response, 0, response.Length);
                SendMessage(stream, "test");
            }
        }
    }
    public static void SendMessage(NetworkStream stream, string inputText)
    {
        byte[] sendBytes = Encoding.UTF8.GetBytes(inputText);
        byte lengthHeader = 0;
        byte[] lengthCount = new byte[] { };

        if (sendBytes.Length <= 125)
            lengthHeader = (byte)sendBytes.Length;

        if (125 < sendBytes.Length && sendBytes.Length < 65535) //System.UInt16
        {
            lengthHeader = 126;

            lengthCount = new byte[] {
            (byte)(sendBytes.Length >> 8),
            (byte)(sendBytes.Length)
        };
        }

        if (sendBytes.Length > 65535)//max 2_147_483_647 but .Length -> System.Int32
        {
            lengthHeader = 127;
            lengthCount = new byte[] {
            (byte)(sendBytes.Length >> 56),
            (byte)(sendBytes.Length >> 48),
            (byte)(sendBytes.Length >> 40),
            (byte)(sendBytes.Length >> 32),
            (byte)(sendBytes.Length >> 24),
            (byte)(sendBytes.Length >> 16),
            (byte)(sendBytes.Length >> 8),
            (byte)sendBytes.Length,
        };
        }

        List<byte> responseArray = new List<byte>() { 0b10000001 };

        responseArray.Add(lengthHeader);
        responseArray.AddRange(lengthCount);
        responseArray.AddRange(sendBytes);

        stream.Write(responseArray.ToArray(), 0, responseArray.Count);
    }
}
