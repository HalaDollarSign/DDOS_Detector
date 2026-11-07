using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

// Detector settings
const int PORT = 8080;
const int MAX_REQUESTS = 10;
const int TIME_WINDOW_SEC = 5;
const int BAN_DURATION_SEC = 30;

Dictionary<string, Queue<DateTime>> requestLog = new();
Dictionary<string, DateTime> blockedIps = new();

TcpListener listener = new TcpListener(IPAddress.Any, PORT);
listener.Start();

Console.WriteLine("=== NETWORK ANOMALY DETECTOR (DDoS/Flood) ===");
Console.WriteLine($"[*] Listening on port: {PORT}");
Console.WriteLine($"[*] Alert threshold: {MAX_REQUESTS} requests per {TIME_WINDOW_SEC}s window");
Console.WriteLine($"[*] Ban duration: {BAN_DURATION_SEC} seconds");
Console.WriteLine($"[!] PRESS 'B' AT ANY TIME TO VIEW THE ACTIVE BLACKLIST\n");

_ = Task.Run(() =>
{
    while (true)
    {
        if (Console.ReadKey(intercept: true).Key == ConsoleKey.B)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n=== ACTIVE BLACKLIST ===");
            if (blockedIps.Count == 0)
            {
                Console.WriteLine("[-] Blacklist is currently empty.");
            }
            else
            {
                DateTime now = DateTime.Now;
                foreach (var entry in blockedIps)
                {
                    double timeLeft = (entry.Value - now).TotalSeconds;
                    if (timeLeft > 0)
                    {
                        Console.WriteLine($"[!] IP: {entry.Key} | Ban expires in: {timeLeft:F1}s");
                    }
                }
            }
            Console.WriteLine("========================\n");
            Console.ResetColor();
        }
    }
});




while (true)
{
    TcpClient client = await listener.AcceptTcpClientAsync();
    string clientIp = ((IPEndPoint)client.Client.RemoteEndPoint).Address.ToString();
    DateTime now = DateTime.Now;

    if (blockedIps.ContainsKey(clientIp))
    {
        if (now < blockedIps[clientIp])
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"[-] Blocked connection dropped from {clientIp}. Ban expires in {(blockedIps[clientIp] - now).TotalSeconds:F0}s.");
            Console.ResetColor();

            client.Close();
            continue;
        }
        else
        {
            blockedIps.Remove(clientIp);
            requestLog[clientIp].Clear();

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"[*] Ban lifted for {clientIp}. Resuming normal monitoring.");
            Console.ResetColor();
        }
    }

    if (!requestLog.ContainsKey(clientIp))
    {
        requestLog[clientIp] = new Queue<DateTime>();
    }

    Queue<DateTime> timestamps = requestLog[clientIp];
    timestamps.Enqueue(now);

    while (timestamps.Count > 0 && (now - timestamps.Peek()).TotalSeconds > TIME_WINDOW_SEC)
    {
        timestamps.Dequeue();
    }

    if (timestamps.Count > MAX_REQUESTS)
    {
        blockedIps[clientIp] = now.AddSeconds(BAN_DURATION_SEC);

        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"[!!!] THRESHOLD EXCEEDED: IP {clientIp} is now BANNED for {BAN_DURATION_SEC} seconds!");
        Console.ResetColor();
    }
    else
    {
        Console.WriteLine($"[+] Connection from {clientIp} (Current traffic: {timestamps.Count} requests)");
    }

    client.Close();
}