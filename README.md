# Network Anomaly Detector & Rate Limiter (C#)

Advanced console-based defensive security tool written in C# designed to detect network anomalies, simulate basic DDoS/Flood attacks, and enforce automatic active mitigation (IP blacklisting). Built as part of a cybersecurity portfolio focusing on Blue Team and SOC (Security Operations Center) engineering principles.

## Features
- **Sliding Time Window Detection:** Monitors incoming TCP connections using a dynamic time window algorithm.
- **Active Mitigation (IP Blacklisting):** Automatically blocks IPs exceeding threshold limits for a specified duration.
- **Real-Time Blacklist Inspection:** Utilizes background multithreading (`Task.Run`) to allow system administrators to query the active blacklist interactively (`Press 'B'`) without blocking packet capturing.
- **Optimized Data Structures:** Efficient memory and time complexity management using standard collections.

## Architecture & Technical Highlights (Lessons Learned)
* **Data Structure Optimization:** Utilizes a `Dictionary<string, Queue<DateTime>>` to track connection timestamps per IP. The `Queue` (FIFO) enables efficient removal of stale log entries without the $O(N)$ shift overhead of standard lists.
* **Memory Protection (Garbage Collection):** Implements dynamic clean-up inside the connection loop to drop timestamps older than the configured time window, preventing Out-Of-Memory (OOM) errors during high-volume traffic bursts.
* **Performance-First Blacklisting:** Separates banned IPs into a dedicated dictionary (`blockedIps`). Incoming packets from blocked hosts are dropped instantly at the start of the loop via a lightweight `DateTime` check, bypassing heavier threshold evaluation logic.
* **Concurrency Management:** Asynchronous TCP listener (`AcceptTcpClientAsync`) paired with a dedicated background monitoring task ensures non-blocking operational flow.

## Requirements
- [.NET SDK](https://dotnet.microsoft.com/)

## How to Run
1. Clone the repository.
2. Open the project folder in your terminal.
3. Start the application:
   ```bash
   dotnet run

Press B at any time during execution to view the active blacklist status.

Disclaimer: This tool is created strictly for educational purposes, defensive architecture testing, and use in controlled laboratory environments.