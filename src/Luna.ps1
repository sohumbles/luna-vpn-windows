# Luna 1.5.2-release — Windows 10/11 proxy/VPN client
# Split routing for System Proxy and native Xray TUN modes.
[CmdletBinding()]
param()

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms, Microsoft.VisualBasic, System.Net.Http

Add-Type -TypeDefinition @'
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

public sealed class LunaTrafficTotals
{
    public long ReceivedBytes { get; set; }
    public long SentBytes { get; set; }
}

public static class LunaSystemTrafficMeter
{
    public static LunaTrafficTotals GetTotals()
    {
        long received = 0;
        long sent = 0;
        foreach (NetworkInterface adapter in
            NetworkInterface.GetAllNetworkInterfaces())
        {
            if (adapter.OperationalStatus != OperationalStatus.Up ||
                adapter.NetworkInterfaceType == NetworkInterfaceType.Loopback ||
                adapter.NetworkInterfaceType == NetworkInterfaceType.Tunnel)
                continue;

            try
            {
                IPv4InterfaceStatistics statistics =
                    adapter.GetIPv4Statistics();
                received += Math.Max(0L, statistics.BytesReceived);
                sent += Math.Max(0L, statistics.BytesSent);
            }
            catch
            {
            }
        }
        return new LunaTrafficTotals
        {
            ReceivedBytes = received,
            SentBytes = sent
        };
    }
}

public sealed class LunaAppTraffic
{
    public int ProcessId { get; set; }
    public string ProcessName { get; set; }
    public long ReceivedBytes { get; set; }
    public long SentBytes { get; set; }
    public long TotalBytes { get; set; }
    public long ActiveConnections { get; set; }
    public long TotalConnections { get; set; }
}

public sealed class RouteCheckTarget
{
    public string Id { get; private set; }
    public string Name { get; private set; }
    public Uri Endpoint { get; private set; }
    public string ExpectedMarker { get; private set; }
    public string ProbeKind { get; private set; }

    public RouteCheckTarget(
        string id,
        string name,
        string endpoint,
        string expectedMarker,
        string probeKind)
    {
        if (String.IsNullOrWhiteSpace(id))
            throw new ArgumentException("Target id is required.", "id");
        if (String.IsNullOrWhiteSpace(name))
            throw new ArgumentException("Target name is required.", "name");
        if (String.IsNullOrWhiteSpace(expectedMarker))
            throw new ArgumentException(
                "Expected response marker is required.",
                "expectedMarker");

        Uri uri;
        if (!Uri.TryCreate(endpoint, UriKind.Absolute, out uri) ||
            !String.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Only absolute HTTPS endpoints are supported.", "endpoint");

        Id = id;
        Name = name;
        Endpoint = uri;
        ExpectedMarker = expectedMarker;
        ProbeKind = String.IsNullOrWhiteSpace(probeKind)
            ? "http"
            : probeKind;
    }
}

public sealed class RouteCheckResult
{
    public RouteCheckTarget Target { get; set; }
    public bool IsAvailable { get; set; }
    public long LatencyMs { get; set; }
    public string Status { get; set; }
    public string ErrorReason { get; set; }
    public int HttpStatusCode { get; set; }
    public DateTimeOffset CheckedAt { get; set; }
    public long DnsMs { get; set; }
    public long TcpMs { get; set; }
    public long TunnelMs { get; set; }
    public long TlsMs { get; set; }
    public long TtfbMs { get; set; }
    public string TlsProtocol { get; set; }
    public bool ContentValidated { get; set; }
    public int ResponseBytesRead { get; set; }
}

public sealed class RouteQualityService
{
    private const int MaxResponseBytes = 32768;
    private readonly int timeoutMilliseconds;
    private readonly int maxConcurrency;

    private sealed class ProbeException : Exception
    {
        public string Phase { get; private set; }

        public ProbeException(string phase, string message)
            : base(message)
        {
            Phase = phase;
        }
    }

    private sealed class HttpProbeData
    {
        public int StatusCode;
        public long TtfbMs;
        public bool ContentValidated;
        public int BytesRead;
    }

    public RouteQualityService(int timeoutMilliseconds, int maxConcurrency)
    {
        if (timeoutMilliseconds < 1000)
            throw new ArgumentOutOfRangeException("timeoutMilliseconds");
        if (maxConcurrency < 1)
            throw new ArgumentOutOfRangeException("maxConcurrency");

        this.timeoutMilliseconds = timeoutMilliseconds;
        this.maxConcurrency = maxConcurrency;
    }

    public async Task<RouteCheckResult[]> CheckAsync(
        RouteCheckTarget[] targets,
        string proxyUrl,
        CancellationToken cancellationToken)
    {
        if (targets == null) throw new ArgumentNullException("targets");
        using (SemaphoreSlim limiter = new SemaphoreSlim(maxConcurrency))
        {
            Task<RouteCheckResult>[] tasks = targets
                .Select(target => CheckOneAsync(
                    limiter,
                    target,
                    proxyUrl,
                    cancellationToken))
                .ToArray();
            return await Task.WhenAll(tasks).ConfigureAwait(false);
        }
    }

    private async Task<RouteCheckResult> CheckOneAsync(
        SemaphoreSlim limiter,
        RouteCheckTarget target,
        string proxyUrl,
        CancellationToken cancellationToken)
    {
        bool entered = false;
        Stopwatch totalWatch = new Stopwatch();
        long dnsMs = -1;
        long tcpMs = -1;
        long tunnelMs = -1;
        long tlsMs = -1;
        long ttfbMs = -1;
        int statusCode = 0;
        int responseBytes = 0;
        string tlsProtocol = String.Empty;
        string phase = "подготовка";
        TcpClient tcp = null;
        SslStream tls = null;
        try
        {
            await limiter.WaitAsync(cancellationToken).ConfigureAwait(false);
            entered = true;
            using (CancellationTokenSource timeoutSource =
                CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                timeoutSource.CancelAfter(timeoutMilliseconds);
                CancellationToken token = timeoutSource.Token;
                totalWatch.Start();

                Uri proxy = String.IsNullOrWhiteSpace(proxyUrl)
                    ? null
                    : new Uri(proxyUrl);
                Stopwatch stage = Stopwatch.StartNew();

                if (proxy == null)
                {
                    phase = "DNS";
                    IPAddress[] addresses = await AwaitWithCancellation(
                        Dns.GetHostAddressesAsync(target.Endpoint.DnsSafeHost),
                        token).ConfigureAwait(false);
                    stage.Stop();
                    dnsMs = Math.Max(0L, stage.ElapsedMilliseconds);
                    if (addresses == null || addresses.Length == 0)
                        throw new ProbeException(
                            "DNS",
                            "DNS не вернул адрес сервиса");

                    phase = "TCP";
                    stage.Restart();
                    tcp = await ConnectAnyAsync(
                        addresses,
                        target.Endpoint.Port,
                        token).ConfigureAwait(false);
                    stage.Stop();
                    tcpMs = Math.Max(1L, stage.ElapsedMilliseconds);
                }
                else
                {
                    phase = "TCP";
                    stage.Restart();
                    tcp = new TcpClient();
                    await ConnectTcpAsync(
                        tcp,
                        proxy.DnsSafeHost,
                        proxy.Port,
                        token).ConfigureAwait(false);
                    stage.Stop();
                    tcpMs = Math.Max(1L, stage.ElapsedMilliseconds);

                    phase = "VPN-туннель";
                    stage.Restart();
                    NetworkStream proxyStream = tcp.GetStream();
                    string authority =
                        target.Endpoint.DnsSafeHost + ":" + target.Endpoint.Port;
                    string connectRequest =
                        "CONNECT " + authority + " HTTP/1.1\r\n" +
                        "Host: " + authority + "\r\n" +
                        "Proxy-Connection: keep-alive\r\n" +
                        "User-Agent: Luna-RouteQuality/2.0\r\n\r\n";
                    await WriteAsciiAsync(
                        proxyStream,
                        connectRequest,
                        token).ConfigureAwait(false);
                    string connectResponse = await ReadHeadersAsync(
                        proxyStream,
                        token).ConfigureAwait(false);
                    int connectStatus = ParseStatusCode(connectResponse);
                    if (connectStatus != 200)
                        throw new ProbeException(
                            "VPN-туннель",
                            "Прокси не открыл маршрут: HTTP " + connectStatus);
                    stage.Stop();
                    tunnelMs = Math.Max(1L, stage.ElapsedMilliseconds);
                }

                phase = "TLS";
                stage.Restart();
                tls = new SslStream(tcp.GetStream(), false);
                await AwaitWithCancellation(
                    tls.AuthenticateAsClientAsync(
                        target.Endpoint.DnsSafeHost,
                        new X509CertificateCollection(),
                        SslProtocols.Tls12 | SslProtocols.Tls13,
                        false),
                    token).ConfigureAwait(false);
                stage.Stop();
                tlsMs = Math.Max(1L, stage.ElapsedMilliseconds);
                tlsProtocol = tls.SslProtocol.ToString();

                phase = "HTTP";
                string path = String.IsNullOrEmpty(target.Endpoint.PathAndQuery)
                    ? "/"
                    : target.Endpoint.PathAndQuery;
                string request;
                if (String.Equals(
                    target.ProbeKind,
                    "websocket",
                    StringComparison.OrdinalIgnoreCase))
                {
                    request =
                        "GET " + path + " HTTP/1.1\r\n" +
                        "Host: " + target.Endpoint.DnsSafeHost + "\r\n" +
                        "Upgrade: websocket\r\n" +
                        "Connection: Upgrade\r\n" +
                        "Sec-WebSocket-Key: TGluYS1Sb3V0ZS1DaGVjaw==\r\n" +
                        "Sec-WebSocket-Version: 13\r\n" +
                        "User-Agent: Luna-RouteQuality/2.0\r\n\r\n";
                }
                else
                {
                    request =
                        "GET " + path + " HTTP/1.1\r\n" +
                        "Host: " + target.Endpoint.DnsSafeHost + "\r\n" +
                        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
                        "Luna-RouteQuality/2.0\r\n" +
                        "Accept: */*\r\n" +
                        "Accept-Encoding: identity\r\n" +
                        "Cache-Control: no-cache, no-store\r\n" +
                        "Pragma: no-cache\r\n" +
                        "Range: bytes=0-" + (MaxResponseBytes - 1) + "\r\n" +
                        "Connection: close\r\n\r\n";
                }
                await WriteAsciiAsync(tls, request, token).ConfigureAwait(false);

                phase = "HTTP-ответ";
                HttpProbeData http = await ReadAndValidateResponseAsync(
                    tls,
                    target.ExpectedMarker,
                    token).ConfigureAwait(false);
                statusCode = http.StatusCode;
                ttfbMs = http.TtfbMs;
                responseBytes = http.BytesRead;

                if ((statusCode < 200 || statusCode >= 400) &&
                    statusCode != 101)
                    throw new ProbeException(
                        "HTTP",
                        "Сервис ответил HTTP " + statusCode);
                if (!http.ContentValidated)
                    throw new ProbeException(
                        "содержимое",
                        "Ответ получен, но сервис не подтверждён");

                totalWatch.Stop();
                return CreateMeasuredResult(
                    target,
                    Math.Max(1L, totalWatch.ElapsedMilliseconds),
                    statusCode,
                    dnsMs,
                    tcpMs,
                    tunnelMs,
                    tlsMs,
                    ttfbMs,
                    tlsProtocol,
                    responseBytes);
            }
        }
        catch (OperationCanceledException)
        {
            if (cancellationToken.IsCancellationRequested)
                throw;
            return CreateFailure(
                target,
                "Тайм-аут на этапе: " + phase,
                totalWatch,
                statusCode,
                dnsMs,
                tcpMs,
                tunnelMs,
                tlsMs,
                ttfbMs,
                tlsProtocol,
                responseBytes);
        }
        catch (AuthenticationException)
        {
            return CreateFailure(
                target,
                "TLS: сертификат или handshake не прошёл проверку",
                totalWatch,
                statusCode,
                dnsMs,
                tcpMs,
                tunnelMs,
                tlsMs,
                ttfbMs,
                tlsProtocol,
                responseBytes);
        }
        catch (ProbeException error)
        {
            return CreateFailure(
                target,
                error.Phase + ": " + error.Message,
                totalWatch,
                statusCode,
                dnsMs,
                tcpMs,
                tunnelMs,
                tlsMs,
                ttfbMs,
                tlsProtocol,
                responseBytes);
        }
        catch (Exception error)
        {
            return CreateFailure(
                target,
                DescribeError(error, phase),
                totalWatch,
                statusCode,
                dnsMs,
                tcpMs,
                tunnelMs,
                tlsMs,
                ttfbMs,
                tlsProtocol,
                responseBytes);
        }
        finally
        {
            if (tls != null)
            {
                try { tls.Dispose(); } catch { }
            }
            if (tcp != null)
            {
                try { tcp.Close(); } catch { }
            }
            if (entered) limiter.Release();
        }
    }

    private static async Task<T> AwaitWithCancellation<T>(
        Task<T> task,
        CancellationToken token)
    {
        TaskCompletionSource<bool> cancelled =
            new TaskCompletionSource<bool>();
        using (token.Register(() => cancelled.TrySetResult(true)))
        {
            Task winner = await Task.WhenAny(
                task,
                cancelled.Task).ConfigureAwait(false);
            if (winner != task)
                throw new OperationCanceledException(token);
        }
        return await task.ConfigureAwait(false);
    }

    private static async Task AwaitWithCancellation(
        Task task,
        CancellationToken token)
    {
        TaskCompletionSource<bool> cancelled =
            new TaskCompletionSource<bool>();
        using (token.Register(() => cancelled.TrySetResult(true)))
        {
            Task winner = await Task.WhenAny(
                task,
                cancelled.Task).ConfigureAwait(false);
            if (winner != task)
                throw new OperationCanceledException(token);
        }
        await task.ConfigureAwait(false);
    }

    private static async Task<TcpClient> ConnectAnyAsync(
        IPAddress[] addresses,
        int port,
        CancellationToken token)
    {
        Exception lastError = null;
        foreach (IPAddress address in addresses
            .OrderBy(item => item.AddressFamily == AddressFamily.InterNetwork ? 0 : 1))
        {
            token.ThrowIfCancellationRequested();
            TcpClient client = new TcpClient(address.AddressFamily);
            try
            {
                await ConnectTcpAsync(
                    client,
                    address,
                    port,
                    token).ConfigureAwait(false);
                return client;
            }
            catch (OperationCanceledException)
            {
                client.Close();
                throw;
            }
            catch (Exception error)
            {
                lastError = error;
                client.Close();
            }
        }
        throw new ProbeException(
            "TCP",
            lastError == null
                ? "Не удалось открыть соединение"
                : "Соединение отклонено или недоступно");
    }

    private static async Task ConnectTcpAsync(
        TcpClient client,
        string host,
        int port,
        CancellationToken token)
    {
        using (token.Register(() =>
        {
            try { client.Close(); } catch { }
        }))
        {
            await AwaitWithCancellation(
                client.ConnectAsync(host, port),
                token).ConfigureAwait(false);
        }
    }

    private static async Task ConnectTcpAsync(
        TcpClient client,
        IPAddress address,
        int port,
        CancellationToken token)
    {
        using (token.Register(() =>
        {
            try { client.Close(); } catch { }
        }))
        {
            await AwaitWithCancellation(
                client.ConnectAsync(address, port),
                token).ConfigureAwait(false);
        }
    }

    private static async Task WriteAsciiAsync(
        Stream stream,
        string text,
        CancellationToken token)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(text);
        await stream.WriteAsync(
            bytes,
            0,
            bytes.Length,
            token).ConfigureAwait(false);
        await stream.FlushAsync(token).ConfigureAwait(false);
    }

    private static async Task<string> ReadHeadersAsync(
        Stream stream,
        CancellationToken token)
    {
        byte[] data = new byte[512];
        MemoryStream collected = new MemoryStream();
        while (collected.Length < 8192)
        {
            int read = await stream.ReadAsync(
                data,
                0,
                data.Length,
                token).ConfigureAwait(false);
            if (read <= 0) break;
            collected.Write(data, 0, read);
            string text = Encoding.ASCII.GetString(collected.ToArray());
            if (text.IndexOf("\r\n\r\n", StringComparison.Ordinal) >= 0)
                return text;
        }
        throw new ProbeException(
            "VPN-туннель",
            "Прокси не вернул корректный ответ");
    }

    private static async Task<HttpProbeData> ReadAndValidateResponseAsync(
        Stream stream,
        string expectedMarker,
        CancellationToken token)
    {
        byte[] chunk = new byte[2048];
        MemoryStream collected = new MemoryStream();
        Stopwatch firstByteWatch = Stopwatch.StartNew();
        long ttfb = -1;

        while (collected.Length < MaxResponseBytes)
        {
            int allowed = (int)Math.Min(
                chunk.Length,
                MaxResponseBytes - collected.Length);
            int read = await stream.ReadAsync(
                chunk,
                0,
                allowed,
                token).ConfigureAwait(false);
            if (read <= 0) break;
            if (ttfb < 0)
            {
                firstByteWatch.Stop();
                ttfb = Math.Max(1L, firstByteWatch.ElapsedMilliseconds);
            }
            collected.Write(chunk, 0, read);

            string current = Encoding.UTF8.GetString(collected.ToArray());
            int headerEnd = current.IndexOf(
                "\r\n\r\n",
                StringComparison.Ordinal);
            if (headerEnd >= 0 &&
                current.IndexOf(
                    expectedMarker,
                    0,
                    StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return new HttpProbeData
                {
                    StatusCode = ParseStatusCode(current),
                    TtfbMs = ttfb,
                    ContentValidated = true,
                    BytesRead = (int)collected.Length
                };
            }
        }

        string response = Encoding.UTF8.GetString(collected.ToArray());
        return new HttpProbeData
        {
            StatusCode = ParseStatusCode(response),
            TtfbMs = ttfb,
            ContentValidated = false,
            BytesRead = (int)collected.Length
        };
    }

    private static int ParseStatusCode(string headers)
    {
        if (String.IsNullOrWhiteSpace(headers)) return 0;
        string firstLine = headers.Split(new[] { "\r\n" },
            StringSplitOptions.None)[0];
        string[] parts = firstLine.Split(' ');
        int status;
        return parts.Length >= 2 && Int32.TryParse(parts[1], out status)
            ? status
            : 0;
    }

    private static RouteCheckResult CreateMeasuredResult(
        RouteCheckTarget target,
        long latencyMs,
        int httpStatusCode,
        long dnsMs,
        long tcpMs,
        long tunnelMs,
        long tlsMs,
        long ttfbMs,
        string tlsProtocol,
        int responseBytes)
    {
        string status;
        string error = String.Empty;
        bool available = true;

        if (latencyMs <= 80) status = "Отлично";
        else if (latencyMs <= 150) status = "Хорошо";
        else if (latencyMs <= 300) status = "Нормально";
        else if (latencyMs <= 700) status = "Медленно";
        else
        {
            status = "Недоступно";
            error = "Отклик более 700 ms";
            available = false;
        }

        return new RouteCheckResult
        {
            Target = target,
            IsAvailable = available,
            LatencyMs = latencyMs,
            Status = status,
            ErrorReason = error,
            HttpStatusCode = httpStatusCode,
            CheckedAt = DateTimeOffset.Now,
            DnsMs = dnsMs,
            TcpMs = tcpMs,
            TunnelMs = tunnelMs,
            TlsMs = tlsMs,
            TtfbMs = ttfbMs,
            TlsProtocol = tlsProtocol,
            ContentValidated = true,
            ResponseBytesRead = responseBytes
        };
    }

    private static RouteCheckResult CreateFailure(
        RouteCheckTarget target,
        string reason,
        Stopwatch watch,
        int httpStatusCode,
        long dnsMs,
        long tcpMs,
        long tunnelMs,
        long tlsMs,
        long ttfbMs,
        string tlsProtocol,
        int responseBytes)
    {
        if (watch.IsRunning) watch.Stop();
        return new RouteCheckResult
        {
            Target = target,
            IsAvailable = false,
            LatencyMs = -1,
            Status = "Недоступно",
            ErrorReason = reason,
            HttpStatusCode = httpStatusCode,
            CheckedAt = DateTimeOffset.Now,
            DnsMs = dnsMs,
            TcpMs = tcpMs,
            TunnelMs = tunnelMs,
            TlsMs = tlsMs,
            TtfbMs = ttfbMs,
            TlsProtocol = tlsProtocol,
            ContentValidated = false,
            ResponseBytesRead = responseBytes
        };
    }

    private static string DescribeError(Exception error, string phase)
    {
        Exception current = error;
        while (current != null)
        {
            SocketException socket = current as SocketException;
            if (socket != null)
            {
                if (socket.SocketErrorCode == SocketError.HostNotFound ||
                    socket.SocketErrorCode == SocketError.NoData ||
                    socket.SocketErrorCode == SocketError.TryAgain)
                    return "DNS: имя сервиса не найдено";
                return phase + ": сетевая ошибка " + socket.SocketErrorCode;
            }

            AuthenticationException authentication =
                current as AuthenticationException;
            if (authentication != null)
                return "TLS: сертификат или handshake не прошёл проверку";

            WebException web = current as WebException;
            if (web != null)
            {
                if (web.Status == WebExceptionStatus.NameResolutionFailure)
                    return "DNS: имя сервиса не найдено";
                if (web.Status == WebExceptionStatus.TrustFailure ||
                    web.Status == WebExceptionStatus.SecureChannelFailure)
                    return "TLS: защищённое соединение не установлено";
                if (web.Status == WebExceptionStatus.Timeout)
                    return "Тайм-аут на этапе: " + phase;
                return phase + ": " + web.Status;
            }

            current = current.InnerException;
        }

        string message = error.Message ?? String.Empty;
        if (message.IndexOf("name could not be resolved",
            StringComparison.OrdinalIgnoreCase) >= 0)
            return "DNS: имя сервиса не найдено";
        if (message.IndexOf("SSL", StringComparison.OrdinalIgnoreCase) >= 0 ||
            message.IndexOf("TLS", StringComparison.OrdinalIgnoreCase) >= 0)
            return "TLS: защищённое соединение не установлено";
        return phase + ": соединение завершилось ошибкой";
    }
}

internal sealed class LunaTrafficCounter
{
    public readonly int ProcessId;
    public readonly string ProcessName;
    public long ReceivedBytes;
    public long SentBytes;
    public long ActiveConnections;
    public long TotalConnections;

    public LunaTrafficCounter(int processId, string processName)
    {
        ProcessId = processId;
        ProcessName = processName;
    }
}

public static class LunaTrafficMeter
{
    private const int AfInet = 2;
    private const int TcpTableOwnerPidAll = 5;
    private static readonly object Gate = new object();
    private static ConcurrentDictionary<int, LunaTrafficCounter> counters =
        new ConcurrentDictionary<int, LunaTrafficCounter>();
    private static List<TcpListener> listeners = new List<TcpListener>();
    private static List<TcpClient> clients = new List<TcpClient>();
    private static List<Task> backgroundTasks = new List<Task>();
    private static CancellationTokenSource cancellation;
    private static long receivedBytes;
    private static long sentBytes;
    private static string[] directProcessPaths = new string[0];
    private static string[] directDomains = new string[0];
    private static string[] directNetworks = new string[0];

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddress;
        public uint LocalPort;
        public uint RemoteAddress;
        public uint RemotePort;
        public uint OwningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr tcpTable,
        ref int size,
        bool order,
        int ipVersion,
        int tableClass,
        uint reserved);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(
        uint desiredAccess,
        bool inheritHandle,
        int processId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool QueryFullProcessImageName(
        IntPtr process,
        uint flags,
        StringBuilder path,
        ref int size);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    public static void Start(
        int socksListenPort,
        int socksTargetPort,
        int httpListenPort,
        int httpTargetPort,
        string[] processPaths,
        string[] domains,
        string[] networks)
    {
        Stop();
        counters = new ConcurrentDictionary<int, LunaTrafficCounter>();
        Interlocked.Exchange(ref receivedBytes, 0);
        Interlocked.Exchange(ref sentBytes, 0);
        directProcessPaths = NormalizePaths(processPaths);
        directDomains = NormalizeRules(domains);
        directNetworks = NormalizeRules(networks);
        cancellation = new CancellationTokenSource();

        StartRelay(socksListenPort, socksTargetPort, false, cancellation.Token);
        StartRelay(httpListenPort, httpTargetPort, true, cancellation.Token);
    }

    public static void Stop()
    {
        lock (Gate)
        {
            if (cancellation != null)
            {
                cancellation.Cancel();
                cancellation.Dispose();
                cancellation = null;
            }

            foreach (TcpListener listener in listeners)
            {
                try { listener.Stop(); } catch { }
            }
            listeners.Clear();
            backgroundTasks.Clear();

            foreach (TcpClient client in clients)
            {
                try { client.Close(); } catch { }
            }
            clients.Clear();
        }
    }

    public static LunaTrafficTotals GetTotals()
    {
        return new LunaTrafficTotals
        {
            ReceivedBytes = Interlocked.Read(ref receivedBytes),
            SentBytes = Interlocked.Read(ref sentBytes)
        };
    }

    public static LunaAppTraffic[] GetApplications()
    {
        return counters.Values
            .Select(counter => new LunaAppTraffic
            {
                ProcessId = counter.ProcessId,
                ProcessName = counter.ProcessName,
                ReceivedBytes = Interlocked.Read(ref counter.ReceivedBytes),
                SentBytes = Interlocked.Read(ref counter.SentBytes),
                TotalBytes =
                    Interlocked.Read(ref counter.ReceivedBytes) +
                    Interlocked.Read(ref counter.SentBytes),
                ActiveConnections =
                    Interlocked.Read(ref counter.ActiveConnections),
                TotalConnections =
                    Interlocked.Read(ref counter.TotalConnections)
            })
            .Where(item => item.TotalBytes > 0 || item.ActiveConnections > 0)
            .OrderByDescending(item => item.TotalBytes)
            .ToArray();
    }

    private static void StartRelay(
        int listenPort,
        int targetPort,
        bool selectiveHttp,
        CancellationToken token)
    {
        TcpListener listener = new TcpListener(IPAddress.Loopback, listenPort);
        listener.Start();
        Task acceptTask = Task.Run(() => AcceptLoop(
            listener, listenPort, targetPort, selectiveHttp, token));
        lock (Gate)
        {
            listeners.Add(listener);
            backgroundTasks.Add(acceptTask);
        }
    }

    private static async Task AcceptLoop(
        TcpListener listener,
        int listenPort,
        int targetPort,
        bool selectiveHttp,
        CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await listener.AcceptTcpClientAsync();
            }
            catch
            {
                if (token.IsCancellationRequested) return;
                continue;
            }

            lock (Gate) { clients.Add(client); }
            Task connectionTask = Task.Run(() => HandleConnection(
                client, listenPort, targetPort, selectiveHttp, token));
            lock (Gate) { backgroundTasks.Add(connectionTask); }
        }
    }

    private static async Task HandleConnection(
        TcpClient client,
        int listenPort,
        int targetPort,
        bool selectiveHttp,
        CancellationToken token)
    {
        TcpClient target = null;
        LunaTrafficCounter counter = null;
        try
        {
            IPEndPoint remote = client.Client.RemoteEndPoint as IPEndPoint;
            int processId = remote == null
                ? 0
                : FindOwningProcess(remote.Port, listenPort);
            counter = counters.GetOrAdd(
                processId,
                id => new LunaTrafficCounter(id, GetProcessName(id)));
            Interlocked.Increment(ref counter.ActiveConnections);
            Interlocked.Increment(ref counter.TotalConnections);

            NetworkStream clientStream = client.GetStream();
            if (selectiveHttp)
            {
                await HandleHttpProxyConnection(
                    clientStream, targetPort, processId, counter, token);
                return;
            }

            target = new TcpClient(AddressFamily.InterNetwork);
            lock (Gate) { clients.Add(target); }
            await target.ConnectAsync(IPAddress.Loopback, targetPort);
            NetworkStream targetStream = target.GetStream();
            Task upload = Pump(
                clientStream,
                targetStream,
                counter,
                true,
                token);
            Task download = Pump(
                targetStream,
                clientStream,
                counter,
                false,
                token);
            await Task.WhenAll(upload, download);
        }
        catch { }
        finally
        {
            if (counter != null)
                Interlocked.Decrement(ref counter.ActiveConnections);
            try { client.Close(); } catch { }
            try { if (target != null) target.Close(); } catch { }
            lock (Gate)
            {
                clients.Remove(client);
                if (target != null) clients.Remove(target);
            }
        }
    }

    private sealed class HttpRequestHead
    {
        public byte[] Bytes;
        public int HeaderLength;
        public string Host;
        public int Port;
        public bool IsConnect;
    }

    private static async Task HandleHttpProxyConnection(
        NetworkStream clientStream,
        int proxyTargetPort,
        int processId,
        LunaTrafficCounter counter,
        CancellationToken token)
    {
        TcpClient target = null;
        try
        {
            HttpRequestHead request = await ReadHttpRequestHead(clientStream, token);
            if (request == null) return;

            string processPath = GetProcessPath(processId);
            bool direct = await ShouldRouteDirect(processPath, request.Host);
            target = new TcpClient();
            lock (Gate) { clients.Add(target); }
            if (direct)
                await target.ConnectAsync(request.Host, request.Port);
            else
                await target.ConnectAsync(IPAddress.Loopback, proxyTargetPort);

            NetworkStream targetStream = target.GetStream();
            if (direct && request.IsConnect)
            {
                byte[] established = Encoding.ASCII.GetBytes(
                    "HTTP/1.1 200 Connection Established\r\n" +
                    "Proxy-Agent: Luna/1.5\r\n\r\n");
                await clientStream.WriteAsync(
                    established, 0, established.Length, token);
                CountTransfer(counter, false, established.Length);
                int trailing = request.Bytes.Length - request.HeaderLength;
                if (trailing > 0)
                {
                    await targetStream.WriteAsync(
                        request.Bytes, request.HeaderLength, trailing, token);
                    CountTransfer(counter, true, trailing);
                }
            }
            else
            {
                byte[] outbound = direct
                    ? RewriteDirectHttpRequest(request)
                    : request.Bytes;
                await targetStream.WriteAsync(outbound, 0, outbound.Length, token);
                CountTransfer(counter, true, outbound.Length);
            }

            Task upload = Pump(clientStream, targetStream, counter, true, token);
            Task download = Pump(targetStream, clientStream, counter, false, token);
            await Task.WhenAll(upload, download);
        }
        catch
        {
            try
            {
                byte[] failed = Encoding.ASCII.GetBytes(
                    "HTTP/1.1 502 Bad Gateway\r\n" +
                    "Connection: close\r\nContent-Length: 0\r\n\r\n");
                clientStream.Write(failed, 0, failed.Length);
            }
            catch { }
        }
        finally
        {
            try { if (target != null) target.Close(); } catch { }
            lock (Gate) { if (target != null) clients.Remove(target); }
        }
    }

    private static async Task<HttpRequestHead> ReadHttpRequestHead(
        NetworkStream stream,
        CancellationToken token)
    {
        MemoryStream buffer = new MemoryStream();
        byte[] chunk = new byte[4096];
        int headerLength = -1;
        while (buffer.Length < 65536 && headerLength < 0)
        {
            int count = await stream.ReadAsync(chunk, 0, chunk.Length, token);
            if (count <= 0) return null;
            buffer.Write(chunk, 0, count);
            headerLength = FindHeaderEnd(buffer.ToArray());
        }
        if (headerLength < 0) return null;

        byte[] bytes = buffer.ToArray();
        string headers = Encoding.ASCII.GetString(bytes, 0, headerLength);
        string[] lines = headers.Split(new[] { "\r\n" }, StringSplitOptions.None);
        if (lines.Length == 0) return null;
        string[] first = lines[0].Split(new[] { ' ' }, 3);
        if (first.Length < 2) return null;

        bool connect = first[0].Equals("CONNECT", StringComparison.OrdinalIgnoreCase);
        string host;
        int port;
        if (connect)
        {
            if (!TryParseAuthority(first[1], 443, out host, out port)) return null;
        }
        else
        {
            Uri uri;
            if (Uri.TryCreate(first[1], UriKind.Absolute, out uri))
            {
                host = uri.Host;
                port = uri.IsDefaultPort
                    ? (uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase)
                        ? 443 : 80)
                    : uri.Port;
            }
            else
            {
                string hostHeader = lines.FirstOrDefault(line =>
                    line.StartsWith("Host:", StringComparison.OrdinalIgnoreCase));
                if (hostHeader == null || !TryParseAuthority(
                    hostHeader.Substring(5).Trim(), 80, out host, out port))
                    return null;
            }
        }

        return new HttpRequestHead
        {
            Bytes = bytes,
            HeaderLength = headerLength,
            Host = host,
            Port = port,
            IsConnect = connect
        };
    }

    private static int FindHeaderEnd(byte[] bytes)
    {
        for (int index = 3; index < bytes.Length; index++)
        {
            if (bytes[index - 3] == 13 && bytes[index - 2] == 10 &&
                bytes[index - 1] == 13 && bytes[index] == 10)
                return index + 1;
        }
        return -1;
    }

    private static bool TryParseAuthority(
        string authority,
        int defaultPort,
        out string host,
        out int port)
    {
        host = null;
        port = defaultPort;
        authority = (authority ?? String.Empty).Trim();
        if (authority.StartsWith("[", StringComparison.Ordinal))
        {
            int closing = authority.IndexOf(']');
            if (closing <= 1) return false;
            host = authority.Substring(1, closing - 1);
            if (closing + 1 < authority.Length && authority[closing + 1] == ':')
            {
                int parsed;
                if (Int32.TryParse(authority.Substring(closing + 2), out parsed))
                    port = parsed;
            }
            return port > 0 && port <= 65535;
        }

        int separator = authority.LastIndexOf(':');
        if (separator > 0 && authority.IndexOf(':') == separator)
        {
            int parsed;
            if (Int32.TryParse(authority.Substring(separator + 1), out parsed))
            {
                port = parsed;
                authority = authority.Substring(0, separator);
            }
        }
        host = authority.TrimEnd('.');
        return host.Length > 0 && port > 0 && port <= 65535;
    }

    private static byte[] RewriteDirectHttpRequest(HttpRequestHead request)
    {
        string text = Encoding.ASCII.GetString(
            request.Bytes, 0, request.HeaderLength);
        int lineEnd = text.IndexOf("\r\n", StringComparison.Ordinal);
        string firstLine = lineEnd >= 0 ? text.Substring(0, lineEnd) : text;
        string[] first = firstLine.Split(new[] { ' ' }, 3);
        Uri uri;
        if (first.Length >= 3 && Uri.TryCreate(first[1], UriKind.Absolute, out uri))
        {
            string path = String.IsNullOrEmpty(uri.PathAndQuery)
                ? "/" : uri.PathAndQuery;
            string replacement = first[0] + " " + path + " " + first[2];
            text = replacement + text.Substring(firstLine.Length);
        }
        byte[] header = Encoding.ASCII.GetBytes(text);
        int trailing = request.Bytes.Length - request.HeaderLength;
        if (trailing <= 0) return header;
        byte[] result = new byte[header.Length + trailing];
        Buffer.BlockCopy(header, 0, result, 0, header.Length);
        Buffer.BlockCopy(
            request.Bytes, request.HeaderLength, result, header.Length, trailing);
        return result;
    }

    private static async Task Pump(
        NetworkStream source,
        NetworkStream destination,
        LunaTrafficCounter counter,
        bool upload,
        CancellationToken token)
    {
        byte[] buffer = new byte[65536];
        while (!token.IsCancellationRequested)
        {
            int count = await source.ReadAsync(
                buffer,
                0,
                buffer.Length,
                token);
            if (count <= 0) return;
            await destination.WriteAsync(buffer, 0, count, token);

            if (upload)
            {
                Interlocked.Add(ref sentBytes, count);
                Interlocked.Add(ref counter.SentBytes, count);
            }
            else
            {
                Interlocked.Add(ref receivedBytes, count);
                Interlocked.Add(ref counter.ReceivedBytes, count);
            }
        }
    }

    private static async Task<bool> ShouldRouteDirect(
        string processPath,
        string host)
    {
        if (!String.IsNullOrWhiteSpace(processPath) &&
            directProcessPaths.Any(path => String.Equals(
                path, processPath, StringComparison.OrdinalIgnoreCase)))
            return true;

        string normalizedHost = (host ?? String.Empty).Trim('[', ']', '.', ' ')
            .ToLowerInvariant();
        if (directDomains.Any(rule => DomainMatches(normalizedHost, rule)))
            return true;

        IPAddress literal;
        if (IPAddress.TryParse(normalizedHost, out literal))
            return directNetworks.Any(rule => NetworkContains(rule, literal));

        if (directNetworks.Length == 0) return false;
        try
        {
            IPAddress[] resolved = await Dns.GetHostAddressesAsync(normalizedHost);
            return resolved.Any(address =>
                directNetworks.Any(rule => NetworkContains(rule, address)));
        }
        catch { return false; }
    }

    public static bool TestRouteDecision(
        string processPath,
        string host,
        string[] processPaths,
        string[] domains,
        string[] networks)
    {
        string[] oldPaths = directProcessPaths;
        string[] oldDomains = directDomains;
        string[] oldNetworks = directNetworks;
        try
        {
            directProcessPaths = NormalizePaths(processPaths);
            directDomains = NormalizeRules(domains);
            directNetworks = NormalizeRules(networks);
            return ShouldRouteDirect(processPath, host).GetAwaiter().GetResult();
        }
        finally
        {
            directProcessPaths = oldPaths;
            directDomains = oldDomains;
            directNetworks = oldNetworks;
        }
    }

    private static bool DomainMatches(string host, string rule)
    {
        rule = (rule ?? String.Empty).Trim().TrimEnd('.').ToLowerInvariant();
        bool wildcard = rule.StartsWith("*.", StringComparison.Ordinal);
        if (wildcard) rule = rule.Substring(2);
        if (rule.Length == 0) return false;
        if (wildcard)
            return host.EndsWith("." + rule, StringComparison.OrdinalIgnoreCase);
        return String.Equals(host, rule, StringComparison.OrdinalIgnoreCase) ||
            host.EndsWith("." + rule, StringComparison.OrdinalIgnoreCase);
    }

    private static bool NetworkContains(string rule, IPAddress address)
    {
        try
        {
            string[] parts = (rule ?? String.Empty).Split('/');
            IPAddress network = IPAddress.Parse(parts[0]);
            if (network.AddressFamily != address.AddressFamily) return false;
            byte[] networkBytes = network.GetAddressBytes();
            byte[] addressBytes = address.GetAddressBytes();
            int prefix = parts.Length == 2
                ? Int32.Parse(parts[1])
                : networkBytes.Length * 8;
            if (prefix < 0 || prefix > networkBytes.Length * 8) return false;
            for (int index = 0; index < networkBytes.Length; index++)
            {
                int remaining = prefix - index * 8;
                if (remaining <= 0) break;
                int bits = Math.Min(8, remaining);
                int mask = 0xFF << (8 - bits);
                if ((networkBytes[index] & mask) != (addressBytes[index] & mask))
                    return false;
            }
            return true;
        }
        catch { return false; }
    }

    private static string[] NormalizePaths(string[] values)
    {
        if (values == null) return new string[0];
        return values
            .Where(value => !String.IsNullOrWhiteSpace(value))
            .Select(value => value.Trim().Replace('/', '\\'))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static string[] NormalizeRules(string[] values)
    {
        if (values == null) return new string[0];
        return values
            .Where(value => !String.IsNullOrWhiteSpace(value))
            .Select(value => value.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static void CountTransfer(
        LunaTrafficCounter counter,
        bool upload,
        int count)
    {
        if (count <= 0 || counter == null) return;
        if (upload)
        {
            Interlocked.Add(ref sentBytes, count);
            Interlocked.Add(ref counter.SentBytes, count);
        }
        else
        {
            Interlocked.Add(ref receivedBytes, count);
            Interlocked.Add(ref counter.ReceivedBytes, count);
        }
    }

    private static string GetProcessName(int processId)
    {
        if (processId <= 0) return "Неизвестное приложение";
        try
        {
            return Process.GetProcessById(processId).ProcessName;
        }
        catch
        {
            return "PID " + processId;
        }
    }

    private static string GetProcessPath(int processId)
    {
        if (processId <= 0) return String.Empty;
        try
        {
            Process process = Process.GetProcessById(processId);
            return process.MainModule == null
                ? String.Empty : process.MainModule.FileName;
        }
        catch { }
        IntPtr handle = OpenProcess(0x1000, false, processId);
        if (handle == IntPtr.Zero) return String.Empty;
        try
        {
            StringBuilder path = new StringBuilder(32768);
            int length = path.Capacity;
            return QueryFullProcessImageName(handle, 0, path, ref length)
                ? path.ToString() : String.Empty;
        }
        finally { CloseHandle(handle); }
    }

    public static string ResolveProcessPath(int processId)
    {
        return GetProcessPath(processId);
    }

    private static int FindOwningProcess(int clientPort, int proxyPort)
    {
        for (int attempt = 0; attempt < 4; attempt++)
        {
            int result = FindOwningProcessOnce(clientPort, proxyPort);
            if (result > 0) return result;
            Thread.Sleep(10);
        }
        return 0;
    }

    private static int FindOwningProcessOnce(int clientPort, int proxyPort)
    {
        int size = 0;
        GetExtendedTcpTable(
            IntPtr.Zero,
            ref size,
            false,
            AfInet,
            TcpTableOwnerPidAll,
            0);
        if (size <= 0) return 0;

        IntPtr table = Marshal.AllocHGlobal(size);
        try
        {
            uint status = GetExtendedTcpTable(
                table,
                ref size,
                false,
                AfInet,
                TcpTableOwnerPidAll,
                0);
            if (status != 0) return 0;

            int count = Marshal.ReadInt32(table);
            IntPtr rowPointer = IntPtr.Add(table, sizeof(int));
            int rowSize = Marshal.SizeOf(typeof(MibTcpRowOwnerPid));
            for (int index = 0; index < count; index++)
            {
                MibTcpRowOwnerPid row =
                    (MibTcpRowOwnerPid)Marshal.PtrToStructure(
                        rowPointer,
                        typeof(MibTcpRowOwnerPid));
                if (DecodePort(row.LocalPort) == clientPort &&
                    DecodePort(row.RemotePort) == proxyPort)
                    return unchecked((int)row.OwningPid);
                rowPointer = IntPtr.Add(rowPointer, rowSize);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(table);
        }
        return 0;
    }

    private static int DecodePort(uint networkPort)
    {
        byte[] bytes = BitConverter.GetBytes(networkPort);
        return (bytes[0] << 8) | bytes[1];
    }
}
'@ -ReferencedAssemblies 'System.Net.Http.dll'

$AppVersion = '1.5.2-release'
$AppRoot = Join-Path $env:LOCALAPPDATA 'Luna'
$LegacyRoot = Join-Path $env:LOCALAPPDATA 'LumaTunnel'
$CoreDir = Join-Path $AppRoot 'core'
$DataFile = Join-Path $AppRoot 'state.json'
$ConfigFile = Join-Path $AppRoot 'xray-config.json'
$LogFile = Join-Path $AppRoot 'xray.log'
$RuntimeErrorFile = Join-Path $AppRoot 'xray-stderr.log'
$RuntimeOutputFile = Join-Path $AppRoot 'xray-stdout.log'
$BackendServerCacheFile = Join-Path $AppRoot 'backend-servers-cache.json'
$BackendMetadataCacheFile = Join-Path $AppRoot 'backend-metadata-cache.json'
$BackendClientConfigFile = Join-Path $AppRoot 'client-api.json'
$DefaultBackendBaseUrl = 'https://security-luna-vpn.ru'
New-Item -ItemType Directory -Force -Path $AppRoot, $CoreDir | Out-Null
if(-not (Test-Path $DataFile) -and (Test-Path (Join-Path $LegacyRoot 'state.json'))){
    Copy-Item (Join-Path $LegacyRoot 'state.json') $DataFile -Force
}
if(-not (Test-Path (Join-Path $CoreDir 'xray.exe')) -and (Test-Path (Join-Path $LegacyRoot 'core\xray.exe'))){
    Copy-Item (Join-Path $LegacyRoot 'core\*') $CoreDir -Recurse -Force
}

$defaultState = @{
    profiles = @()
    subscriptions = @()
    selectedId = ''
    settings = @{
        mode='System proxy'; localPort=10808; dns='1.1.1.1'; bypassLan=$true
        blockAds=$false; autoStart=$false; startMinimized=$false
        directDomains='localhost,*.local'; blockDomains='';language='Русский';theme='Темная'
        autoConnect=$false;killSwitch=$false;dnsProtection=$false;enableIPv6=$false
        webRtcProtection=$false;dnsLeakProtection=$false;checkUpdates=$true;anonymousStats=$false
        telemetryConsentAsked=$false;latencyAutoRefresh=$false
        engine='Xray-core';splitEnabled=$false;splitDomains=@();splitIps=@();splitApps=@();splitGames=@()
    }
}

function ConvertTo-Hashtable($Object) {
    if ($null -eq $Object) { return $null }
    if ($Object -is [string] -or $Object.GetType().IsPrimitive -or $Object -is [decimal] -or $Object -is [datetime]) {
        return $Object
    }
    if ($Object -is [System.Collections.IDictionary]) {
        $h = @{}; foreach ($k in $Object.Keys) { $h[$k] = ConvertTo-Hashtable $Object[$k] }; return $h
    }
    if ($Object -is [System.Collections.IEnumerable] -and $Object -isnot [string]) {
        return ,@($Object | ForEach-Object { ConvertTo-Hashtable $_ })
    }
    if ($Object -is [pscustomobject]) {
        $h = @{}; foreach ($p in $Object.PSObject.Properties) { $h[$p.Name] = ConvertTo-Hashtable $p.Value }; return $h
    }
    return $Object
}
function Get-LunaObjectValue($Object,[string]$Name,$Fallback=$null) {
    if($null -eq $Object){return $Fallback}
    if($Object -is [System.Collections.IDictionary]){
        if($Object.Contains($Name)){return $Object[$Name]}
        return $Fallback
    }
    $property=$Object.PSObject.Properties[$Name]
    if($null -ne $property){return $property.Value}
    return $Fallback
}
function Set-LunaObjectValue($Object,[string]$Name,$Value) {
    if($null -eq $Object){throw "Нельзя назначить свойство '$Name' пустому объекту."}
    if($Object -is [System.Collections.IDictionary]){$Object[$Name]=$Value;return}
    $property=$Object.PSObject.Properties[$Name]
    if($null -ne $property){$property.Value=$Value;return}
    $Object|Add-Member -NotePropertyName $Name -NotePropertyValue $Value
}
function Save-State {
    $temp="$DataFile.tmp"
    $script:State|ConvertTo-Json -Depth 30|Set-Content -Encoding UTF8 $temp
    Move-Item -LiteralPath $temp -Destination $DataFile -Force
}
function Load-State {
    if (Test-Path $DataFile) {
        try {
            $raw=Get-Content -Raw $DataFile
            if(-not [string]::IsNullOrWhiteSpace($raw)){
                $loaded=ConvertTo-Hashtable ($raw|ConvertFrom-Json)
                if($loaded -and $loaded.ContainsKey('settings')){
                    if(-not $loaded.ContainsKey('profiles')){$loaded.profiles=@()}
                    if(-not $loaded.ContainsKey('subscriptions')){$loaded.subscriptions=@()}
                    if(-not $loaded.ContainsKey('selectedId')){$loaded.selectedId=''}
                    return $loaded
                }
            }
        } catch {}
    }
    return ConvertTo-Hashtable $defaultState
}
$script:State = Load-State
foreach($key in $defaultState.settings.Keys){
    if(-not $script:State.settings.ContainsKey($key)){$script:State.settings[$key]=$defaultState.settings[$key]}
}
foreach($unfinishedSetting in @('autoConnect','killSwitch','dnsProtection','enableIPv6','webRtcProtection','dnsLeakProtection','checkUpdates')){$script:State.settings[$unfinishedSetting]=$false}
$script:State.settings.splitDomains=@($script:State.settings.splitDomains|Where-Object {$_})
$script:State.settings.splitIps=@($script:State.settings.splitIps|Where-Object {$_})
$script:State.settings.splitApps=@($script:State.settings.splitApps|Where-Object {$_})
$script:State.settings.splitGames=@($script:State.settings.splitGames|Where-Object {$_})
if($script:State.settings.directDomains){
    $legacyDirect=@([string]$script:State.settings.directDomains -split '[,;\r\n]+'|ForEach-Object {$_.Trim()}|Where-Object {$_})
    $script:State.settings.splitDomains=@($script:State.settings.splitDomains+$legacyDirect|Select-Object -Unique)
}
$runKey='HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$existingRunValue=(Get-ItemProperty $runKey -Name Luna -ErrorAction SilentlyContinue).Luna
if($env:LUNA_EXECUTABLE_PATH){
    if($existingRunValue -eq '""' -or $existingRunValue -match '(?i)powershell|\.ps1'){
        Remove-ItemProperty $runKey Luna -ErrorAction SilentlyContinue
        $existingRunValue=$null
    }
    if($existingRunValue -match '(?i)Luna\.exe'){
        $script:State.settings.autoStart=$true
        if($existingRunValue -match '(?i)--tray'){$script:State.settings.startMinimized=$true}
    }
}
if($env:LUNA_START_IN_TRAY -eq '1'){$script:State.settings.startMinimized=$true}
$script:CoreProcess = $null
$script:ConnectedAt = $null
$script:LatencyHistory = New-Object Collections.ArrayList
$script:PingTask = $null
$script:SelectedPingTask = $null
$script:SelectedPingProfileId = ''
$script:SelectedPingButton = $null
$script:LatencyLastCheckedAt = $null
$script:RefreshingProfiles = $false
$script:SettingsDirty = $false
$script:LogFollow = $true
$script:NetworkStart = $null
$script:NetworkLast = $null
$script:NetworkLastAt = $null
$script:SpeedSamples = @()
$script:SystemNetworkStart = $null
$script:SystemNetworkLast = $null
$script:SystemNetworkLastAt = $null
$script:ServerLoadState = 'loading'
$script:ServerLoadMessage = 'Подготавливаем каталог серверов…'
$script:BackendSyncInProgress = $false
$script:BackendConfig = $null
$script:BackendLatestVersion = $null
$script:BackendLatestNews = $null
$script:BackendLatestChangelog = $null
$script:RouteQualityService = New-Object RouteQualityService -ArgumentList 4500,3
$script:RouteTargets = [RouteCheckTarget[]]@(
    (New-Object RouteCheckTarget -ArgumentList 'youtube','YouTube','https://rr2---sn-gvnuxaxjvh-5c5l.googlevideo.com/generate_204','Server: gvs','http'),
    (New-Object RouteCheckTarget -ArgumentList 'discord','Discord','https://gateway.discord.gg/?v=10&encoding=json','Sec-WebSocket-Accept','websocket'),
    (New-Object RouteCheckTarget -ArgumentList 'microsoft','Microsoft','https://www.microsoft.com/robots.txt','User-agent','http'),
    (New-Object RouteCheckTarget -ArgumentList 'github','GitHub','https://api.github.com/rate_limit','"rate"','http'),
    (New-Object RouteCheckTarget -ArgumentList 'cloudflare','Cloudflare','https://www.cloudflare.com/cdn-cgi/trace','fl=','http')
)
$script:RouteQualityTask = $null
$script:RouteQualityCancellation = $null
$script:RouteQualityMode = ''
$script:RouteBaselineResults = @{}
$script:RouteVpnResults = @{}
$script:RouteNextCheckAt = $null
$script:RouteLastCheckedAt = $null

function Decode-Base64([string]$Text) {
    $s = $Text.Replace('-','+').Replace('_','/')
    while ($s.Length % 4) { $s += '=' }
    return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s))
}
function Get-Or($Value,$Fallback) {
    if($null -eq $Value -or [string]::IsNullOrEmpty([string]$Value)){return $Fallback}
    return $Value
}
function Parse-Query([string]$Query) {
    $result=@{}
    foreach($pair in $Query.TrimStart('?').Split('&',[StringSplitOptions]::RemoveEmptyEntries)){
        $kv=$pair.Split('=',2); $result[[Uri]::UnescapeDataString($kv[0])] = if($kv.Count -gt 1){[Uri]::UnescapeDataString($kv[1])}else{''}
    }
    return $result
}
function New-Profile([string]$Name,[string]$Protocol,[string]$ServerHost,[int]$Port,[hashtable]$Extra,[string]$Raw) {
    return @{ id=[guid]::NewGuid().ToString(); name=$Name; protocol=$Protocol; host=$ServerHost; port=$Port
        favorite=$false; latency='—'; extra=$Extra; raw=$Raw; subscriptionId='' }
}
function Parse-ProxyLink([string]$Link) {
    $Link=$Link.Trim()
    if($Link -match '^vmess://(.+)$'){
        $v=Decode-Base64 $Matches[1]; $j=ConvertTo-Hashtable ($v|ConvertFrom-Json)
        return New-Profile (Get-Or $j.ps "$($j.add):$($j.port)") 'vmess' $j.add ([int]$j.port) @{
            id=$j.id; aid=(Get-Or $j.aid 0); network=(Get-Or $j.net 'tcp'); security=(Get-Or $j.tls 'none')
            path=$j.path; hostHeader=$j.host; sni=$j.sni; type=$j.type
        } $Link
    }
    if($Link -notmatch '^(vless|trojan|socks|ss)://'){ throw 'Неподдерживаемый формат ссылки.' }
    $scheme=$Matches[1]
    if($scheme -eq 'ss'){
        $body=$Link.Substring(5); $name=''
        if($body.Contains('#')){$parts=$body.Split('#',2);$body=$parts[0];$name=[Uri]::UnescapeDataString($parts[1])}
        if($body.Contains('@')){$parts=$body.Split('@',2);$cred=$parts[0];$server=$parts[1]}else{
            $decoded=Decode-Base64 $body; $at=$decoded.LastIndexOf('@'); $cred=$decoded.Substring(0,$at);$server=$decoded.Substring($at+1)
        }
        try{$cred=Decode-Base64 $cred}catch{}
        $c=$cred.Split(':',2);$hp=$server.Split(':'); return New-Profile (Get-Or $name $hp[0]) 'shadowsocks' $hp[0] ([int]$hp[-1]) @{method=$c[0];password=$c[1]} $Link
    }
    $u=[Uri]$Link; $q=Parse-Query $u.Query
    $name=if($u.Fragment){[Uri]::UnescapeDataString($u.Fragment.TrimStart('#'))}else{"$($u.Host):$($u.Port)"}
    $user=[Uri]::UnescapeDataString($u.UserInfo)
    return New-Profile $name $scheme $u.Host $u.Port @{
        id=$user; password=$user; network=(Get-Or $q.type 'tcp'); security=(Get-Or $q.security 'none')
        flow=$q.flow; sni=$q.sni; publicKey=$q.pbk; shortId=$q.sid; fingerprint=(Get-Or $q.fp 'chrome')
        path=$q.path; hostHeader=$q.host; serviceName=$q.serviceName
    } $Link
}
function Parse-SubscriptionBody([string]$Body) {
    $text=$Body.Trim()
    if($text -notmatch '(?m)^(vless|vmess|trojan|ss|socks)://'){
        try{$text=Decode-Base64 $text}catch{}
    }
    if($text.TrimStart() -match '^[\[{]'){
        return Parse-XrayJsonSubscription $text
    }
    $items=@()
    $parseErrors=@()
    foreach($line in ($text -split "[`r`n]+")){
        if($line.Trim() -match '^(vless|vmess|trojan|ss|socks)://'){
            try{$items += ,(Parse-ProxyLink $line.Trim())}catch{$parseErrors += $_.Exception.Message}
        }
    }
    if(-not $items.Count -and $parseErrors.Count){throw $parseErrors[0]}
    return $items
}
function Parse-XrayJsonSubscription([string]$Text) {
    try{$configs=$Text|ConvertFrom-Json}catch{throw 'Некорректная JSON-подписка.'}
    $result=@()
    foreach($config in $configs){
        $proxy=@($config.outbounds|?{$_.protocol -in @('vless','vmess','trojan','shadowsocks','socks')})|Select-Object -First 1
        if(-not $proxy){continue}
        $protocol=$proxy.protocol
        $serverAddress='';$port=0;$extra=@{isJson=$true}
        if($protocol -in @('vless','vmess')){
            $server=$proxy.settings.vnext[0];$serverAddress=$server.address;$port=[int]$server.port
            $extra.id=$server.users[0].id
        }else{
            $server=$proxy.settings.servers[0];$serverAddress=$server.address;$port=[int]$server.port
            $extra.password=$server.password
        }
        $name=Get-Or $config.remarks "$serverAddress`:$port"
        $raw=$config|ConvertTo-Json -Depth 100 -Compress
        $result+=,(New-Profile $name $protocol $serverAddress $port $extra $raw)
    }
    return $result
}
function ConvertFrom-YamlScalar([string]$Value) {
    $v=$Value.Trim()
    if(($v.StartsWith('"') -and $v.EndsWith('"')) -or ($v.StartsWith("'") -and $v.EndsWith("'"))){
        $v=$v.Substring(1,$v.Length-2)
    }
    return $v.Replace('\"','"').Replace("''","'")
}
function Parse-ClashYaml([string]$Body) {
    $profiles=@()
    $inside=$false
    $current=$null
    foreach($rawLine in ($Body -split "[`r`n]+")){
        if($rawLine -match '^proxies:\s*$'){$inside=$true;continue}
        if($inside -and $rawLine -match '^[A-Za-z0-9_-]+:\s*$'){break}
        if(-not $inside){continue}
        if($rawLine -match '^\s*-\s+name:\s*(.+)$'){
            if($current){$profiles+=,$current}
            $current=@{name=(ConvertFrom-YamlScalar $Matches[1])}
            continue
        }
        if($current -and $rawLine -match '^\s+([A-Za-z0-9_-]+):\s*(.*)$'){
            $current[$Matches[1]]=ConvertFrom-YamlScalar $Matches[2]
        }
    }
    if($current){$profiles+=,$current}
    $result=@()
    foreach($y in $profiles){
        if($y.type -notin @('vless','vmess','trojan','ss','socks5')){continue}
        $protocol=if($y.type -eq 'ss'){'shadowsocks'}elseif($y.type -eq 'socks5'){'socks'}else{$y.type}
        $security=if($y.ContainsKey('reality-opts')){'reality'}elseif($y.tls -eq 'true'){'tls'}else{'none'}
        $extra=@{
            id=$y.uuid; password=(Get-Or $y.password $y.uuid)
            network=(Get-Or $y.network 'tcp'); security=$security
            flow=$y.flow; sni=(Get-Or $y.servername $y.sni)
            publicKey=$y.'public-key'; shortId=$y.'short-id'
            fingerprint=(Get-Or $y.'client-fingerprint' 'chrome')
            path=$y.path; hostHeader=$y.host; serviceName=$y.'grpc-service-name'
            method=$y.cipher
        }
        $result+=,(New-Profile $y.name $protocol $y.server ([int]$y.port) $extra '')
    }
    return $result
}
function Add-AppLog([string]$Message) {
    $line="$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [Luna] $Message"
    try{Add-Content -Encoding UTF8 -Path $LogFile -Value $line}catch{}
}
function Get-NetworkTotals {
    try{
        $totals=[LunaTrafficMeter]::GetTotals()
        return @{received=[int64]$totals.ReceivedBytes;sent=[int64]$totals.SentBytes}
    }catch{
        return @{received=[int64]0;sent=[int64]0}
    }
}
function Get-SystemNetworkTotals {
    try{
        $totals=[LunaSystemTrafficMeter]::GetTotals()
        return @{received=[int64]$totals.ReceivedBytes;sent=[int64]$totals.SentBytes}
    }catch{
        return @{received=[int64]0;sent=[int64]0}
    }
}
function Update-SystemTrafficStatistics {
    $now=Get-Date
    $totals=Get-SystemNetworkTotals
    if(-not $script:SystemNetworkStart){
        $script:SystemNetworkStart=$totals
        $script:SystemNetworkLast=$totals
        $script:SystemNetworkLastAt=$now
    }
    $seconds=[Math]::Max([double]0.1,[double](($now-$script:SystemNetworkLastAt).TotalSeconds))
    # Keep cumulative network counters in Int64. Passing an Int32 literal as the
    # first Math.Max argument makes PowerShell select the Int32 overload and
    # throws as soon as a counter grows beyond 2 GB.
    [int64]$receivedDelta=[int64]$totals.received-[int64]$script:SystemNetworkLast.received
    [int64]$sentDelta=[int64]$totals.sent-[int64]$script:SystemNetworkLast.sent
    if($receivedDelta -lt 0){$receivedDelta=[int64]0}
    if($sentDelta -lt 0){$sentDelta=[int64]0}
    $down=$receivedDelta*8/$seconds/1MB
    $up=$sentDelta*8/$seconds/1MB
    $SystemDownSpeed.Text="↓ $([Math]::Round($down,1)) Mbps"
    $SystemUpSpeed.Text="↑ $([Math]::Round($up,1)) Mbps"
    [int64]$systemReceived=[int64]$totals.received-[int64]$script:SystemNetworkStart.received
    [int64]$systemSent=[int64]$totals.sent-[int64]$script:SystemNetworkStart.sent
    if($systemReceived -lt 0){$systemReceived=[int64]0}
    if($systemSent -lt 0){$systemSent=[int64]0}
    $SystemTrafficTotal.Text="За время работы Luna: ↓ $(Format-Bytes $systemReceived) · ↑ $(Format-Bytes $systemSent)"
    $script:SystemNetworkLast=$totals
    $script:SystemNetworkLastAt=$now
}
function Format-Bytes([double]$Value) {
    if($Value -ge 1GB){return "$([Math]::Round($Value/1GB,2)) ГБ"}
    if($Value -ge 1MB){return "$([Math]::Round($Value/1MB,1)) МБ"}
    if($Value -ge 1KB){return "$([Math]::Round($Value/1KB,1)) КБ"}
    return "$([Math]::Round($Value)) Б"
}
function Update-SessionStatistics {
    if(-not $script:ConnectedAt -or -not $script:NetworkStart){return}
    $now=Get-Date;$totals=Get-NetworkTotals
    $sample=[pscustomobject]@{time=$now;received=[int64]$totals.received;sent=[int64]$totals.sent}
    $script:SpeedSamples=@($script:SpeedSamples|Where-Object {($now-$_.time).TotalSeconds -le 4})+@($sample)
    $baseline=$script:SpeedSamples|Select-Object -First 1
    $seconds=[Math]::Max([double]0.1,[double](($now-$baseline.time).TotalSeconds))
    $down=[Math]::Max([double]0,[double](($totals.received-$baseline.received)*8/$seconds/1MB))
    $up=[Math]::Max([double]0,[double](($totals.sent-$baseline.sent)*8/$seconds/1MB))
    $DownSpeed.Text="↓ $([Math]::Round($down,1)) Mbps";$UpSpeed.Text="↑ $([Math]::Round($up,1)) Mbps"
    $HomeDownSpeed.Text=$DownSpeed.Text;$HomeUpSpeed.Text=$UpSpeed.Text
    $ReceivedTotal.Text="Получено: $(Format-Bytes ($totals.received-$script:NetworkStart.received))"
    $SentTotal.Text="Передано: $(Format-Bytes ($totals.sent-$script:NetworkStart.sent))"
    $apps=@([LunaTrafficMeter]::GetApplications()|ForEach-Object{
        [pscustomobject]@{
            name=$_.ProcessName
            pid=$_.ProcessId
            received=Format-Bytes $_.ReceivedBytes
            sent=Format-Bytes $_.SentBytes
            total=Format-Bytes $_.TotalBytes
            connections=$_.ActiveConnections
        }
    })
    $AppsTraffic.ItemsSource=$apps
    $AppsSummary.Text=if($apps.Count){"Приложений: $($apps.Count) · учтён только трафик, реально прошедший через Luna"}else{'Ожидаем трафик приложений через Luna…'}
    $script:NetworkLast=$totals;$script:NetworkLastAt=$now
}
function Write-AtomicJson([string]$Path,$Value) {
    $temporary="$Path.$([guid]::NewGuid().ToString('N')).tmp"
    try{
        ConvertTo-Json -InputObject $Value -Depth 30|Set-Content -Encoding UTF8 -LiteralPath $temporary
        Move-Item -LiteralPath $temporary -Destination $Path -Force
    }finally{
        if(Test-Path -LiteralPath $temporary){Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue}
    }
}
function ConvertFrom-LunaJson([string]$Json) {
    $parsed=$Json|ConvertFrom-Json
    if($parsed -is [array]){$parsed|ForEach-Object{$_}}else{$parsed}
}
function ConvertTo-LocalProfile($Server,[string]$Source='local-config') {
    if(-not $Server.id -or -not $Server.name -or -not $Server.host){throw 'В описании сервера отсутствует id, name или host.'}
    $enabled=if($null -eq $Server.enabled){$true}else{[bool]$Server.enabled}
    $available=if($null -eq $Server.available){$true}else{[bool]$Server.available}
    $status=if(-not $enabled){'Отключён'}elseif($Source -eq 'backend-api' -and -not $available){'Недоступен'}elseif($Source -eq 'backend-api'){'Сервис Luna'}else{'Локальная конфигурация'}
    $health=if(-not $enabled -or -not $available){'Недоступен'}elseif($Source -eq 'backend-api'){'Доступен'}else{$status}
    $latency=if($null -ne $Server.ping -and [string]$Server.ping -match '^\d+$'){"$([int]$Server.ping) ms"}else{'—'}
    return @{
        id=[string]$Server.id;name=[string]$Server.name;country=[string]$Server.country;city=[string]$Server.city
        host=[string]$Server.host;port=[int](Get-Or $Server.port 443);protocol=[string](Get-Or $Server.protocol 'vless')
        enabled=$enabled;source=$Source;status=$status;healthStatus=$health;available=$available
        latency=$latency;favorite=$false;subscriptionId='';raw=[string]$Server.config
        backendLoad=$Server.load;backendUpdatedAt=[string]$Server.updatedAt
        extra=@{
            id=[string]$Server.uuid;password=[string]$Server.password
            network=[string](Get-Or $Server.network 'tcp');security=[string](Get-Or $Server.security 'none')
            flow=[string]$Server.flow;sni=[string](Get-Or $Server.sni $Server.serverName)
            publicKey=[string]$Server.publicKey;shortId=[string]$Server.shortId;spiderX=[string](Get-Or $Server.spiderX '/')
            fingerprint=[string](Get-Or $Server.fingerprint 'chrome')
            path=[string]$Server.path;hostHeader=[string]$Server.hostHeader;serviceName=[string]$Server.serviceName
        }
    }
}
function Replace-BackendProfiles($Profiles) {
    $items=@($Profiles)
    if(-not $items.Count){return 0}
    $ids=@{};foreach($item in $items){$ids[[string]$item.id]=$true}
    $preserved=@($State.profiles|?{$_.source -ne 'backend-api' -and -not $ids.ContainsKey([string]$_.id)})
    $State.profiles=@($preserved)+@($items)
    if(-not @($State.profiles|?{$_.id -eq $State.selectedId}).Count){
        $State.selectedId=[string]$State.profiles[0].id
    }
    return $items.Count
}
function Load-BackendServerCache {
    if(-not (Test-Path -LiteralPath $BackendServerCacheFile)){return 0}
    try{
        $cached=@(ConvertFrom-LunaJson (Get-Content -Raw -Encoding UTF8 -LiteralPath $BackendServerCacheFile))
        $profiles=@()
        foreach($server in $cached){
            try{$profiles+=,(ConvertTo-LocalProfile $server 'backend-api')}catch{Add-AppLog "Пропущен сервер из кэша: $($_.Exception.Message)"}
        }
        if(-not $profiles.Count){return 0}
        $count=Replace-BackendProfiles $profiles
        Add-AppLog "Загружен резервный кэш backend: $count серверов"
        return $count
    }catch{
        Add-AppLog "Ошибка кэша backend: $($_.Exception.Message)"
        return 0
    }
}
function Initialize-ServerCatalog {
    $catalog=Join-Path $AppRoot 'servers.json'
    $cached=Load-BackendServerCache
    if($cached){
        $script:ServerLoadState='success'
        $script:ServerLoadMessage="Последний кэш backend: $cached серверов. Выполняется обновление…"
    }
    $loaded=0
    if(Test-Path $catalog){
        try{
            $json=Get-Content -Raw -Encoding UTF8 $catalog|ConvertFrom-Json
            foreach($server in @($json)){
                $profile=ConvertTo-LocalProfile $server 'local-config'
                $State.profiles=@($State.profiles|?{$_.id -ne $profile.id})
                $State.profiles+=,$profile;$loaded++
            }
            Add-AppLog "servers.json загружен, серверов: $loaded"
        }catch{
            Add-AppLog "Ошибка servers.json: $($_.Exception.Message)"
        }
    }
    $legacyCount=@($State.profiles|?{$_.id -eq 'luna-main-ru-1' -or $_.source -eq 'local-fallback'}).Count
    $State.profiles=@($State.profiles|?{$_.id -ne 'luna-main-ru-1' -and $_.source -ne 'local-fallback'})
    if($legacyCount){Add-AppLog "Удалено устаревших встроенных профилей: $legacyCount"}
    if($script:ServerLoadState -eq 'loading'){
        if(@($State.profiles).Count){
            $script:ServerLoadState='success'
            $script:ServerLoadMessage='Используются сохранённые профили. Выполняется обновление backend…'
        }else{
            $script:ServerLoadState='empty'
            $script:ServerLoadMessage='Локальный список пуст. Выполняется запрос к backend Luna…'
        }
    }
    if(-not @($State.profiles).Count){
        $script:ServerLoadState='empty';$script:ServerLoadMessage='Список серверов пуст.'
        Add-AppLog 'Список серверов пуст.'
    }else{Add-AppLog "Всего серверов в состоянии: $(@($State.profiles).Count)"}
    Save-State
}

function Build-StreamSettings($p) {
    $e=$p.extra; $network=if($e.network){$e.network}else{'tcp'}
    $s=@{network=$network; security=if($e.security -in @('tls','reality')){$e.security}else{'none'}}
    if($network -eq 'ws'){$s.wsSettings=@{path=(Get-Or $e.path '/');headers=@{Host=$e.hostHeader}}}
    if($network -eq 'grpc'){$s.grpcSettings=@{serviceName=$e.serviceName}}
    if($s.security -eq 'tls'){$s.tlsSettings=@{serverName=$e.sni;fingerprint=$e.fingerprint}}
    if($s.security -eq 'reality'){$s.realitySettings=@{serverName=$e.sni;publicKey=$e.publicKey;shortId=$e.shortId;fingerprint=$e.fingerprint;spiderX=(Get-Or $e.spiderX '/')}}
    return $s
}
function Protect-AnonymousReportText([string]$Text) {
    if([string]::IsNullOrWhiteSpace($Text)){return ''}
    $safe=[string]$Text
    $safe=$safe -replace '(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b','[UUID]'
    $safe=$safe -replace '(?i)\b(?:https?|vless|vmess|trojan|ss|socks5)://\S+','[LINK]'
    $safe=$safe -replace '(?i)\b(?:\d{1,3}\.){3}\d{1,3}\b','[IP]'
    $safe=$safe -replace '(?i)\b(?:[0-9a-f]{0,4}:){2,}[0-9a-f:]{0,4}\b','[IP]'
    $safe=$safe -replace '(?i)[A-Z]:\\Users\\[^\\\s]+','C:\Users\[USER]'
    $safe=$safe -replace '(?i)\b(privatekey|publickey|shortid|token|password|uuid)\s*[:=]\s*[^\s;,]+','$1=[REDACTED]'
    if($safe.Length -gt 6000){$safe=$safe.Substring(0,6000)}
    return $safe
}
function Send-AnonymousErrorReport([string]$Title,[string]$Message,[string]$Module='Desktop') {
    if(-not [bool]$script:State.settings.anonymousStats){return}
    try{
        $safeTitle=Protect-AnonymousReportText $Title
        $safeMessage=Protect-AnonymousReportText $Message
        $fingerprint="$safeTitle|$safeMessage"
        if($script:LastAnonymousReportFingerprint -eq $fingerprint -and $script:LastAnonymousReportAt -and ((Get-Date)-$script:LastAnonymousReportAt).TotalSeconds -lt 60){return}
        $script:LastAnonymousReportFingerprint=$fingerprint
        $script:LastAnonymousReportAt=Get-Date
        if(-not $script:AnonymousReportClient){
            $script:AnonymousReportClient=New-Object Net.Http.HttpClient
            $script:AnonymousReportClient.Timeout=[TimeSpan]::FromSeconds(12)
        }
        $pending=@()
        foreach($entry in @($script:AnonymousReportTasks)){
            if($entry.Task.IsCompleted){
                try{$response=$entry.Task.GetAwaiter().GetResult();$response.Dispose()}catch{}
                try{$entry.Content.Dispose()}catch{}
            }else{$pending+=,$entry}
        }
        $script:AnonymousReportTasks=$pending
        if($script:AnonymousReportTasks.Count -ge 8){return}
        $payload=[ordered]@{
            app='Luna';version=$AppVersion;windows=[Environment]::OSVersion.VersionString
            error='LUNA_DESKTOP_ERROR';module=(Protect-AnonymousReportText $Module)
            log="$safeTitle — $safeMessage"
        }|ConvertTo-Json -Compress
        $content=New-Object Net.Http.StringContent -ArgumentList ($payload,[Text.Encoding]::UTF8,'application/json')
        $task=$script:AnonymousReportClient.PostAsync("$DefaultBackendBaseUrl/api/error-report",$content)
        $script:AnonymousReportTasks+=,@{Task=$task;Content=$content}
        Add-AppLog '[INFO] Анонимный диагностический отчёт поставлен в очередь.'
    }catch{Add-AppLog '[WARN] Не удалось поставить анонимный отчёт в очередь.'}
}
function Get-LunaRoutingRules {
    $rules=@()
    if($State.settings.mode -eq 'TUN'){
        $rules+=@{type='field';inboundTag=@('tun-in');process=@('self/','xray/');outboundTag='direct'}
    }
    if($State.settings.bypassLan){$rules+=@{type='field';ip=@('geoip:private');outboundTag='direct'}}
    if($State.settings.blockAds){$rules+=@{type='field';domain=@('geosite:category-ads-all');outboundTag='block'}}
    $block=@([string]$State.settings.blockDomains -split '[,;\r\n]+'|ForEach-Object {$_.Trim()}|Where-Object {$_}|ForEach-Object {'domain:'+($_ -replace '^\*\.','')})
    if($block.Count){$rules+=@{type='field';domain=$block;outboundTag='block'}}
    $direct=@()
    $direct+=@([string]$State.settings.directDomains -split '[,;\r\n]+'|ForEach-Object {$_.Trim()}|Where-Object {$_})
    if([bool]$State.settings.splitEnabled){$direct+=@($State.settings.splitDomains)}
    $direct=@($direct|ForEach-Object {([string]$_).Trim()}|Where-Object {$_}|ForEach-Object {'domain:'+($_ -replace '^\*\.','')}|Select-Object -Unique)
    if($direct.Count){$rules+=@{type='field';domain=$direct;outboundTag='direct'}}
    if([bool]$State.settings.splitEnabled){
        $ips=@($State.settings.splitIps|ForEach-Object {([string]$_).Trim()}|Where-Object {$_}|Select-Object -Unique)
        if($ips.Count){$rules+=@{type='field';ip=$ips;outboundTag='direct'}}
        if($State.settings.mode -eq 'TUN'){
            $processes=@($State.settings.splitApps+$State.settings.splitGames|ForEach-Object {([string]$_).Trim().Replace('\','/')}|Where-Object {$_}|Select-Object -Unique)
            if($processes.Count){$rules+=@{type='field';inboundTag=@('tun-in');process=$processes;outboundTag='direct'}}
        }
    }
    return $rules
}
function Add-LunaTunInbound($inbounds) {
    $result=@($inbounds|Where-Object {(Get-LunaObjectValue $_ 'tag') -ne 'tun-in' -and (Get-LunaObjectValue $_ 'protocol') -ne 'tun'})
    if($State.settings.mode -ne 'TUN'){return $result}
    $gateway=@('172.19.0.1/30')
    $routes=@('0.0.0.0/0')
    if([bool]$State.settings.enableIPv6){$gateway+=,'fdfe:dcba:9876::1/126';$routes+=,'::/0'}
    $dnsServers=@([string]$State.settings.dns -split '[,; ]+'|Where-Object {$_})
    if(-not $dnsServers.Count){$dnsServers=@('1.1.1.1')}
    $result+=@{
        tag='tun-in';protocol='tun'
        settings=@{name='Luna';mtu=1500;gateway=$gateway;dns=$dnsServers;autoSystemRoutingTable=$routes;autoOutboundsInterface='auto'}
        sniffing=@{enabled=$true;destOverride=@('http','tls','quic');routeOnly=$true}
    }
    return $result
}
function Build-XrayConfig($p,[int]$InboundPort=0) {
    $e=$p.extra
    $basePort=if($InboundPort -gt 0){$InboundPort}else{[int]$State.settings.localPort}
    if($e.isJson -and $p.raw){
        $jsonConfig=ConvertTo-Hashtable ($p.raw|ConvertFrom-Json)
        Set-LunaObjectValue $jsonConfig 'log' @{loglevel='warning';access=$LogFile;error=$LogFile}
        $jsonInbounds=@(Get-LunaObjectValue $jsonConfig 'inbounds' @())
        foreach($inbound in $jsonInbounds){
            if((Get-LunaObjectValue $inbound 'protocol') -eq 'socks'){Set-LunaObjectValue $inbound 'port' $basePort;Set-LunaObjectValue $inbound 'listen' '127.0.0.1'}
            if((Get-LunaObjectValue $inbound 'protocol') -eq 'http'){Set-LunaObjectValue $inbound 'port' ($basePort+1);Set-LunaObjectValue $inbound 'listen' '127.0.0.1'}
        }
        Set-LunaObjectValue $jsonConfig 'inbounds' @(Add-LunaTunInbound $jsonInbounds)
        $jsonOutbounds=@(Get-LunaObjectValue $jsonConfig 'outbounds' @())
        if(-not $jsonOutbounds.Count){throw 'JSON-профиль не содержит outbound.'}
        # Select-Object already returns the selected outbound object. Wrapping it
        # in @() turns it into Object[]; assigning `.tag` to that array fails for
        # JSON subscription profiles whose outbound did not already have a tag.
        $proxyOutbound=$jsonOutbounds|Where-Object {(Get-LunaObjectValue $_ 'protocol') -notin @('freedom','blackhole')}|Select-Object -First 1
        if($proxyOutbound){Set-LunaObjectValue $proxyOutbound 'tag' 'proxy'}
        if(-not @($jsonOutbounds|Where-Object {(Get-LunaObjectValue $_ 'tag') -eq 'direct'}).Count){$jsonOutbounds+=,@{protocol='freedom';tag='direct'}}
        if(-not @($jsonOutbounds|Where-Object {(Get-LunaObjectValue $_ 'tag') -eq 'block'}).Count){$jsonOutbounds+=,@{protocol='blackhole';tag='block'}}
        Set-LunaObjectValue $jsonConfig 'outbounds' $jsonOutbounds
        $jsonRouting=Get-LunaObjectValue $jsonConfig 'routing'
        if(-not $jsonRouting){$jsonRouting=@{domainStrategy='IPIfNonMatch';rules=@()};Set-LunaObjectValue $jsonConfig 'routing' $jsonRouting}
        Set-LunaObjectValue $jsonRouting 'domainStrategy' 'IPIfNonMatch'
        $existingRules=@(Get-LunaObjectValue $jsonRouting 'rules' @())
        Set-LunaObjectValue $jsonRouting 'rules' (@(Get-LunaRoutingRules)+$existingRules)
        return $jsonConfig
    }
    switch($p.protocol){
        'vless' {$out=@{protocol='vless';settings=@{vnext=@(@{address=$p.host;port=$p.port;users=@(@{id=$e.id;encryption='none';flow=$e.flow})})};streamSettings=Build-StreamSettings $p}}
        'vmess' {$out=@{protocol='vmess';settings=@{vnext=@(@{address=$p.host;port=$p.port;users=@(@{id=$e.id;alterId=[int]$e.aid;security='auto'})})};streamSettings=Build-StreamSettings $p}}
        'trojan' {$out=@{protocol='trojan';settings=@{servers=@(@{address=$p.host;port=$p.port;password=$e.password})};streamSettings=Build-StreamSettings $p}}
        'shadowsocks' {$out=@{protocol='shadowsocks';settings=@{servers=@(@{address=$p.host;port=$p.port;method=$e.method;password=$e.password})}}}
        'socks' {$out=@{protocol='socks';settings=@{servers=@(@{address=$p.host;port=$p.port;users=@(@{user=$e.id;pass=$e.password})})}}}
    }
    $out.tag='proxy'
    $inbounds=@(@{listen='127.0.0.1';port=$basePort;protocol='socks';settings=@{udp=$false}})
    $httpPort=$basePort+1
    $inbounds+=@{listen='127.0.0.1';port=$httpPort;protocol='http';settings=@{}}
    $inbounds=@(Add-LunaTunInbound $inbounds)
    $rules=@(Get-LunaRoutingRules)
    return @{
        log=@{loglevel='warning';access=$LogFile;error=$LogFile}
        dns=@{servers=@($State.settings.dns,'localhost')}
        inbounds=$inbounds
        outbounds=@($out,@{protocol='freedom';tag='direct'},@{protocol='blackhole';tag='block'})
        routing=@{domainStrategy='IPIfNonMatch';rules=$rules}
        policy=@{system=@{statsInboundUplink=$true;statsInboundDownlink=$true}}
        stats=@{}
    }
}
function Set-SystemProxy([bool]$Enabled) {
    $path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    Set-ItemProperty $path ProxyEnable ([int]$Enabled)
    if($Enabled){Set-ItemProperty $path ProxyServer "127.0.0.1:$([int]$State.settings.localPort+1)";Set-ItemProperty $path ProxyOverride '<local>'}
    Add-Type @'
using System; using System.Runtime.InteropServices;
public class WinInet { [DllImport("wininet.dll")] public static extern bool InternetSetOption(IntPtr h,int o,IntPtr b,int l); }
'@ -ErrorAction SilentlyContinue
    [WinInet]::InternetSetOption([IntPtr]::Zero,39,[IntPtr]::Zero,0)|Out-Null
    [WinInet]::InternetSetOption([IntPtr]::Zero,37,[IntPtr]::Zero,0)|Out-Null
}

$xamlText=@'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" Title="Luna" Width="1120" Height="720" MinWidth="920" MinHeight="600" WindowStartupLocation="CenterScreen" Background="#050719" Foreground="#FAF9FF" FontFamily="Segoe UI">
 <Window.Resources>
  <SolidColorBrush x:Key="{x:Static SystemColors.WindowBrushKey}" Color="#101333"/>
  <SolidColorBrush x:Key="{x:Static SystemColors.ControlBrushKey}" Color="#101333"/>
  <SolidColorBrush x:Key="{x:Static SystemColors.HighlightBrushKey}" Color="#7658E8"/>
  <SolidColorBrush x:Key="{x:Static SystemColors.HighlightTextBrushKey}" Color="#FFFFFF"/>
  <SolidColorBrush x:Key="{x:Static SystemColors.ControlTextBrushKey}" Color="#F8F9FF"/>
  <Style TargetType="TextBlock"><Setter Property="Foreground" Value="#F8F9FF"/></Style>
  <Style TargetType="Button">
   <Setter Property="Foreground" Value="#FAF9FF"/><Setter Property="Background" Value="#171B42"/><Setter Property="BorderThickness" Value="0"/><Setter Property="Padding" Value="14,9"/><Setter Property="Margin" Value="4"/><Setter Property="Cursor" Value="Hand"/>
   <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button"><Border Name="ButtonBorder" Background="{TemplateBinding Background}" CornerRadius="9" Padding="{TemplateBinding Padding}"><ContentPresenter HorizontalAlignment="{TemplateBinding HorizontalContentAlignment}" VerticalAlignment="Center"/></Border><ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="ButtonBorder" Property="Background" Value="#343A5B"/></Trigger><Trigger Property="IsPressed" Value="True"><Setter TargetName="ButtonBorder" Property="Background" Value="#5147B8"/></Trigger><Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.55"/></Trigger></ControlTemplate.Triggers></ControlTemplate></Setter.Value></Setter>
  </Style>
  <Style x:Key="CircleButtonStyle" TargetType="Button">
   <Setter Property="Foreground" Value="#FFFFFF"/><Setter Property="Background" Value="#0C1030"/><Setter Property="BorderBrush" Value="#9A7BFF"/><Setter Property="BorderThickness" Value="2"/><Setter Property="Cursor" Value="Hand"/>
   <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button"><Border Name="Circle" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="110"><ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/></Border><ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Circle" Property="Background" Value="#242542"/><Setter TargetName="Circle" Property="BorderBrush" Value="#A89FFF"/></Trigger><Trigger Property="IsPressed" Value="True"><Setter TargetName="Circle" Property="Background" Value="#302B63"/></Trigger></ControlTemplate.Triggers></ControlTemplate></Setter.Value></Setter>
  </Style>
  <Style TargetType="TextBox"><Setter Property="Foreground" Value="#F4F4FA"/><Setter Property="Background" Value="#171A29"/><Setter Property="BorderBrush" Value="#30354E"/><Setter Property="Padding" Value="9"/><Setter Property="Margin" Value="4"/></Style>
  <Style TargetType="ComboBox">
   <Setter Property="Foreground" Value="#FFFFFF"/><Setter Property="Background" Value="#101333"/><Setter Property="BorderBrush" Value="#393B79"/><Setter Property="Padding" Value="10,8"/><Setter Property="Margin" Value="4"/>
   <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="ComboBox"><Grid><ToggleButton Name="Toggle" Focusable="False" IsChecked="{Binding IsDropDownOpen,RelativeSource={RelativeSource TemplatedParent},Mode=TwoWay}" ClickMode="Press"><ToggleButton.Template><ControlTemplate TargetType="ToggleButton"><Border Name="Box" Background="#101333" BorderBrush="#393B79" BorderThickness="1" CornerRadius="9"><Grid><ContentPresenter Margin="10,7,30,7" VerticalAlignment="Center"/><TextBlock Text="⌄" Foreground="#CDBFFF" FontSize="16" HorizontalAlignment="Right" VerticalAlignment="Center" Margin="0,0,11,4"/></Grid></Border><ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="Box" Property="BorderBrush" Value="#9A7BFF"/></Trigger></ControlTemplate.Triggers></ControlTemplate></ToggleButton.Template></ToggleButton><ContentPresenter IsHitTestVisible="False" Content="{TemplateBinding SelectionBoxItem}" ContentTemplate="{TemplateBinding SelectionBoxItemTemplate}" Margin="14,8,34,8" VerticalAlignment="Center"/><Popup Name="Popup" Placement="Bottom" IsOpen="{TemplateBinding IsDropDownOpen}" AllowsTransparency="True" Focusable="False" PopupAnimation="Fade"><Border MinWidth="{Binding ActualWidth,RelativeSource={RelativeSource TemplatedParent}}" MaxHeight="330" Background="#101333" BorderBrush="#56509A" BorderThickness="1" CornerRadius="9" Padding="3"><ScrollViewer><ItemsPresenter/></ScrollViewer></Border></Popup></Grid></ControlTemplate></Setter.Value></Setter>
  </Style>
  <Style TargetType="ComboBoxItem"><Setter Property="Foreground" Value="#FFFFFF"/><Setter Property="Background" Value="#171A29"/><Setter Property="Padding" Value="10,7"/></Style>
  <Style TargetType="ListViewItem"><Setter Property="Foreground" Value="#F5F6FF"/><Setter Property="Padding" Value="6"/><Setter Property="HorizontalContentAlignment" Value="Stretch"/><Setter Property="Template"><Setter.Value><ControlTemplate TargetType="ListViewItem"><Grid><Border Name="SelectionRail" Width="4" HorizontalAlignment="Left" Margin="1,3,0,3" CornerRadius="2" Background="#9A7BFF" Opacity="0"/><Border Name="Row" Margin="8,1,1,1" Padding="{TemplateBinding Padding}" CornerRadius="6"><Border.Background><SolidColorBrush Color="#111421"/></Border.Background><GridViewRowPresenter Content="{TemplateBinding Content}" Columns="{Binding Path=View.Columns,RelativeSource={RelativeSource AncestorType={x:Type ListView}}}"/></Border></Grid><ControlTemplate.Triggers><Trigger Property="IsSelected" Value="True"><Setter TargetName="SelectionRail" Property="Opacity" Value="1"/><Setter TargetName="Row" Property="Background" Value="#4B3E91"/><Setter Property="Foreground" Value="#FEFEFF"/><Setter Property="FontWeight" Value="SemiBold"/></Trigger><Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.5"/></Trigger><EventTrigger RoutedEvent="MouseEnter"><BeginStoryboard><Storyboard><ColorAnimation Storyboard.TargetName="Row" Storyboard.TargetProperty="(Border.Background).(SolidColorBrush.Color)" To="#29275C" Duration="0:0:0.16"/></Storyboard></BeginStoryboard></EventTrigger><EventTrigger RoutedEvent="MouseLeave"><BeginStoryboard><Storyboard><ColorAnimation Storyboard.TargetName="Row" Storyboard.TargetProperty="(Border.Background).(SolidColorBrush.Color)" To="#111421" Duration="0:0:0.22"/></Storyboard></BeginStoryboard></EventTrigger></ControlTemplate.Triggers></ControlTemplate></Setter.Value></Setter></Style>
  <Style TargetType="GridViewColumnHeader"><Setter Property="Foreground" Value="#FFFFFF"/><Setter Property="Background" Value="#252A43"/><Setter Property="Padding" Value="8"/></Style>
  <Style TargetType="ScrollBar"><Setter Property="Background" Value="#090C25"/><Setter Property="Width" Value="11"/><Setter Property="Template"><Setter.Value><ControlTemplate TargetType="ScrollBar"><Grid Background="#090C25"><Track Name="PART_Track" Orientation="{TemplateBinding Orientation}" IsDirectionReversed="True"><Track.DecreaseRepeatButton><RepeatButton Background="Transparent" BorderThickness="0" Command="ScrollBar.PageUpCommand"/></Track.DecreaseRepeatButton><Track.Thumb><Thumb><Thumb.Template><ControlTemplate TargetType="Thumb"><Border Background="#514A91" CornerRadius="5" Margin="2"/></ControlTemplate></Thumb.Template></Thumb></Track.Thumb><Track.IncreaseRepeatButton><RepeatButton Background="Transparent" BorderThickness="0" Command="ScrollBar.PageDownCommand"/></Track.IncreaseRepeatButton></Track></Grid></ControlTemplate></Setter.Value></Setter></Style>
 </Window.Resources>
  <Grid>
  <Grid.ColumnDefinitions><ColumnDefinition Width="210"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
  <Border Background="#090C25" BorderBrush="#25245A" BorderThickness="0,0,1,0">
   <DockPanel Margin="16">
    <ScrollViewer DockPanel.Dock="Top" VerticalScrollBarVisibility="Auto"><StackPanel>
     <Image Name="BrandIcon" Width="76" Height="76" HorizontalAlignment="Left" Stretch="UniformToFill" Margin="0,0,0,10"/>
     <TextBlock Text="Luna" FontSize="29" FontWeight="SemiBold" Foreground="#FFFFFF"/>
     <TextBlock Text="VPN · 1.5.2-release" Foreground="#BCAEFF" Margin="1,0,0,25"/>
     <Button Name="NavHome" Content="◉  Подключение" HorizontalContentAlignment="Left"/>
     <Button Name="NavServers" Content="◫  Серверы" HorizontalContentAlignment="Left"/>
     <Button Name="NavSubs" Content="↻  Подписки" HorizontalContentAlignment="Left"/>
     <Button Name="NavRoutes" Content="⇄  Маршрутизация" HorizontalContentAlignment="Left"/>
     <Button Name="NavLogs" Content="≡  Журнал" HorizontalContentAlignment="Left"/>
     <Button Name="NavStats" Content="▥  Статистика" HorizontalContentAlignment="Left"/>
     <Button Name="NavSplit" Content="⑂  Split Tunneling" ToolTip="Исключения сайтов, IP, приложений и игр" HorizontalContentAlignment="Left"/>
     <Button Name="NavApps" Content="▦  По приложениям" ToolTip="Реальный трафик через Luna" HorizontalContentAlignment="Left"/>
     <Button Name="NavSettings" Content="⚙  Настройки" HorizontalContentAlignment="Left"/>
     <Button Name="NavExperts" Content="◇  Для экспертов" HorizontalContentAlignment="Left"/>
     <Button Name="NavAbout" Content="ⓘ  О программе" HorizontalContentAlignment="Left"/>
    </StackPanel></ScrollViewer>
    <Border DockPanel.Dock="Bottom" Background="#111536" BorderBrush="#292B63" BorderThickness="1" CornerRadius="12" Padding="11"><StackPanel>
     <TextBlock Text="🟢  ЗАЩИТА" Foreground="#BCAEFF" FontWeight="SemiBold"/>
     <TextBlock Name="CoreStatus" Text="● VPN не активен" Foreground="#AEB4CC" Margin="0,6,0,2"/>
     <TextBlock Name="ProtectionDetail" Text="Готово к подключению." FontSize="11" Foreground="#AEB4CC"/>
    </StackPanel></Border>
   </DockPanel>
  </Border>
  <Grid Grid.Column="1" Margin="26">
   <Grid.Background><RadialGradientBrush Center="0.52,0.42" GradientOrigin="0.52,0.42" RadiusX="0.8" RadiusY="0.8"><GradientStop Color="#171348" Offset="0"/><GradientStop Color="#090B24" Offset="0.52"/><GradientStop Color="#050719" Offset="1"/></RadialGradientBrush></Grid.Background>
   <Grid Name="HomePage">
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <StackPanel><TextBlock Text="LUNA · ЗАЩИЩЁННОЕ СОЕДИНЕНИЕ" FontSize="12" Foreground="#BCAEFF"/><TextBlock Text="Ваш маршрут к свободной сети" FontSize="30" FontWeight="SemiBold" Margin="0,4,0,0"/></StackPanel>
    <Grid Grid.Row="1" Margin="0,18,0,12"><Grid.ColumnDefinitions><ColumnDefinition Width="350"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
     <StackPanel HorizontalAlignment="Left" VerticalAlignment="Top" Width="320" Margin="8,0,0,0">
      <Grid Width="250" Height="250"><Ellipse Name="WaveRing" Width="210" Height="210" Stroke="#9A7BFF" StrokeThickness="3" Opacity="0" HorizontalAlignment="Center" VerticalAlignment="Center" RenderTransformOrigin="0.5,0.5"><Ellipse.RenderTransform><ScaleTransform ScaleX="1" ScaleY="1"/></Ellipse.RenderTransform></Ellipse><Button Name="ConnectButton" Width="210" Height="210" Style="{StaticResource CircleButtonStyle}"><StackPanel HorizontalAlignment="Center"><TextBlock Name="ConnectLabel" Text="ПОДКЛЮЧИТЬ" FontSize="17" FontWeight="Bold" HorizontalAlignment="Center"/><TextBlock Name="SessionTime" Text="00:00:00" FontSize="14" Foreground="#C9C5FF" HorizontalAlignment="Center" Margin="0,9,0,0"/></StackPanel></Button></Grid>
      <TextBlock Name="ConnectionStatus" Text="Нет подключения" HorizontalAlignment="Center" FontSize="18" Margin="0,16,0,5"/>
      <TextBlock Name="SelectedServer" Text="Выберите сервер справа" HorizontalAlignment="Center" Foreground="#B8BDD2" TextTrimming="CharacterEllipsis" MaxWidth="310"/>
      <ComboBox Name="QuickServer" Visibility="Collapsed"/>
     </StackPanel>
     <Border Grid.Column="1" Background="#0D102E" BorderBrush="#292B63" BorderThickness="1" CornerRadius="16" Padding="14" Margin="12,0,0,0">
      <Grid><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
       <DockPanel Margin="4,0,4,10"><StackPanel><TextBlock Text="СЕРВЕРЫ" Foreground="#C4C8DC" FontWeight="SemiBold"/><TextBlock Text="Выберите сервер или проверьте задержку" Foreground="#8F96B5" FontSize="11"/></StackPanel><Button Name="HomePingAllButton" Content="⚡ Пинг всех" DockPanel.Dock="Right" VerticalAlignment="Center"/></DockPanel>
       <ListBox Name="HomeServerList" Grid.Row="1" Background="Transparent" BorderThickness="0" ScrollViewer.VerticalScrollBarVisibility="Auto" ScrollViewer.HorizontalScrollBarVisibility="Disabled" ScrollViewer.CanContentScroll="True">
        <ListBox.ItemContainerStyle><Style TargetType="ListBoxItem"><Setter Property="HorizontalContentAlignment" Value="Stretch"/><Setter Property="Foreground" Value="#F5F6FF"/><Setter Property="Padding" Value="0"/><Setter Property="Margin" Value="0,2"/><Setter Property="Template"><Setter.Value><ControlTemplate TargetType="ListBoxItem"><Border Name="ServerRow" Background="#11152F" BorderBrush="#24295C" BorderThickness="1" CornerRadius="10" Padding="11,8"><ContentPresenter/></Border><ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="ServerRow" Property="Background" Value="#202052"/><Setter TargetName="ServerRow" Property="BorderBrush" Value="#7567FF"/></Trigger><Trigger Property="IsSelected" Value="True"><Setter TargetName="ServerRow" Property="Background" Value="#342B72"/><Setter TargetName="ServerRow" Property="BorderBrush" Value="#A89FFF"/><Setter Property="FontWeight" Value="SemiBold"/></Trigger></ControlTemplate.Triggers></ControlTemplate></Setter.Value></Setter></Style></ListBox.ItemContainerStyle>
        <ListBox.ItemTemplate><DataTemplate><Grid><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="80"/><ColumnDefinition Width="42"/></Grid.ColumnDefinitions><StackPanel><TextBlock Text="{Binding name}" TextTrimming="CharacterEllipsis"/><TextBlock Text="{Binding protocol}" Foreground="#9DA5C4" FontSize="11"/></StackPanel><TextBlock Grid.Column="1" Text="{Binding latency}" Foreground="#CDBFFF" VerticalAlignment="Center" HorizontalAlignment="Right"/><Button Grid.Column="2" Content="↻" Tag="{Binding id}" ToolTip="Проверить этот сервер" Width="34" Height="30" Padding="0" Margin="8,0,0,0"/></Grid></DataTemplate></ListBox.ItemTemplate>
       </ListBox>
      </Grid>
     </Border>
    </Grid>
    <Grid Grid.Row="2"><Grid.ColumnDefinitions><ColumnDefinition/><ColumnDefinition Width="1.35*"/><ColumnDefinition/></Grid.ColumnDefinitions>
     <Border Background="#101333" BorderBrush="#292B63" BorderThickness="1" CornerRadius="14" Margin="5" Padding="13"><StackPanel><TextBlock Text="РЕЖИМ" Foreground="#C4C8DC"/><ComboBox Name="HomeModeBox" Margin="0,5,0,0"><ComboBoxItem Content="System proxy"/><ComboBoxItem Content="TUN"/></ComboBox><TextBlock Name="ModeLabel" Text="System proxy" Visibility="Collapsed"/></StackPanel></Border>
     <Border Grid.Column="1" Background="#101333" BorderBrush="#292B63" BorderThickness="1" CornerRadius="14" Margin="5" Padding="13"><Grid><Grid.ColumnDefinitions><ColumnDefinition/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions><StackPanel><TextBlock Text="ЗАДЕРЖКА ВЫБРАННОГО СЕРВЕРА" Foreground="#C4C8DC"/><TextBlock Name="LatencyServerName" Text="Сервер не выбран" Foreground="#9EA5C2" FontSize="11"/><TextBlock Name="LatencyLabel" Text="—" FontSize="20"/><TextBlock Name="LatencyLastCheckedHome" Text="Последняя проверка: ещё не выполнялась" Foreground="#949AB8" FontSize="11"/><CheckBox Name="LatencyAutoRefresh" Content="Автообновление" Margin="4,6,0,0"/></StackPanel><Button Name="LatencyRefreshHome" Grid.Column="1" Content="Обновить" VerticalAlignment="Center"/></Grid></Border>
     <Border Grid.Column="2" Background="#101333" BorderBrush="#292B63" BorderThickness="1" CornerRadius="14" Margin="5" Padding="13"><StackPanel><TextBlock Text="СКОРОСТЬ" Foreground="#C4C8DC"/><TextBlock Name="HomeUpSpeed" Text="↑ 0 Mbps" Foreground="#65E6A7" FontSize="15"/><TextBlock Name="HomeDownSpeed" Text="↓ 0 Mbps" Foreground="#FF6B7A" FontSize="15"/></StackPanel></Border>
    </Grid>
   </Grid>
   <Grid Name="ServersPage" Visibility="Collapsed">
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <DockPanel><TextBlock Text="Серверы" FontSize="30" FontWeight="SemiBold"/><StackPanel Orientation="Horizontal" DockPanel.Dock="Right"><Button Name="RefreshBackendButton" Content="↻ Сервис Luna"/><Button Name="ImportClipboard" Content="Из буфера"/><Button Name="AddLink" Content="+ Добавить"/></StackPanel></DockPanel>
    <TextBox Name="SearchBox" Grid.Row="1" Text="" ToolTip="Поиск по имени, адресу или протоколу"/>
    <Border Grid.Row="2" Background="#101333" CornerRadius="8" Padding="10,7" Margin="4,2,4,8"><TextBlock Name="ServerLoadStatus" Text="Загружаем список серверов…" Foreground="#CDBFFF"/></Border>
    <ListView Name="ServerList" Grid.Row="3" Background="#0B0E29" BorderThickness="0" Margin="4">
     <ListView.View><GridView><GridViewColumn Header="Название" DisplayMemberBinding="{Binding name}" Width="190"/><GridViewColumn Header="Локация" DisplayMemberBinding="{Binding location}" Width="140"/><GridViewColumn Header="Протокол" DisplayMemberBinding="{Binding protocol}" Width="90"/><GridViewColumn Header="Адрес" DisplayMemberBinding="{Binding endpoint}" Width="180"/><GridViewColumn Header="Состояние" DisplayMemberBinding="{Binding status}" Width="170"/><GridViewColumn Header="TCP" DisplayMemberBinding="{Binding latency}" Width="75"/></GridView></ListView.View>
    </ListView>
    <StackPanel Grid.Row="4" Orientation="Horizontal" HorizontalAlignment="Right"><Button Name="PingAllButton" Content="⚡ Проверить все"/><Button Name="PingButton" Content="Проверить выбранный"/><Button Name="DeleteServer" Content="Удалить"/></StackPanel>
   </Grid>
    <Grid Name="SubsPage" Visibility="Collapsed">
     <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <TextBlock Text="Подписки" FontSize="30" FontWeight="SemiBold"/>
    <StackPanel Grid.Row="1" Orientation="Horizontal"><TextBox Name="SubscriptionUrl" Width="560" ToolTip="https://…"/><Button Name="AddSubscription" Content="+ Добавить"/><Button Name="UpdateSubscriptions" Content="Обновить все"/></StackPanel>
    <ListView Name="SubscriptionList" Grid.Row="2" Background="#111421" BorderThickness="0" Margin="4"><ListView.View><GridView><GridViewColumn Header="Название" DisplayMemberBinding="{Binding name}" Width="220"/><GridViewColumn Header="URL" DisplayMemberBinding="{Binding url}" Width="450"/><GridViewColumn Header="Серверов" DisplayMemberBinding="{Binding count}" Width="100"/></GridView></ListView.View></ListView>
    <Button Name="DeleteSubscription" Grid.Row="3" Content="Удалить выбранную подписку" HorizontalAlignment="Right"/>
   </Grid>
   <Grid Name="RoutesPage" Visibility="Collapsed">
    <StackPanel><TextBlock Text="Маршрутизация" FontSize="30" FontWeight="SemiBold" Margin="0,0,0,18"/>
     <TextBlock Text="Домены напрямую (через запятую)"/><TextBox Name="DirectDomains" Height="70" AcceptsReturn="True"/>
     <TextBlock Text="Заблокированные домены (через запятую)" Margin="0,12,0,0"/><TextBox Name="BlockDomains" Height="70" AcceptsReturn="True"/>
     <CheckBox Name="BypassLan" Content="Локальная сеть — напрямую" Margin="5,15"/>
     <CheckBox Name="BlockAds" Content="Блокировать рекламу по geosite" Margin="5"/>
     <Button Name="SaveRoutes" Content="Сохранить правила" Width="180" HorizontalAlignment="Left" Margin="0,20,0,0"/>
    </StackPanel>
   </Grid>
   <Grid Name="LogsPage" Visibility="Collapsed"><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions><TextBlock Text="Журнал" FontSize="30" FontWeight="SemiBold"/><StackPanel Grid.Row="1" Orientation="Horizontal"><ComboBox Name="LogFilter" Width="130"><ComboBoxItem Content="Все"/><ComboBoxItem Content="INFO"/><ComboBoxItem Content="WARN"/><ComboBoxItem Content="ERROR"/></ComboBox><TextBox Name="LogSearch" Width="330" ToolTip="Поиск в журнале"/></StackPanel><RichTextBox Name="LogView" Grid.Row="2" IsReadOnly="True" VerticalScrollBarVisibility="Auto" Background="#0B0E29" Foreground="#EDEEFF" BorderThickness="0" FontFamily="Consolas"/><StackPanel Grid.Row="3" Orientation="Horizontal" HorizontalAlignment="Right"><Button Name="LiveLogButton" Content="Смотреть реал.тайм" Visibility="Collapsed"/><Button Name="ExportLogs" Content="Экспорт"/><Button Name="ClearLogs" Content="Очистить"/></StackPanel></Grid>
   <Grid Name="StatsPage" Visibility="Collapsed"><ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled"><StackPanel>
    <TextBlock Text="Статистика" FontSize="30" FontWeight="SemiBold"/>
    <TextBlock Text="Показатели Luna и всего устройства разделены — значения не смешиваются" Foreground="#9EA5C2" Margin="0,4,0,18"/>
    <WrapPanel>
     <Border Background="#101333" CornerRadius="14" Padding="18" Width="270" Margin="5"><StackPanel><TextBlock Text="ТРАФИК ЧЕРЕЗ LUNA · СКОРОСТЬ" Foreground="#AEB4CC"/><TextBlock Name="UpSpeed" Text="↑ 0 Mbps" Foreground="#65E6A7" FontSize="22"/><TextBlock Name="DownSpeed" Text="↓ 0 Mbps" Foreground="#FF6B7A" FontSize="22"/></StackPanel></Border>
     <Border Background="#101333" CornerRadius="14" Padding="18" Width="270" Margin="5"><StackPanel><TextBlock Text="ТРАФИК ЧЕРЕЗ LUNA · ОБЪЁМ" Foreground="#AEB4CC"/><TextBlock Name="ReceivedTotal" Text="Получено: 0 Б" FontSize="17"/><TextBlock Name="SentTotal" Text="Передано: 0 Б" FontSize="17"/></StackPanel></Border>
     <Border Background="#101333" CornerRadius="14" Padding="18" Width="300" Margin="5"><StackPanel><TextBlock Text="ВЕСЬ ТРАФИК УСТРОЙСТВА" Foreground="#AEB4CC"/><StackPanel Orientation="Horizontal"><TextBlock Name="SystemUpSpeed" Text="↑ 0 Mbps" Foreground="#65E6A7" FontSize="19" Margin="0,0,12,0"/><TextBlock Name="SystemDownSpeed" Text="↓ 0 Mbps" Foreground="#FF6B7A" FontSize="19"/></StackPanel><TextBlock Name="SystemTrafficTotal" Text="За время работы Luna: ↓ 0 Б · ↑ 0 Б" Foreground="#9EA5C2" FontSize="11" Margin="0,7,0,0"/></StackPanel></Border>
    </WrapPanel>
    <Border Background="#101333" CornerRadius="14" Padding="18" Margin="5,18,5,5"><StackPanel><TextBlock Name="StatIPv4" Text="Публичный IPv4: определяется через соединение Luna"/><TextBlock Name="StatCountry" Text="Страна: —"/><TextBlock Name="StatProvider" Text="Провайдер: определяется через соединение Luna"/><TextBlock Name="StatEncryption" Text="Шифрование: —"/></StackPanel></Border>
       <Border Background="#101333" BorderBrush="#292B63" BorderThickness="1" CornerRadius="14" Margin="5,18,5,5" Padding="12">
     <Grid><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="150"/><RowDefinition Height="34"/></Grid.RowDefinitions><DockPanel Margin="6,0,4,8"><TextBlock Text="TCP VPN · 60 СЕК" Foreground="#C4C8DC"/><StackPanel Orientation="Horizontal" DockPanel.Dock="Right"><TextBlock Text="Джиттер: " Foreground="#949AB8"/><TextBlock Name="JitterLabel" Text="—" Foreground="#D7C8FF"/><TextBlock Text="   Потери: " Foreground="#949AB8"/><TextBlock Name="PacketLossLabel" Text="0%" Foreground="#65E6A7"/><TextBlock Name="GraphValue" Text="—" Foreground="#D7C8FF" FontWeight="SemiBold" Margin="14,0,0,0"/></StackPanel></DockPanel><Canvas Name="LatencyCanvas" Grid.Row="1" ClipToBounds="True" Background="#080B24"/><Grid Grid.Row="2"><Grid.ColumnDefinitions><ColumnDefinition Width="70"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions><TextBlock Text="Потери" Foreground="#7F86A5" VerticalAlignment="Center"/><Canvas Name="LossCanvas" Grid.Column="1" Background="#080B24" ClipToBounds="True"/></Grid></Grid>
    </Border>
    <Border Name="RouteQualityCard" Background="#101333" BorderBrush="#4B4295" BorderThickness="1" CornerRadius="14" Margin="5,18,5,26" Padding="18">
     <Grid>
      <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
      <DockPanel>
       <StackPanel Orientation="Horizontal" DockPanel.Dock="Right"><Button Name="RouteBaselineButton" Content="Проверить до подключения" Padding="13,8" ToolTip="Короткая HTTPS-проверка напрямую, без системного прокси Luna"/><Button Name="RouteCheckButton" Content="↻ Проверить" Padding="13,8" IsEnabled="False" ToolTip="Проверить сервисы через текущий VPN-маршрут"/></StackPanel>
       <StackPanel><TextBlock Text="Качество маршрута" FontSize="21" FontWeight="SemiBold"/><TextBlock Text="DNS → TCP → TLS → HTTP → проверка ответа; не speedtest" Foreground="#9EA6C4" FontSize="12" Margin="0,4,0,0"/></StackPanel>
      </DockPanel>
      <TextBlock Name="RouteDisconnectedMessage" Grid.Row="1" Text="Подключитесь к VPN, чтобы проверить маршрут до сервисов." Foreground="#C9C5FF" Margin="0,13,0,3"/>
      <TextBlock Name="RouteComparisonSummary" Grid.Row="2" Text="Сначала можно проверить маршрут без VPN, затем подключиться и сравнить." Foreground="#AEB4CC" Margin="0,3,0,11" TextWrapping="Wrap"/>
      <ItemsControl Name="RouteQualityList" Grid.Row="3">
       <ItemsControl.ItemTemplate><DataTemplate><Border Background="#0B0E29" BorderBrush="#252A5B" BorderThickness="1" CornerRadius="9" Padding="11,9" Margin="0,3"><Grid><Grid.ColumnDefinitions><ColumnDefinition Width="1.25*"/><ColumnDefinition Width="1.05*"/><ColumnDefinition Width="1.05*"/><ColumnDefinition Width="1.05*"/><ColumnDefinition Width="2.2*"/></Grid.ColumnDefinitions><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/></Grid.RowDefinitions><TextBlock Text="{Binding Service}" FontWeight="SemiBold"/><StackPanel Grid.Column="1"><TextBlock Text="БЕЗ VPN" FontSize="9" Foreground="#7F86A5"/><TextBlock Text="{Binding DirectLatencyText}" Foreground="#D8D3FF"/></StackPanel><StackPanel Grid.Column="2"><TextBlock Text="ЧЕРЕЗ VPN" FontSize="9" Foreground="#7F86A5"/><TextBlock Text="{Binding VpnLatencyText}" Foreground="#D8D3FF"/></StackPanel><Border Grid.Column="3" Background="#171B42" CornerRadius="8" Padding="8,5" HorizontalAlignment="Left"><TextBlock Text="{Binding Status}" Foreground="{Binding StatusColor}" FontWeight="SemiBold"/></Border><TextBlock Grid.Column="4" Text="{Binding Detail}" Foreground="#AEB4CC" TextWrapping="Wrap"/><TextBlock Grid.Row="1" Grid.Column="4" Text="{Binding CheckedAtText}" Foreground="#747B9A" FontSize="10" Margin="0,3,0,0"/></Grid></Border></DataTemplate></ItemsControl.ItemTemplate>
      </ItemsControl>
     </Grid>
    </Border>   </StackPanel></ScrollViewer></Grid>
   <Grid Name="SplitPage" Visibility="Collapsed">
    <ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled"><StackPanel>
     <TextBlock Text="Split Tunneling" FontSize="30" FontWeight="SemiBold"/>
     <TextBlock Text="Выбранный трафик идёт напрямую, остальной — через VPN Luna." Foreground="#9EA5C2" Margin="0,4,0,14"/>
     <Border Background="#101333" BorderBrush="#4B4295" BorderThickness="1" CornerRadius="14" Padding="16" Margin="0,0,0,14"><Grid><Grid.ColumnDefinitions><ColumnDefinition/><ColumnDefinition Width="360"/></Grid.ColumnDefinitions><StackPanel><CheckBox Name="SplitEnabled" Content="Включить контролируемое исключение трафика" FontSize="17" FontWeight="SemiBold"/><TextBlock Name="SplitStatus" Text="Выключено. Весь поддерживаемый трафик использует обычный маршрут Luna." Foreground="#AEB4CC" TextWrapping="Wrap" Margin="4,7,18,0"/></StackPanel><StackPanel Grid.Column="1"><TextBlock Text="ОБЛАСТЬ ДЕЙСТВИЯ" Foreground="#BCAEFF" FontSize="11"/><ComboBox Name="SplitScopeBox" Margin="0,6,0,0"><ComboBoxItem Content="System proxy · HTTP/HTTPS приложений"/><ComboBoxItem Content="TUN · весь системный трафик"/></ComboBox></StackPanel></Grid></Border>
     <Grid><Grid.ColumnDefinitions><ColumnDefinition/><ColumnDefinition/></Grid.ColumnDefinitions><Grid.RowDefinitions><RowDefinition/><RowDefinition/></Grid.RowDefinitions>
      <Border Background="#101333" BorderBrush="#292B63" BorderThickness="1" CornerRadius="14" Padding="14" Margin="4"><Grid><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="170"/><RowDefinition Height="Auto"/></Grid.RowDefinitions><TextBlock Text="Сайты" FontSize="19" FontWeight="SemiBold"/><TextBlock Grid.Row="1" Text="Домен и его поддомены будут обходить VPN." Foreground="#9EA5C2" FontSize="11"/><ListBox Name="SplitDomainList" Grid.Row="2" Background="#0B0E29" Margin="0,9"/><StackPanel Grid.Row="3" Orientation="Horizontal"><TextBox Name="SplitDomainInput" Width="220" ToolTip="example.com или *.example.com"/><Button Name="AddSplitDomain" Content="Добавить"/><Button Name="RemoveSplitDomain" Content="Удалить"/></StackPanel></Grid></Border>
      <Border Grid.Column="1" Background="#101333" BorderBrush="#292B63" BorderThickness="1" CornerRadius="14" Padding="14" Margin="4"><Grid><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="170"/><RowDefinition Height="Auto"/></Grid.RowDefinitions><TextBlock Text="IP-адреса" FontSize="19" FontWeight="SemiBold"/><TextBlock Grid.Row="1" Text="Поддерживаются IPv4, IPv6 и CIDR-подсети." Foreground="#9EA5C2" FontSize="11"/><ListBox Name="SplitIpList" Grid.Row="2" Background="#0B0E29" Margin="0,9"/><StackPanel Grid.Row="3" Orientation="Horizontal"><TextBox Name="SplitIpInput" Width="220" ToolTip="203.0.113.7 или 203.0.113.0/24"/><Button Name="AddSplitIp" Content="Добавить"/><Button Name="RemoveSplitIp" Content="Удалить"/></StackPanel></Grid></Border>
      <Border Grid.Row="1" Background="#101333" BorderBrush="#292B63" BorderThickness="1" CornerRadius="14" Padding="14" Margin="4"><Grid><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="170"/><RowDefinition Height="Auto"/></Grid.RowDefinitions><TextBlock Text="Приложения" FontSize="19" FontWeight="SemiBold"/><TextBlock Grid.Row="1" Text="Выберите .exe на диске или уже запущенный процесс." Foreground="#9EA5C2" FontSize="11"/><ListBox Name="SplitAppList" Grid.Row="2" Background="#0B0E29" Margin="0,9"/><WrapPanel Grid.Row="3"><Button Name="AddSplitApp" Content="+ Файл .exe"/><Button Name="AddRunningSplitApp" Content="◉ Запущенный процесс"/><Button Name="RemoveSplitApp" Content="Удалить"/></WrapPanel></Grid></Border>
      <Border Grid.Row="1" Grid.Column="1" Background="#101333" BorderBrush="#292B63" BorderThickness="1" CornerRadius="14" Padding="14" Margin="4"><Grid><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="170"/><RowDefinition Height="Auto"/></Grid.RowDefinitions><TextBlock Text="Игры" FontSize="19" FontWeight="SemiBold"/><TextBlock Grid.Row="1" Text="Выберите .exe игры, launcher или их запущенные процессы." Foreground="#9EA5C2" FontSize="11"/><ListBox Name="SplitGameList" Grid.Row="2" Background="#0B0E29" Margin="0,9"/><WrapPanel Grid.Row="3"><Button Name="AddSplitGame" Content="+ Файл игры"/><Button Name="AddRunningSplitGame" Content="◉ Запущенная игра"/><Button Name="RemoveSplitGame" Content="Удалить"/></WrapPanel></Grid></Border>
     </Grid>
     <Border Background="#0B0E29" BorderBrush="#292B63" BorderThickness="1" CornerRadius="12" Padding="13" Margin="4,12"><StackPanel><TextBlock Text="Правила хранятся только на этом ПК. Luna не отправляет список сайтов, IP и пути к приложениям на сервер." Foreground="#AEB4CC" TextWrapping="Wrap"/><TextBlock Text="System proxy: Luna управляет HTTP/HTTPS только у приложений, использующих системный прокси; остальные приложения уже идут напрямую. UDP в этом режиме не перехватывается. TUN: правила охватывают системные TCP/UDP-соединения, IPv4 и IPv6 и требуют права администратора." Foreground="#FFD580" TextWrapping="Wrap" Margin="0,8,0,0"/></StackPanel></Border>
     <StackPanel Orientation="Horizontal" HorizontalAlignment="Right"><Button Name="ImportSplitRules" Content="Импорт"/><Button Name="ExportSplitRules" Content="Экспорт"/><Button Name="ResetSplitRules" Content="Сбросить"/><Button Name="ApplySplitRules" Content="Применить" Background="#5147B8"/></StackPanel>
    </StackPanel></ScrollViewer>
   </Grid>
   <Grid Name="AppsPage" Visibility="Collapsed"><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions><StackPanel><TextBlock Text="Трафик по приложениям" FontSize="30" FontWeight="SemiBold"/><TextBlock Name="AppsSummary" Text="Ожидаем трафик приложений через Luna…" Foreground="#9EA5C2" Margin="0,5,0,16"/></StackPanel><Border Grid.Row="1" Background="#101333" BorderBrush="#292B63" BorderThickness="1" CornerRadius="14" Padding="10"><ListView Name="AppsTraffic"><ListView.View><GridView><GridViewColumn Header="Приложение" DisplayMemberBinding="{Binding name}" Width="230"/><GridViewColumn Header="PID" DisplayMemberBinding="{Binding pid}" Width="80"/><GridViewColumn Header="Получено" DisplayMemberBinding="{Binding received}" Width="125"/><GridViewColumn Header="Отправлено" DisplayMemberBinding="{Binding sent}" Width="125"/><GridViewColumn Header="Всего" DisplayMemberBinding="{Binding total}" Width="125"/><GridViewColumn Header="Активные соединения" DisplayMemberBinding="{Binding connections}" Width="165"/></GridView></ListView.View></ListView></Border></Grid>
   <Grid Name="SettingsPage" Visibility="Collapsed">
    <ScrollViewer VerticalScrollBarVisibility="Auto"><StackPanel><TextBlock Text="Настройки" FontSize="30" FontWeight="SemiBold" Margin="0,0,0,18"/>
     <TextBlock Text="Интерфейс" FontSize="19" FontWeight="SemiBold"/><TextBlock Text="Язык"/><ComboBox Name="LanguageBox" Width="260" HorizontalAlignment="Left"><ComboBoxItem Content="Русский"/><ComboBoxItem Content="English"/></ComboBox><TextBlock Text="Тема"/><ComboBox Name="ThemeBox" Width="260" HorizontalAlignment="Left"><ComboBoxItem Content="Темная"/><ComboBoxItem Content="Светлая"/><ComboBoxItem Content="Авто"/></ComboBox>
     <TextBlock Text="Режим подключения"/><ComboBox Name="ModeBox" Width="320" HorizontalAlignment="Left"><ComboBoxItem Content="System proxy"/><ComboBoxItem Content="TUN"/></ComboBox>
     <TextBlock Text="Локальный SOCKS-порт" Margin="0,12,0,0"/><TextBox Name="PortBox" Width="260" HorizontalAlignment="Left"/>
     <TextBlock Text="DNS-сервер" Margin="0,12,0,0"/><TextBox Name="DnsBox" Width="260" HorizontalAlignment="Left"/>
     <CheckBox Name="AutoStart" Content="Запускать вместе с Windows" Margin="5,15"/><CheckBox Name="StartMinimized" Content="Запускать и сворачивать в системный трей" Margin="5"/>
     <TextBlock Text="ФУНКЦИИ В РАЗРАБОТКЕ · появятся в следующих обновлениях" Foreground="#FFD166" Margin="4,16,0,6"/>
     <CheckBox Name="AutoConnect" Content="Автоподключение — в разработке" IsEnabled="False"/><CheckBox Name="KillSwitch" Content="Kill Switch — в разработке" IsEnabled="False"/><CheckBox Name="DnsProtection" Content="Расширенная защита DNS — в разработке" IsEnabled="False"/><CheckBox Name="EnableIPv6" Content="Управление IPv6 — в разработке" IsEnabled="False"/><CheckBox Name="WebRtcProtection" Content="Защита WebRTC — в разработке" IsEnabled="False"/><CheckBox Name="DnsLeakProtection" Content="Блокировка утечек DNS — в разработке" IsEnabled="False"/><CheckBox Name="CheckUpdates" Content="Автопроверка обновлений — в разработке" IsEnabled="False"/><CheckBox Name="AnonymousStats" Content="Отправлять анонимные диагностические отчёты"/>
     <StackPanel Orientation="Horizontal" Margin="0,18,0,0"><Button Name="SaveSettings" Content="Сохранить"/><Button Name="InstallCore" Content="Установить Xray-core"/></StackPanel>
     <TextBlock Text="System proxy поддерживает исключения сайтов, IP, приложений и игр для proxy-aware HTTP/HTTPS. TUN перехватывает системный TCP/UDP-трафик. Luna запросит права администратора только для TUN." Foreground="#858BA8" TextWrapping="Wrap" Margin="4,18"/>
    </StackPanel></ScrollViewer>
   </Grid>
   <Grid Name="ExpertsPage" Visibility="Collapsed"><StackPanel><TextBlock Text="Для экспертов" FontSize="30" FontWeight="SemiBold"/><TextBlock Text="Сейчас полностью поддерживается только Xray-core. Остальные движки появятся в следующих обновлениях." TextWrapping="Wrap" Foreground="#FFD166" Margin="4,8,0,18"/><TextBlock Text="Сетевой движок"/><ComboBox Name="EngineBox" Width="390" HorizontalAlignment="Left"><ComboBoxItem Content="Xray-core"/><ComboBoxItem Content="Sing-box — в разработке" IsEnabled="False"/><ComboBoxItem Content="Clash Meta — в разработке" IsEnabled="False"/><ComboBoxItem Content="Hysteria2 — в разработке" IsEnabled="False"/><ComboBoxItem Content="WireGuard — в разработке" IsEnabled="False"/><ComboBoxItem Content="OpenVPN — в разработке" IsEnabled="False"/></ComboBox><TextBlock Name="EngineStatus" Text="● Xray-core установлен" Foreground="#65E6A7" Margin="5,8"/><Button Name="ResetSettings" Content="Сбросить все настройки" Width="220" HorizontalAlignment="Left" Margin="0,25,0,0"/></StackPanel></Grid>
   <Grid Name="AboutPage" Visibility="Collapsed"><ScrollViewer VerticalScrollBarVisibility="Auto"><StackPanel><TextBlock Text="О программе" FontSize="30" FontWeight="SemiBold"/><Image Name="AboutIcon" Width="120" Height="120" HorizontalAlignment="Left" Margin="0,24,0,12"/><TextBlock Text="Luna VPN" FontSize="26"/><TextBlock Text="Версия 1.5.2-release" Foreground="#BCAEFF"/><TextBlock Text="Luna Engine · Xray 26.3.27" Margin="0,16,0,0"/><TextBlock Text="Интерфейс · WPF / .NET Framework"/><TextBlock Text="Сервис Luna обновляет каталог серверов, новости и сведения о версиях. При его недоступности локальные подписки и VPN продолжают работать." TextWrapping="Wrap" Foreground="#9EA5C2" Margin="0,18,0,0"/><Border Background="#101333" BorderBrush="#292B63" BorderThickness="1" CornerRadius="14" Padding="16" Margin="0,18,0,0"><StackPanel><TextBlock Text="СЕРВИС LUNA" Foreground="#BCAEFF" FontWeight="SemiBold"/><TextBlock Name="BackendStatusText" Text="Ожидается синхронизация…" TextWrapping="Wrap" Margin="0,8,0,0"/><TextBlock Name="UpdateStatusText" Text="Версия: проверка не выполнялась" TextWrapping="Wrap" Foreground="#C8CCE0" Margin="0,7,0,0"/><TextBlock Name="LatestNewsText" Text="Новости: —" TextWrapping="Wrap" Foreground="#C8CCE0" Margin="0,7,0,0"/><TextBlock Name="ChangelogStatusText" Text="Изменения: —" TextWrapping="Wrap" Foreground="#C8CCE0" Margin="0,7,0,0"/></StackPanel></Border></StackPanel></ScrollViewer></Grid>
   <Border Name="LoadingOverlay" Panel.ZIndex="50" Background="#D90B0D16" CornerRadius="14" Visibility="Collapsed">
    <StackPanel Width="360" HorizontalAlignment="Center" VerticalAlignment="Center"><TextBlock Name="LoadingText" Text="Загрузка…" FontSize="18" FontWeight="SemiBold" HorizontalAlignment="Center" Margin="0,0,0,14"/><ProgressBar Height="7" IsIndeterminate="True" Foreground="#8C7CFF" Background="#262A43"/></StackPanel>
   </Border>
   <Border Name="ToastPanel" Panel.ZIndex="70" Background="#F0181C3A" BorderBrush="#56509A" BorderThickness="1" CornerRadius="14" Padding="16" Width="420" HorizontalAlignment="Right" VerticalAlignment="Top" Margin="0,18,18,0" Visibility="Collapsed"><StackPanel><DockPanel><TextBlock Name="ToastTitle" Text="Luna" FontWeight="Bold" FontSize="16"/><Button Name="CloseToast" Content="×" DockPanel.Dock="Right" Padding="7,2"/></DockPanel><TextBlock Name="ToastMessage" Text="" TextWrapping="Wrap" Foreground="#D7DAEA" Margin="0,8,0,10"/><Button Name="FixButton" Content="Исправить" HorizontalAlignment="Left" Visibility="Collapsed"/></StackPanel></Border>
  </Grid>
 </Grid>
</Window>
'@

$useLightTheme=$State.settings.theme -eq 'Светлая'
if($State.settings.theme -eq 'Авто'){
    try{$useLightTheme=(Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize').AppsUseLightTheme -eq 1}catch{$useLightTheme=$false}
}
if($useLightTheme){
    $themeMap=[ordered]@{
        '#FFFFFF'='#202038';'#FAF9FF'='#202038';'#F8F9FF'='#202038';'#F5F6FF'='#202038'
        '#F4F5FF'='#202038';'#F4F4FA'='#202038';'#EDEEFF'='#28283F';'#D8DCF0'='#36364D'
        '#D7DAEA'='#45455E';'#D7C8FF'='#5147B8';'#CDBFFF'='#5147B8';'#C9C5FF'='#5147B8'
        '#C8CCE0'='#52526A';'#C4C8DC'='#4A4A62';'#BCAEFF'='#5E4AC2';'#B8BDD2'='#62627A'
        '#AFA5D8'='#5C5674';'#AEB4CC'='#5D5D75';'#A89FFF'='#7658E8';'#9EA5C2'='#686880'
        '#949AB8'='#686880';'#858BA8'='#686880';'#7F86A5'='#62627A';'#747B9A'='#686880'
        '#050719'='#F3F1FA';'#080B24'='#EEEAF8';'#090B24'='#E8E4F4';'#090C25'='#E8E4F4'
        '#0B0E29'='#F7F5FC';'#0C1030'='#EEEAF8';'#101333'='#FFFFFF';'#111421'='#EDE9F7'
        '#111536'='#EDE9F7';'#171348'='#DED8F3';'#171A29'='#F7F5FC';'#171B42'='#E8E4F4'
        '#20254B'='#D7D0E8';'#242542'='#E8E4F4';'#25245A'='#CBC3E5';'#252A43'='#E3DEEF'
        '#262A43'='#E3DEEF';'#29275C'='#D8D0F0';'#292B63'='#CBC3E5';'#302B63'='#D7CFF0'
        '#30354E'='#BDB5D2';'#343A5B'='#C9C1DA';'#393B79'='#AFA2D2';'#514A91'='#7667AE'
        '#55E69D'='#087F52';'#65E6A7'='#087F52';'#74E5B2'='#087F52';'#78E6B4'='#087F52'
        '#FF5D6C'='#C6283C';'#FF6B7A'='#C6283C';'#FF8E9E'='#C6283C';'#FF93A4'='#C6283C'
    }
    $themeTokens=@();$themeIndex=0
    foreach($entry in $themeMap.GetEnumerator()){
        $token="LUNA_THEME_COLOR_$($themeIndex.ToString('D3'))"
        $xamlText=$xamlText.Replace($entry.Key,$token)
        $themeTokens+=,[pscustomobject]@{Token=$token;Color=$entry.Value}
        $themeIndex++
    }
    foreach($entry in $themeTokens){$xamlText=$xamlText.Replace($entry.Token,$entry.Color)}
}
if($State.settings.language -eq 'English'){
    $languageMap=[ordered]@{
        'Подключение'='Connection';'Серверы'='Servers';'Подписки'='Subscriptions';'Маршрутизация'='Routing'
        'Журнал'='Log';'Статистика'='Statistics';'По приложениям'='By application';'Настройки'='Settings'
        'Для экспертов'='For experts';'О программе'='About';'Ваш маршрут к свободной сети'='Your route to the open internet'
        'ПОДКЛЮЧИТЬ'='CONNECT';'Нет подключения'='Not connected';'Выберите сервер'='Select a server'
        'РЕЖИМ'='MODE';'СКОРОСТЬ'='SPEED';'ТЕКУЩАЯ ЗАДЕРЖКА'='CURRENT LATENCY';'ЗАДЕРЖКА · 60 СЕК'='LATENCY · 60 SEC'
        'ТРАФИК ЧЕРЕЗ LUNA'='TRAFFIC THROUGH LUNA';'ДО VPN-СЕРВЕРА · TCP'='TO VPN SERVER · TCP';'TCP ДО VPN-СЕРВЕРА · 60 СЕК'='TCP TO VPN SERVER · 60 SEC'
        'ТРАФИК ЧЕРЕЗ LUNA · СКОРОСТЬ'='TRAFFIC THROUGH LUNA · RATE';'ТРАФИК ЧЕРЕЗ LUNA · ОБЪЁМ'='TRAFFIC THROUGH LUNA · TOTAL'
        'TCP VPN · 60 СЕК'='VPN TCP · 60 SEC';'ВЕСЬ ТРАФИК УСТРОЙСТВА'='ALL DEVICE TRAFFIC'
        'Сейчас'='Now';'Потери'='Loss';'Название'='Name';'Локация'='Location';'Протокол'='Protocol'
        'Адрес'='Address';'Состояние'='Status';'Проверить выбранный'='Check selected';'Удалить'='Delete'
        'Интерфейс'='Interface';'Язык'='Language';'Тема'='Theme';'Темная'='Dark';'Светлая'='Light'
        'Режим подключения'='Connection mode';'Локальный SOCKS-порт'='Local SOCKS port';'DNS-сервер'='DNS server'
        'Сохранить'='Save';'Запускать вместе с Windows'='Start with Windows';'Сворачивать в трей'='Minimize to tray'
        'Автоподключение'='Auto-connect';'Защита DNS'='DNS protection';'Блокировать утечки DNS'='Block DNS leaks'
        'Проверять обновления'='Check for updates';'Отправлять анонимную статистику'='Send anonymous statistics'
        'Экспорт'='Export';'Очистить'='Clear';'Смотреть реал.тайм'='Watch live';'Русский'='Russian';'Авто'='Auto'
        'ЗАДЕРЖКА ВЫБРАННОГО СЕРВЕРА'='SELECTED SERVER LATENCY';'Выберите сервер или проверьте задержку'='Select a server or check latency'
        'Автообновление'='Auto-refresh';'Последняя проверка: ещё не выполнялась'='Last check: not run yet'
        'Сервер не выбран'='No server selected';'Обновить'='Refresh';'Пинг всех'='Ping all';'Требуется перезапуск приложения Luna'='Luna restart required'
    }
    foreach($entry in @($languageMap.GetEnumerator()|Sort-Object {$_.Key.Length} -Descending)){$xamlText=$xamlText.Replace($entry.Key,$entry.Value)}
}
[xml]$xaml=$xamlText
$reader=New-Object System.Xml.XmlNodeReader $xaml
$Window=[Windows.Markup.XamlReader]::Load($reader)
Add-Type @'
using System;
using System.Diagnostics;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
public static class LunaDwm {
 [DllImport("dwmapi.dll")] public static extern int DwmSetWindowAttribute(IntPtr h, int a, ref int v, int s);
}
public static class LunaLatencyProbe {
 public static Task<int> MeasureTcpAsync(string host, int port, int timeoutMs) {
  return Task.Factory.StartNew(() => {
   using (var client = new TcpClient()) {
    var watch = Stopwatch.StartNew();
    try {
     IAsyncResult pending = client.BeginConnect(host, port, null, null);
     using (pending.AsyncWaitHandle) {
      if (!pending.AsyncWaitHandle.WaitOne(timeoutMs)) return -1;
      client.EndConnect(pending);
     }
     watch.Stop();
     return client.Connected ? Math.Max(1, (int)watch.ElapsedMilliseconds) : -1;
    } catch { return -1; }
   }
  });
 }
}
'@ -ErrorAction SilentlyContinue
$Window.Add_SourceInitialized({
    $handle=(New-Object Windows.Interop.WindowInteropHelper($Window)).Handle
    $enabled=1
    [void][LunaDwm]::DwmSetWindowAttribute($handle,20,[ref]$enabled,4)
})
$names=@('HomePage','ServersPage','SubsPage','RoutesPage','LogsPage','StatsPage','SplitPage','AppsPage','SettingsPage','ExpertsPage','AboutPage','BrandIcon','AboutIcon','BackendStatusText','UpdateStatusText','LatestNewsText','ChangelogStatusText','NavHome','NavServers','NavSubs','NavRoutes','NavLogs','NavStats','NavSplit','NavApps','NavSettings','NavExperts','NavAbout','CoreStatus','ProtectionDetail','ConnectButton','ConnectLabel','WaveRing','ConnectionStatus','SelectedServer','QuickServer','HomeServerList','HomePingAllButton','HomeModeBox','SessionTime','ModeLabel','HomeUpSpeed','HomeDownSpeed','LatencyLabel','LatencyServerName','LatencyLastCheckedHome','LatencyRefreshHome','LatencyAutoRefresh','GraphValue','JitterLabel','PacketLossLabel','LatencyCanvas','LossCanvas','RouteQualityCard','RouteBaselineButton','RouteCheckButton','RouteDisconnectedMessage','RouteComparisonSummary','RouteQualityList','LoadingOverlay','LoadingText','ToastPanel','ToastTitle','ToastMessage','CloseToast','FixButton','ServerList','ServerLoadStatus','SearchBox','RefreshBackendButton','ImportClipboard','AddLink','PingAllButton','PingButton','DeleteServer','SubscriptionUrl','AddSubscription','UpdateSubscriptions','SubscriptionList','DeleteSubscription','DirectDomains','BlockDomains','BypassLan','BlockAds','SaveRoutes','LogView','LogFilter','LogSearch','LiveLogButton','ExportLogs','ClearLogs','UpSpeed','DownSpeed','ReceivedTotal','SentTotal','SystemUpSpeed','SystemDownSpeed','SystemTrafficTotal','StatIPv4','StatCountry','StatProvider','StatEncryption','SplitEnabled','SplitStatus','SplitScopeBox','SplitDomainInput','SplitDomainList','AddSplitDomain','RemoveSplitDomain','SplitIpInput','SplitIpList','AddSplitIp','RemoveSplitIp','SplitAppList','AddSplitApp','AddRunningSplitApp','RemoveSplitApp','SplitGameList','AddSplitGame','AddRunningSplitGame','RemoveSplitGame','ApplySplitRules','ExportSplitRules','ImportSplitRules','ResetSplitRules','LanguageBox','ThemeBox','ModeBox','PortBox','DnsBox','AutoStart','StartMinimized','AutoConnect','KillSwitch','DnsProtection','EnableIPv6','WebRtcProtection','DnsLeakProtection','CheckUpdates','AnonymousStats','SaveSettings','InstallCore','EngineBox','EngineStatus','ResetSettings')
foreach($n in $names){Set-Variable -Scope Script -Name $n -Value $Window.FindName($n)}
$script:AppsTraffic=$Window.FindName('AppsTraffic')
$script:AppsSummary=$Window.FindName('AppsSummary')
function Test-IsAdministrator {
    try{
        $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
        return (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }catch{return $false}
}
function Request-TunElevation {
    if(Test-IsAdministrator){return $false}
    if(-not $env:LUNA_EXECUTABLE_PATH){
        Show-Notice 'Нужны права администратора' 'Запустите Luna.exe от имени администратора для подключения в режиме TUN.' 'WARN'
        return $true
    }
    try{
        Add-AppLog '[INFO] Для режима TUN запрашиваются права администратора.'
        Start-Process -FilePath $env:LUNA_EXECUTABLE_PATH -Verb RunAs -ArgumentList '--elevated-tun' | Out-Null
        $script:AllowExit=$true
        $Window.Close()
    }catch{
        Show-Notice 'TUN не запущен' 'Без разрешения администратора Windows не позволяет создать системный VPN-интерфейс.' 'WARN'
    }
    return $true
}
function Normalize-SplitDomain([string]$Value) {
    $value=([string]$Value).Trim().ToLowerInvariant()
    if(-not $value){throw 'Введите домен сайта.'}
    if($value -match '^[a-z][a-z0-9+.-]*://'){
        try{$value=([Uri]$value).DnsSafeHost.ToLowerInvariant()}catch{throw 'Указан некорректный адрес сайта.'}
    }
    $wildcard=$value.StartsWith('*.')
    if($wildcard){$value=$value.Substring(2)}
    $value=$value.Trim('. ')
    try{$value=(New-Object Globalization.IdnMapping).GetAscii($value)}catch{throw 'Указан некорректный домен.'}
    if($value -ne 'localhost' -and ($value.Length -gt 253 -or $value -notmatch '^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')){throw 'Указан некорректный домен.'}
    if($wildcard){return '*.'+$value}
    return $value
}
function Normalize-SplitIp([string]$Value) {
    $value=([string]$Value).Trim()
    if(-not $value){throw 'Введите IP-адрес или CIDR-подсеть.'}
    $parts=$value.Split('/')
    if($parts.Count -gt 2){throw 'Некорректный формат IP/CIDR.'}
    try{$address=[Net.IPAddress]::Parse($parts[0])}catch{throw 'Некорректный IP-адрес.'}
    if($parts.Count -eq 2){
        $prefix=0
        if(-not [int]::TryParse($parts[1],[ref]$prefix)){throw 'Некорректная длина префикса CIDR.'}
        $max=if($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork){32}else{128}
        if($prefix -lt 0 -or $prefix -gt $max){throw "Префикс CIDR должен быть от 0 до $max."}
        return "$($address.IPAddressToString)/$prefix"
    }
    return $address.IPAddressToString
}
function Update-SplitView {
    $SplitEnabled.IsChecked=[bool]$State.settings.splitEnabled
    $SplitScopeBox.SelectedIndex=if($State.settings.mode -eq 'TUN'){1}else{0}
    $SplitDomainList.ItemsSource=@($State.settings.splitDomains)
    $SplitIpList.ItemsSource=@($State.settings.splitIps)
    $SplitAppList.ItemsSource=@($State.settings.splitApps)
    $SplitGameList.ItemsSource=@($State.settings.splitGames)
    $count=@($State.settings.splitDomains).Count+@($State.settings.splitIps).Count+@($State.settings.splitApps).Count+@($State.settings.splitGames).Count
    if([bool]$State.settings.splitEnabled){
        $scope=if($State.settings.mode -eq 'TUN'){'TUN: весь системный TCP/UDP-трафик'}else{'System proxy: HTTP/HTTPS proxy-aware приложений'}
        $SplitStatus.Text="Активно: $count правил. $scope. Выбранный трафик идёт напрямую."
        $SplitStatus.Foreground='#74E5B2'
    }else{
        $SplitStatus.Text="Выключено: сохранено $count правил, но они не применяются."
        $SplitStatus.Foreground='#AEB4CC'
    }
}
function Add-SplitExecutables([string]$Category) {
    $dialog=New-Object Microsoft.Win32.OpenFileDialog
    $dialog.Filter='Приложения и игры (*.exe)|*.exe'
    $dialog.Multiselect=$true
    if($dialog.ShowDialog()){
        $key=if($Category -eq 'game'){'splitGames'}else{'splitApps'}
        $State.settings[$key]=@($State.settings[$key]+@($dialog.FileNames)|Where-Object {$_}|Select-Object -Unique)
        Save-State;Update-SplitView
    }
}
function Get-LunaRunningProcessChoices {
    $blockedIds=New-Object 'System.Collections.Generic.HashSet[int]'
    $null=$blockedIds.Add([int]$PID)
    if($script:CoreProcess -and -not $script:CoreProcess.HasExited){$null=$blockedIds.Add([int]$script:CoreProcess.Id)}
    $rows=New-Object 'System.Collections.Generic.List[object]'
    foreach($process in [Diagnostics.Process]::GetProcesses()){
        try{
            $processId=[int]$process.Id
            if($processId -le 4 -or $blockedIds.Contains($processId)){continue}
            $name=[string]$process.ProcessName
            if($name -match '^(?i:xray|Luna)$'){continue}
            $path=[LunaTrafficMeter]::ResolveProcessPath($processId)
            if([string]::IsNullOrWhiteSpace($path) -or [IO.Path]::GetExtension($path) -ine '.exe' -or -not [IO.File]::Exists($path)){continue}
            $rows.Add([pscustomobject]@{Name=$name;PID=$processId;Path=$path})
        }catch{
            # Protected and short-lived Windows processes are intentionally omitted.
        }finally{
            try{$process.Dispose()}catch{}
        }
    }
    return @($rows|Sort-Object Name,PID)
}
function Show-RunningProcessPicker([string]$Category) {
    [xml]$pickerXaml=@"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" Title="Запущенные процессы · Luna" Width="940" Height="620" MinWidth="720" MinHeight="460" WindowStartupLocation="CenterOwner" Background="#080B24" Foreground="#F8F7FF" ShowInTaskbar="False">
 <Window.Resources>
  <Style TargetType="Button"><Setter Property="Foreground" Value="#F8F7FF"/><Setter Property="Background" Value="#1A1E4C"/><Setter Property="BorderBrush" Value="#4B4295"/><Setter Property="BorderThickness" Value="1"/><Setter Property="Padding" Value="14,8"/><Setter Property="Margin" Value="4"/></Style>
  <Style TargetType="TextBox"><Setter Property="Foreground" Value="#F8F7FF"/><Setter Property="Background" Value="#101333"/><Setter Property="BorderBrush" Value="#4B4295"/><Setter Property="CaretBrush" Value="#FFFFFF"/><Setter Property="Padding" Value="10,7"/></Style>
  <Style TargetType="DataGrid"><Setter Property="Foreground" Value="#F8F7FF"/><Setter Property="Background" Value="#0B0E29"/><Setter Property="BorderBrush" Value="#292B63"/><Setter Property="RowBackground" Value="#0B0E29"/><Setter Property="AlternatingRowBackground" Value="#101333"/><Setter Property="HorizontalGridLinesBrush" Value="#202652"/><Setter Property="VerticalGridLinesBrush" Value="#202652"/></Style>
  <Style TargetType="DataGridColumnHeader"><Setter Property="Foreground" Value="#D9D5FF"/><Setter Property="Background" Value="#171B42"/><Setter Property="BorderBrush" Value="#292B63"/><Setter Property="Padding" Value="10,8"/></Style>
  <Style TargetType="DataGridRow"><Setter Property="Foreground" Value="#F8F7FF"/><Setter Property="BorderBrush" Value="#202652"/><Style.Triggers><Trigger Property="IsSelected" Value="True"><Setter Property="Background" Value="#403684"/><Setter Property="Foreground" Value="#FFFFFF"/></Trigger></Style.Triggers></Style>
 </Window.Resources>
 <Grid Margin="20">
  <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
  <StackPanel><TextBlock Text="Выбор запущенного процесса" FontSize="25" FontWeight="SemiBold"/><TextBlock Text="Выберите один или несколько процессов. Luna сохранит полный путь EXE, а не временный PID." Foreground="#AEB4CC" Margin="0,5,0,14"/></StackPanel>
  <Grid Grid.Row="1" Margin="0,0,0,10"><Grid.ColumnDefinitions><ColumnDefinition/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions><TextBox Name="ProcessSearch" ToolTip="Поиск по названию, PID или пути"/><Button Name="RefreshProcesses" Grid.Column="1" Content="↻ Обновить"/><TextBlock Name="ProcessCount" Grid.Column="2" Foreground="#BCAEFF" VerticalAlignment="Center" Margin="12,0,4,0"/></Grid>
  <DataGrid Name="ProcessGrid" Grid.Row="2" IsReadOnly="True" AutoGenerateColumns="False" CanUserAddRows="False" CanUserDeleteRows="False" SelectionMode="Extended" SelectionUnit="FullRow" AlternationCount="2">
   <DataGrid.Columns><DataGridTextColumn Header="Процесс" Binding="{Binding Name}" Width="190"/><DataGridTextColumn Header="PID" Binding="{Binding PID}" Width="85"/><DataGridTextColumn Header="Полный путь EXE" Binding="{Binding Path}" Width="*"/></DataGrid.Columns>
  </DataGrid>
  <TextBlock Name="ProcessStatus" Grid.Row="3" Text="Защищённые системные процессы и процессы без доступного пути не отображаются." Foreground="#8F96B5" TextWrapping="Wrap" Margin="2,10,2,4"/>
  <StackPanel Grid.Row="4" Orientation="Horizontal" HorizontalAlignment="Right"><Button Name="CancelProcessSelection" Content="Отмена"/><Button Name="ConfirmProcessSelection" Content="Добавить выбранные" Background="#5147B8"/></StackPanel>
 </Grid>
</Window>
"@
    $reader=New-Object Xml.XmlNodeReader $pickerXaml
    $picker=[Windows.Markup.XamlReader]::Load($reader)
    $picker.Owner=$Window
    $ProcessSearch=$picker.FindName('ProcessSearch');$RefreshProcesses=$picker.FindName('RefreshProcesses');$ProcessCount=$picker.FindName('ProcessCount');$ProcessGrid=$picker.FindName('ProcessGrid');$ProcessStatus=$picker.FindName('ProcessStatus');$CancelProcessSelection=$picker.FindName('CancelProcessSelection');$ConfirmProcessSelection=$picker.FindName('ConfirmProcessSelection')
    $loadProcesses={
        $items=@(Get-LunaRunningProcessChoices)
        $picker.Tag=$items
        $ProcessGrid.ItemsSource=$items
        $ProcessCount.Text="$($items.Count) доступно"
        $ProcessStatus.Text=if($items.Count){'Можно выбрать несколько строк с помощью Ctrl или Shift.'}else{'Доступных пользовательских процессов не найдено. Запустите приложение или игру и нажмите «Обновить».'}
    }.GetNewClosure()
    $applySearch={
        $needle=$ProcessSearch.Text.Trim()
        $items=@($picker.Tag)
        if($needle){$items=@($items|Where-Object {$_.Name -like "*$needle*" -or ([string]$_.PID) -like "*$needle*" -or $_.Path -like "*$needle*"})}
        $ProcessGrid.ItemsSource=$items
        $ProcessCount.Text="$($items.Count) показано"
    }.GetNewClosure()
    $commitSelection={
        $selected=@($ProcessGrid.SelectedItems)
        if(-not $selected.Count){$ProcessStatus.Text='Сначала выберите хотя бы один процесс.';$ProcessStatus.Foreground='#FFD166';return}
        $paths=@($selected|ForEach-Object {[string]$_.Path}|Where-Object {$_ -and [IO.File]::Exists($_)}|Select-Object -Unique)
        if(-not $paths.Count){$ProcessStatus.Text='Выбранные процессы уже завершились или их файлы недоступны. Обновите список.';$ProcessStatus.Foreground='#FF8E9E';return}
        $key=if($Category -eq 'game'){'splitGames'}else{'splitApps'}
        $State.settings[$key]=@($State.settings[$key]+$paths|Select-Object -Unique)
        Save-State;Update-SplitView
        $picker.DialogResult=$true
    }.GetNewClosure()
    $RefreshProcesses.Add_Click($loadProcesses)
    $ProcessSearch.Add_TextChanged($applySearch)
    $ConfirmProcessSelection.Add_Click($commitSelection)
    $ProcessGrid.Add_MouseDoubleClick($commitSelection)
    $CancelProcessSelection.Add_Click({$picker.DialogResult=$false}.GetNewClosure())
    & $loadProcesses
    $null=$picker.ShowDialog()
}
function Apply-SplitConfiguration {
    Save-State;Update-SplitView
    if($script:CoreProcess -and -not $script:CoreProcess.HasExited){
        Stop-Tunnel
        Start-Tunnel
    }else{Show-Notice 'Правила сохранены' 'Они будут применены при следующем подключении Luna.' 'SUCCESS'}
}
$script:ToastTimer=New-Object Windows.Threading.DispatcherTimer
$script:ToastTimer.Interval=[TimeSpan]::FromSeconds(3)
$script:ToastTimer.Add_Tick({
    $script:ToastTimer.Stop()
    $ToastPanel.Visibility='Collapsed'
})
$runtimeRoot=if($PSScriptRoot){$PSScriptRoot}else{$env:LUNA_RUNTIME_DIR}
$iconPath=Join-Path $runtimeRoot 'luna-icon.png'
if(Test-Path $iconPath){
    $iconBitmap=New-Object Windows.Media.Imaging.BitmapImage
    $iconBitmap.BeginInit();$iconBitmap.CacheOption='OnLoad';$iconBitmap.UriSource=New-Object Uri($iconPath);$iconBitmap.EndInit()
    $Window.Icon=$iconBitmap;$BrandIcon.Source=$iconBitmap;$AboutIcon.Source=$iconBitmap
}

function Get-CorePath {
    $local=Join-Path $CoreDir 'xray.exe'; if(Test-Path $local){return $local}
    if($env:LUNA_APP_DIR){
        $portable=Join-Path $env:LUNA_APP_DIR 'core\xray.exe'
        if(Test-Path $portable){return $portable}
    }
    $cmd=Get-Command xray.exe -ErrorAction SilentlyContinue; if($cmd){return $cmd.Source}
    return $null
}
function Refresh-CoreStatus {
    if(Get-CorePath){$CoreStatus.Text='● VPN не активен';$CoreStatus.Foreground='#AEB4CC';$ProtectionDetail.Text='Все компоненты работают.';$InstallCore.Content='Xray-core установлен';$InstallCore.IsEnabled=$false}else{$CoreStatus.Text='● Требуется компонент';$CoreStatus.Foreground='#FF8E9E';$ProtectionDetail.Text='Установите сетевой движок.';$InstallCore.Content='Установить Xray-core';$InstallCore.IsEnabled=$true}
}
function Get-AvailablePortBlock([int]$Preferred) {
    $used=New-Object 'Collections.Generic.HashSet[int]'
    foreach($endpoint in [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners()){
        [void]$used.Add([int]$endpoint.Port)
    }
    for($port=[Math]::Max([int]1024,[int]$Preferred);$port -lt 65000;$port+=2){
        if(-not $used.Contains($port) -and -not $used.Contains($port+1) -and -not $used.Contains($port+2) -and -not $used.Contains($port+3)){return $port}
    }
    throw 'Не удалось найти свободные локальные порты.'
}
function Refresh-Profiles {
    if($script:RefreshingProfiles){return}
    $script:RefreshingProfiles=$true
    try{
        $filter=$SearchBox.Text.ToLowerInvariant()
        $rows=@($State.profiles|?{"$($_.name) $($_.host) $($_.protocol) $($_.country) $($_.city)".ToLowerInvariant().Contains($filter)}|%{[pscustomobject]@{id=$_.id;name=$_.name;location=(@($_.country,$_.city)|?{$_}) -join ', ';protocol=$_.protocol.ToUpper();endpoint="$($_.host):$($_.port)";status=(Get-Or $_.healthStatus (Get-Or $_.status 'Не проверен'));latency=$_.latency}})
        $ServerList.ItemsSource=$rows
        $HomeServerList.ItemsSource=$rows
        $QuickServer.Items.Clear()
        foreach($p in $State.profiles){[void]$QuickServer.Items.Add("$($p.name)  ·  $($p.protocol.ToUpper())")}
        $idx=0; for($i=0;$i -lt $State.profiles.Count;$i++){if($State.profiles[$i].id -eq $State.selectedId){$idx=$i}}
        $selectedRow=$rows|Where-Object {$_.id -eq $State.selectedId}|Select-Object -First 1
        if($selectedRow){$ServerList.SelectedItem=$selectedRow;$HomeServerList.SelectedItem=$selectedRow}
        if($State.profiles.Count){$QuickServer.SelectedIndex=$idx;$SelectedServer.Text=$State.profiles[$idx].name;$LatencyServerName.Text=$State.profiles[$idx].name;$LatencyLabel.Text=$State.profiles[$idx].latency}else{$SelectedServer.Text='Серверы не найдены';$LatencyServerName.Text='Сервер не выбран'}
        $ServerLoadStatus.Text=$script:ServerLoadMessage
        $ServerLoadStatus.Foreground=switch($script:ServerLoadState){'error'{'#FF93A4'}'empty'{'#FF93A4'}'success'{'#78E6B4'}default{'#CDBFFF'}}
    }finally{$script:RefreshingProfiles=$false}
}
function Refresh-Subscriptions {
    $SubscriptionList.ItemsSource=@($State.subscriptions|%{$sub=$_;[pscustomobject]@{id=$sub.id;name=$sub.name;url=$sub.url;count=@($State.profiles|?{$_.subscriptionId -eq $sub.id}).Count}})
}
function Show-Page($Page) {
    foreach($p in @($HomePage,$ServersPage,$SubsPage,$RoutesPage,$LogsPage,$StatsPage,$SplitPage,$AppsPage,$SettingsPage,$ExpertsPage,$AboutPage)){$p.Visibility='Collapsed'}
    $Page.Visibility='Visible'
}
function Show-LunaPage($Page) {
    $Window.Dispatcher.Invoke([action]{
        $Window.ShowInTaskbar=$true
        $Window.Show()
        $Window.WindowState='Normal'
        Show-Page $Page
        [void]$Window.Activate()
    })
}
function Hide-LunaToTray {
    $Window.ShowInTaskbar=$false
    $Window.Hide()
}
function Set-TrayStatus([string]$Text) {
    if($script:TrayIcon){$script:TrayIcon.Text=if($Text.Length -gt 63){$Text.Substring(0,63)}else{$Text}}
}
function Open-PrivacyPolicy {
    $privacyPath=$null
    if($env:LUNA_APP_DIR){$privacyPath=Join-Path $env:LUNA_APP_DIR 'PRIVACY.md'}
    if(-not $privacyPath -or -not (Test-Path $privacyPath)){$privacyPath=Join-Path $PSScriptRoot 'PRIVACY.md'}
    if(Test-Path $privacyPath){Start-Process -FilePath $privacyPath}else{Show-Notice 'Документ не найден' 'Файл PRIVACY.md отсутствует рядом с приложением.' 'WARN'}
}
function Show-TelemetryConsentDialog {
    [xml]$consentXaml=@'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" Title="Конфиденциальность Luna" Width="430" Height="300" WindowStartupLocation="CenterOwner" ResizeMode="NoResize" Background="#090C25" Foreground="#F8F9FF">
 <Grid Margin="18">
  <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
  <StackPanel><TextBlock Text="Анонимные отчёты о работе" FontSize="19" FontWeight="SemiBold"/><TextBlock Text="Выбор можно изменить в настройках Luna." FontSize="12" Foreground="#BCAEFF" Margin="0,3,0,8"/></StackPanel>
  <StackPanel Grid.Row="1"><TextBlock Text="Разрешить анонимные диагностические отчёты для поиска ошибок?" FontSize="14" TextWrapping="Wrap"/><Border Background="#111536" CornerRadius="9" Padding="9" Margin="0,8,0,7"><TextBlock Text="При ошибках Luna отправит версию приложения и Windows, модуль и очищенное описание. VPN-конфигурации, UUID, ключи, IP-адрес, пути пользователя и история сайтов удаляются до отправки." FontSize="12" TextWrapping="Wrap" Foreground="#C8CCE0"/></Border><Button Name="PrivacyButton" Content="Политика конфиденциальности" HorizontalAlignment="Left" Padding="9,5" Background="#171B42" Foreground="#F8F9FF" BorderBrush="#56509A"/></StackPanel>
  <StackPanel Grid.Row="2" Orientation="Horizontal" HorizontalAlignment="Right"><Button Name="DeclineButton" Content="Не разрешать" MinWidth="115" Padding="11,7" Margin="4" Background="#171B42" Foreground="#F8F9FF" BorderBrush="#56509A"/><Button Name="AllowButton" Content="Разрешить" MinWidth="115" Padding="11,7" Margin="4" Background="#7658E8" Foreground="#FEFEFF" BorderBrush="#9A7BFF"/></StackPanel>
 </Grid>
</Window>
'@
    $reader=New-Object System.Xml.XmlNodeReader $consentXaml
    $dialog=[Windows.Markup.XamlReader]::Load($reader)
    $dialog.Owner=$Window
    $allow=$dialog.FindName('AllowButton');$decline=$dialog.FindName('DeclineButton');$privacy=$dialog.FindName('PrivacyButton')
    $result=$false
    $allow.Add_Click({$script:ConsentResult=$true;$dialog.Close()})
    $decline.Add_Click({$script:ConsentResult=$false;$dialog.Close()})
    $privacy.Add_Click({Open-PrivacyPolicy})
    $script:ConsentResult=$false
    [void]$dialog.ShowDialog()
    $State.settings.anonymousStats=[bool]$script:ConsentResult
    $State.settings.telemetryConsentAsked=$true
    $AnonymousStats.IsChecked=$State.settings.anonymousStats
    Save-State
}
function Initialize-SystemTray {
    $script:TrayIcon=New-Object Windows.Forms.NotifyIcon
    $iconSource=if($env:LUNA_EXECUTABLE_PATH){$env:LUNA_EXECUTABLE_PATH}else{$PSCommandPath}
    if($iconSource -and (Test-Path $iconSource)){$script:TrayIconImage=[Drawing.Icon]::ExtractAssociatedIcon($iconSource);$script:TrayIcon.Icon=$script:TrayIconImage}
    $menu=New-Object Windows.Forms.ContextMenuStrip
    $menu.BackColor=[Drawing.Color]::FromArgb(17,20,54);$menu.ForeColor=[Drawing.Color]::FromArgb(245,246,255)
    $menu.Font=New-Object Drawing.Font('Segoe UI',10)
    $menu.ShowImageMargin=$false;$menu.Padding=New-Object Windows.Forms.Padding(5)
    $connectionItem=$menu.Items.Add('●  Подключение')
    $statisticsItem=$menu.Items.Add('▥  Статистика')
    $settingsItem=$menu.Items.Add('⚙  Настройки')
    $aboutItem=$menu.Items.Add('ⓘ  О приложении')
    [void]$menu.Items.Add((New-Object Windows.Forms.ToolStripSeparator))
    $exitItem=$menu.Items.Add('×  Выход')
    foreach($item in @($connectionItem,$statisticsItem,$settingsItem,$aboutItem,$exitItem)){$item.Padding=New-Object Windows.Forms.Padding(10,7,24,7)}
    $connectionItem.Add_Click({Show-LunaPage $HomePage})
    $statisticsItem.Add_Click({Show-LunaPage $StatsPage})
    $settingsItem.Add_Click({Show-LunaPage $SettingsPage})
    $aboutItem.Add_Click({Show-LunaPage $AboutPage})
    $exitItem.Add_Click({
        $script:AllowExit=$true
        $script:TrayIcon.Visible=$false
        $Window.Close()
        if($script:WpfApplication){$script:WpfApplication.Shutdown()}
    })
    $script:TrayIcon.ContextMenuStrip=$menu
    $script:TrayIcon.Add_DoubleClick({Show-LunaPage $HomePage})
    $script:TrayIcon.Visible=$true
    Set-TrayStatus 'Luna VPN — нет подключения'
}
function Set-Loading([bool]$Visible,[string]$Message='Загрузка…') {
    $LoadingText.Text=$Message
    $LoadingOverlay.Visibility=if($Visible){'Visible'}else{'Collapsed'}
    $Window.Dispatcher.Invoke([action]{},[Windows.Threading.DispatcherPriority]::Render)
}
function Get-FriendlyError([string]$Detail) {
    if($Detail -match 'DNS|resolve|lookup'){return 'DNS недоступен.'}
    if($Detail -match 'TLS|certificate|x509|handshake'){return 'TLS не прошёл проверку.'}
    if($Detail -match 'REALITY|Reality|invalid.*password|shortId'){return 'Reality отклонил соединение.'}
    if($Detail -match 'refused|timeout|timed out|unreachable|no route'){return 'Сервер не отвечает.'}
    if($Detail -match 'address already in use|bind'){return 'Локальный порт занят другим VPN-приложением.'}
    return $Detail
}
function Show-Notice([string]$Title,[string]$Message,[string]$Level='INFO',[bool]$CanFix=$false) {
    $script:ToastTimer.Stop()
    $ToastTitle.Text=$Title
    $ToastMessage.Text=if($Level -in @('ERROR','WARN')){Get-FriendlyError $Message}else{$Message}
    $ToastPanel.BorderBrush=switch($Level){'ERROR'{'#FF5D6C'}'WARN'{'#FFD166'}'SUCCESS'{'#55E69D'}default{'#56509A'}}
    $FixButton.Visibility=if($CanFix){'Visible'}else{'Collapsed'};$ToastPanel.Visibility='Visible'
    Add-AppLog "[$Level] $Title — $Message"
    if($Level -eq 'ERROR'){Send-AnonymousErrorReport $Title $Message 'Desktop'}
    $script:ToastTimer.Start()
}
function Start-ConnectionWave {
    $duration=New-Object Windows.Duration([TimeSpan]::FromSeconds(1.35))
    $scale=New-Object Windows.Media.Animation.DoubleAnimation
    $scale.From=1.0;$scale.To=1.85;$scale.Duration=$duration
    $fade=New-Object Windows.Media.Animation.DoubleAnimation
    $fade.From=0.85;$fade.To=0.0;$fade.Duration=$duration
    $WaveRing.RenderTransform.BeginAnimation([Windows.Media.ScaleTransform]::ScaleXProperty,$scale)
    $WaveRing.RenderTransform.BeginAnimation([Windows.Media.ScaleTransform]::ScaleYProperty,$scale)
    $WaveRing.BeginAnimation([Windows.UIElement]::OpacityProperty,$fade)
}
function Refresh-LogView {
    if(-not $LogView){return}
    if(-not $script:LogFollow){return}
    $filter=if($LogFilter.SelectedItem){[string]$LogFilter.SelectedItem.Content}else{'Все'}
    $search=$LogSearch.Text
    $document=New-Object Windows.Documents.FlowDocument
    $paragraph=New-Object Windows.Documents.Paragraph
    $paragraph.Margin='4'
    if(Test-Path $LogFile){
        foreach($line in @(Get-Content $LogFile -Tail 700)){
            if($filter -ne 'Все' -and $line -notmatch "\[$filter\]" -and $line -notmatch $filter){continue}
            if($search -and $line.IndexOf($search,[StringComparison]::OrdinalIgnoreCase) -lt 0){continue}
            $run=New-Object Windows.Documents.Run($line+"`n")
            if($line -match 'ERROR|ошиб|Failed|завершился'){$run.Foreground='#FF6B7A'}
            elseif($line -match 'WARN|предупреж'){$run.Foreground='#FFD166'}
            elseif($line -match 'успеш|Configuration OK|активен|доступно'){$run.Foreground='#65E6A7'}
            else{$run.Foreground='#D8DCF0'}
            [void]$paragraph.Inlines.Add($run)
        }
    }
    [void]$document.Blocks.Add($paragraph);$LogView.Document=$document;$LogView.ScrollToEnd()
}
function Wait-UiTask($Task) {
    while(-not $Task.IsCompleted){
        $Window.Dispatcher.Invoke([action]{},[Windows.Threading.DispatcherPriority]::Background)
        Start-Sleep -Milliseconds 20
    }
    if($Task.IsFaulted){throw $Task.Exception.GetBaseException()}
    if($Task.IsCanceled){throw 'Операция отменена по тайм-ауту.'}
}
function Invoke-AsyncHttp([string]$Uri,[hashtable]$Headers,[switch]$AsBytes,[int]$TimeoutSeconds=90) {
    $handler=New-Object Net.Http.HttpClientHandler
    $handler.AutomaticDecompression=[Net.DecompressionMethods]::GZip -bor [Net.DecompressionMethods]::Deflate
    $client=New-Object Net.Http.HttpClient -ArgumentList (,$handler)
    $client.Timeout=[TimeSpan]::FromSeconds([Math]::Max([double]3,[double]$TimeoutSeconds))
    $request=New-Object Net.Http.HttpRequestMessage -ArgumentList ([Net.Http.HttpMethod]::Get,$Uri)
    foreach($key in $Headers.Keys){[void]$request.Headers.TryAddWithoutValidation($key,[string]$Headers[$key])}
    try{
        $sendTask=$client.SendAsync($request)
        Wait-UiTask $sendTask
        $response=$sendTask.GetAwaiter().GetResult()
        [void]$response.EnsureSuccessStatusCode()
        $contentTask=if($AsBytes){$response.Content.ReadAsByteArrayAsync()}else{$response.Content.ReadAsStringAsync()}
        Wait-UiTask $contentTask
        return [pscustomobject]@{Content=$contentTask.GetAwaiter().GetResult();ContentType=[string]$response.Content.Headers.ContentType}
    }finally{$request.Dispose();$client.Dispose();$handler.Dispose()}
}
function Get-BackendConnectionSettings {
    $settings=@{baseUrl=$DefaultBackendBaseUrl;token=''}
    $paths=@()
    if($env:LUNA_APP_DIR){$paths+=,(Join-Path $env:LUNA_APP_DIR 'client-api.json')}
    $paths+=,$BackendClientConfigFile
    foreach($path in $paths){
        if(Test-Path -LiteralPath $path){
            try{
                $value=Get-Content -Raw -Encoding UTF8 -LiteralPath $path|ConvertFrom-Json
                if($value.baseUrl){$settings.baseUrl=[string]$value.baseUrl}
                if($value.clientToken){$settings.token=[string]$value.clientToken}
            }catch{Add-AppLog "Ошибка client-api.json: $($_.Exception.Message)"}
        }
    }
    if($env:LUNA_BACKEND_URL){$settings.baseUrl=[string]$env:LUNA_BACKEND_URL}
    if($env:LUNA_CLIENT_API_TOKEN){$settings.token=[string]$env:LUNA_CLIENT_API_TOKEN}
    $settings.baseUrl=$settings.baseUrl.TrimEnd('/')
    if($settings.baseUrl -notmatch '^https://' -and $settings.baseUrl -notmatch '^http://(127\.0\.0\.1|localhost)(:\d+)?$'){
        throw 'Backend Luna должен использовать HTTPS.'
    }
    return $settings
}
function Invoke-LunaBackendJson([string]$Path) {
    $connection=Get-BackendConnectionSettings
    $headers=@{'User-Agent'="Luna/$AppVersion";'Accept'='application/json'}
    if($connection.token){$headers['X-Luna-Client-Token']=$connection.token}
    $response=Invoke-AsyncHttp "$($connection.baseUrl)$Path" $headers -TimeoutSeconds 12
    if([string]::IsNullOrWhiteSpace([string]$response.Content)){throw "Backend вернул пустой ответ: $Path"}
    return ConvertFrom-LunaJson ([string]$response.Content)
}
function Load-BackendMetadataCache {
    if(-not (Test-Path -LiteralPath $BackendMetadataCacheFile)){return $null}
    try{return ConvertFrom-LunaJson (Get-Content -Raw -Encoding UTF8 -LiteralPath $BackendMetadataCacheFile)}catch{
        Add-AppLog "Ошибка metadata-кэша backend: $($_.Exception.Message)"
        return $null
    }
}
function Apply-BackendMetadata($Metadata,[bool]$FromCache=$false) {
    if(-not $Metadata){return}
    $suffix=if($FromCache){' · локальный кэш'}else{' · online'}
    if($Metadata.config){
        $script:BackendConfig=$Metadata.config
        if($Metadata.config.maintenance){
            $BackendStatusText.Text="Технические работы$suffix`: $($Metadata.config.maintenanceMessage)"
            $BackendStatusText.Foreground='#FFD166'
            $ConnectButton.IsEnabled=$false
        }else{
            $BackendStatusText.Text="Сервис Luna доступен$suffix"
            $BackendStatusText.Foreground='#65E6A7'
            $ConnectButton.IsEnabled=$true
        }
        if($script:BackendTimer -and $Metadata.config.serverRefreshIntervalSeconds){
            $seconds=[Math]::Max([int]30,[int]$Metadata.config.serverRefreshIntervalSeconds)
            $script:BackendTimer.Interval=[TimeSpan]::FromSeconds($seconds)
        }
    }
    if($Metadata.version){
        $script:BackendLatestVersion=$Metadata.version
        if($Metadata.version.latest){
            $latest=[string]$Metadata.version.latest.version
            $UpdateStatusText.Text=if($Metadata.version.updateAvailable){"Доступна версия $latest"}else{"Установлена актуальная версия $AppVersion"}
            $UpdateStatusText.Foreground=if($Metadata.version.updateAvailable){'#FFD166'}else{'#65E6A7'}
        }
    }
    $news=@($Metadata.news|ForEach-Object{$_})
    if($news.Count){
        $script:BackendLatestNews=$news[0]
        $LatestNewsText.Text="Новости: $($news[0].title) — $($news[0].summary)"
    }
    $entries=if($Metadata.changelog){@($Metadata.changelog.entries|ForEach-Object{$_})}else{@()}
    if($entries.Count){
        $script:BackendLatestChangelog=$entries[0]
        $ChangelogStatusText.Text="Последние изменения: $($entries[0].version) · $($entries[0].title)"
    }
}
function Sync-LunaBackend([switch]$Silent) {
    if($script:BackendSyncInProgress){return}
    $script:BackendSyncInProgress=$true
    if(-not $Silent){Set-Loading $true 'Обновляем данные сервиса Luna…'}
    try{
        try{
            $config=Invoke-LunaBackendJson '/api/config'
        }catch{
            $cachedMetadata=Load-BackendMetadataCache
            if($cachedMetadata){Apply-BackendMetadata $cachedMetadata $true}
            $cachedCount=Load-BackendServerCache
            $script:ServerLoadState='error'
            $script:ServerLoadMessage=if($cachedCount){"Сервис обновления серверов временно недоступен. Используется сохранённый список: $cachedCount."}else{'Сервис обновления серверов временно недоступен. Добавьте подписку или повторите позже.'}
            $BackendStatusText.Text='Сервис Luna временно недоступен · VPN продолжает работать локально'
            $BackendStatusText.Foreground='#FFD166'
            Add-AppLog "[WARN] Сервис Luna временно недоступен: $($_.Exception.Message)"
            Refresh-Profiles
            return
        }

        $version=$null;$news=@();$changelog=$null
        try{$version=Invoke-LunaBackendJson "/api/version?current=$([Uri]::EscapeDataString($AppVersion))&channel=release"}catch{Add-AppLog "[WARN] Не удалось проверить версию: $($_.Exception.Message)"}
        if(-not $config.features -or $config.features.news){
            try{$news=@(Invoke-LunaBackendJson '/api/news?limit=20')}catch{Add-AppLog "[WARN] Не удалось загрузить новости: $($_.Exception.Message)"}
            try{$changelog=Invoke-LunaBackendJson '/api/changelog'}catch{Add-AppLog "[WARN] Не удалось загрузить changelog: $($_.Exception.Message)"}
        }
        $metadata=@{updatedAt=(Get-Date).ToUniversalTime().ToString('o');config=$config;version=$version;news=@($news);changelog=$changelog}
        Write-AtomicJson $BackendMetadataCacheFile $metadata
        Apply-BackendMetadata ([pscustomobject]$metadata) $false

        if($config.maintenance -and -not $Silent){
            Show-Notice 'Технические работы' (Get-Or $config.maintenanceMessage 'Подключение временно ограничено.') 'WARN'
        }elseif($version -and $version.updateAvailable -and -not $Silent){
            $level=if($version.mandatory){'ERROR'}else{'INFO'}
            Show-Notice 'Доступно обновление Luna' "Новая версия: $($version.latest.version)" $level
        }

        if($config.features -and $null -ne $config.features.serverApi -and -not [bool]$config.features.serverApi){
            $cachedCount=Load-BackendServerCache
            $script:ServerLoadState='success'
            $script:ServerLoadMessage=if($cachedCount){"Сервис Luna доступен. Используется сохранённый каталог: $cachedCount серверов."}else{'Сервис Luna доступен. Онлайн-каталог ещё не настроен; используйте локальные подписки.'}
            Refresh-Profiles
            return
        }

        try{
            $servers=@(Invoke-LunaBackendJson '/api/servers')
            $profiles=@()
            foreach($server in $servers){
                try{$profiles+=,(ConvertTo-LocalProfile $server 'backend-api')}catch{Add-AppLog "[WARN] Некорректный сервер backend: $($_.Exception.Message)"}
            }
            if($profiles.Count){
                $count=Replace-BackendProfiles $profiles
                Write-AtomicJson $BackendServerCacheFile $servers
                $script:ServerLoadState='success'
                $script:ServerLoadMessage="Сервис Luna: $count серверов · обновлено $(Get-Date -Format 'HH:mm:ss')"
                Add-AppLog "[INFO] Каталог серверов Luna обновлён: $count серверов"
            }else{
                $existing=@($State.profiles|?{$_.source -eq 'backend-api'}).Count
                if(-not $existing){$existing=Load-BackendServerCache}
                $script:ServerLoadState='error'
                $script:ServerLoadMessage=if($existing){"Backend вернул пустой список. Сохранён рабочий список: $existing."}else{'Backend вернул пустой список. Добавьте сервер в панели администратора.'}
                Add-AppLog "[WARN] Backend вернул пустой или некорректный список; текущие серверы не удалены"
            }
        }catch{
            $existing=@($State.profiles|?{$_.source -eq 'backend-api'}).Count
            if(-not $existing){$existing=Load-BackendServerCache}
            $script:ServerLoadState='error'
            $script:ServerLoadMessage=if($existing){"Ошибка обновления. Используется последний список: $existing серверов."}else{'Не удалось получить серверы, резервный список отсутствует.'}
            Add-AppLog "[WARN] Ошибка /api/servers: $($_.Exception.Message)"
        }
        Save-State
        Refresh-Profiles
    }finally{
        if(-not $Silent){Set-Loading $false}
        $script:BackendSyncInProgress=$false
    }
}
function Get-RouteStatusColor([string]$Status) {
    switch($Status){
        'Отлично' { return '#65E6A7' }
        'Хорошо' { return '#8DC7FF' }
        'Нормально' { return '#FFD166' }
        'Медленно' { return '#FF9F43' }
        default { return '#FF6B7A' }
    }
}
function Format-RouteLatency($Result) {
    if(-not $Result){return '—'}
    if([int64]$Result.LatencyMs -lt 0){return 'недоступен'}
    return "$([int64]$Result.LatencyMs) ms"
}
function Get-RouteCheckMap($Results) {
    $map=@{}
    foreach($result in @($Results)){
        if($result -and $result.Target){$map[[string]$result.Target.Id]=$result}
    }
    return $map
}
function Refresh-RouteQualityView {
    if(-not $RouteQualityList){return}
    $connected=[bool]$script:ConnectedAt
    $items=@()
    foreach($target in $script:RouteTargets){
        $id=[string]$target.Id
        $measuredDirect=if($script:RouteBaselineResults.ContainsKey($id)){$script:RouteBaselineResults[$id]}else{$null}
        $measuredVpn=if($script:RouteVpnResults.ContainsKey($id)){$script:RouteVpnResults[$id]}else{$null}
        $swapComparisonValues=$connected -and $measuredDirect -and $measuredVpn
        $direct=if($swapComparisonValues){$measuredVpn}else{$measuredDirect}
        $vpn=if($swapComparisonValues){$measuredDirect}else{$measuredVpn}
        $active=if($connected -and $vpn){$vpn}elseif($direct){$direct}else{$null}
        $detail=if($active -and -not [string]::IsNullOrWhiteSpace([string]$active.ErrorReason)){
            [string]$active.ErrorReason
        }elseif($active){
            $tlsName=switch([string]$active.TlsProtocol){'Tls13'{'TLS 1.3'}'Tls12'{'TLS 1.2'}default{"TLS $($active.TlsProtocol)"}}
            $confirmation=switch($id){
                'youtube' {'Медиа-узел YouTube подтверждён'}
                'discord' {'WebSocket gateway подтверждён'}
                default {'Ответ сервиса подтверждён'}
            }
            "$confirmation · $tlsName"
        }else{
            'Ожидает проверки'
        }
        if($active){
            $phases=@()
            if([int64]$active.DnsMs -ge 0){$phases+="DNS $($active.DnsMs)"}
            if([int64]$active.TunnelMs -ge 0){$phases+="туннель $($active.TunnelMs)"}
            if([int64]$active.TcpMs -ge 0 -and [int64]$active.TunnelMs -lt 0){$phases+="TCP $($active.TcpMs)"}
            if([int64]$active.TlsMs -ge 0){$phases+="TLS $($active.TlsMs)"}
            if([int64]$active.TtfbMs -ge 0){$phases+="TTFB $($active.TtfbMs) ms"}
            $checked="$($phases -join ' · ') · $($active.CheckedAt.LocalDateTime.ToString('HH:mm:ss'))"
        }else{$checked='Ещё не проверялось'}
        $status=if($active){[string]$active.Status}else{'—'}
        $items+=,[pscustomobject]@{
            Service=[string]$target.Name
            DirectLatencyText=Format-RouteLatency $direct
            VpnLatencyText=Format-RouteLatency $vpn
            Status=$status
            StatusColor=if($active){Get-RouteStatusColor $status}else{'#747B9A'}
            Detail=$detail
            CheckedAtText=$checked
        }
    }
    $RouteQualityList.ItemsSource=$items
    $RouteDisconnectedMessage.Visibility=if($connected){'Collapsed'}else{'Visible'}
    $RouteCheckButton.IsEnabled=$connected -and -not $script:RouteQualityTask
    $RouteBaselineButton.IsEnabled=(-not $connected) -and -not $script:RouteQualityTask
}
function Update-RouteComparisonSummary {
    if($script:RouteQualityTask){
        $RouteComparisonSummary.Text=if($script:RouteQualityMode -eq 'vpn'){
            'Проверяем маршрут через VPN…'
        }else{
            'Проверяем прямой маршрут без VPN…'
        }
        return
    }
    if(-not $script:ConnectedAt){
        $RouteComparisonSummary.Text=if($script:RouteBaselineResults.Count){
            'Проверка без VPN завершена. Подключитесь и Luna автоматически сравнит маршруты.'
        }else{
            'Сначала можно проверить маршрут без VPN, затем подключиться и сравнить.'
        }
        return
    }
    if(-not $script:RouteVpnResults.Count){
        $RouteComparisonSummary.Text='Проверка через VPN запустится автоматически через несколько секунд.'
        return
    }
    if(-not $script:RouteBaselineResults.Count){
        $RouteComparisonSummary.Text='Маршрут через VPN проверен. Для сравнения сначала выполните проверку без VPN.'
        return
    }
    $improved=@()
    foreach($target in $script:RouteTargets){
        $id=[string]$target.Id
        if(-not $script:RouteBaselineResults.ContainsKey($id) -or -not $script:RouteVpnResults.ContainsKey($id)){continue}
        $direct=$script:RouteVpnResults[$id]
        $vpn=$script:RouteBaselineResults[$id]
        $becameAvailable=(-not [bool]$direct.IsAvailable) -and [bool]$vpn.IsAvailable
        $directLatency=[double]$direct.LatencyMs
        $vpnLatency=[double]$vpn.LatencyMs
        $meaningfullyFaster=[bool]$vpn.IsAvailable -and $directLatency -gt 0 -and $vpnLatency -gt 0 -and
            (($directLatency-$vpnLatency) -ge [Math]::Max([double]20,[double]($directLatency*0.15)))
        if($becameAvailable -or $meaningfullyFaster){$improved+=[string]$target.Name}
    }
    if($improved.Count){
        $profile=$State.profiles|Where-Object {$_.id -eq $State.selectedId}|Select-Object -First 1
        $serverName=if($profile){[string]$profile.name}else{'Текущий VPN'}
        $RouteComparisonSummary.Text="$serverName улучшил маршрут до $($improved -join ', ')."
    }else{
        $RouteComparisonSummary.Text='Заметного улучшения относительно прямого маршрута пока не обнаружено.'
    }
}
function Stop-RouteQualityCheck {
    if($script:RouteQualityCancellation){
        try{$script:RouteQualityCancellation.Cancel()}catch{}
        try{$script:RouteQualityCancellation.Dispose()}catch{}
    }
    $script:RouteQualityCancellation=$null
    $script:RouteQualityTask=$null
    $script:RouteQualityMode=''
    $script:RouteNextCheckAt=$null
}
function Start-RouteQualityCheck([bool]$ThroughVpn) {
    if($script:RouteQualityTask -and -not $script:RouteQualityTask.IsCompleted){return}
    if($ThroughVpn -and -not $script:ConnectedAt){return}
    Stop-RouteQualityCheck
    $script:RouteQualityCancellation=New-Object Threading.CancellationTokenSource
    $script:RouteQualityMode=if($ThroughVpn){'vpn'}else{'direct'}
    $proxyUrl=if($ThroughVpn){"http://127.0.0.1:$([int]$State.settings.localPort+1)"}else{$null}
    $script:RouteQualityTask=$script:RouteQualityService.CheckAsync(
        $script:RouteTargets,
        $proxyUrl,
        $script:RouteQualityCancellation.Token)
    $modeText=if($ThroughVpn){'через VPN'}else{'без VPN'}
    Add-AppLog "[INFO] Запущена проверка качества маршрута $modeText."
    Refresh-RouteQualityView
    Update-RouteComparisonSummary
}
function Complete-RouteQualityCheck {
    if(-not $script:RouteQualityTask -or -not $script:RouteQualityTask.IsCompleted){return}
    $mode=$script:RouteQualityMode
    try{
        $results=@($script:RouteQualityTask.GetAwaiter().GetResult())
        $resultMap=Get-RouteCheckMap $results
        if($mode -eq 'vpn'){
            $script:RouteVpnResults=$resultMap
            $script:RouteNextCheckAt=(Get-Date).AddSeconds(60)
        }else{
            $script:RouteBaselineResults=$resultMap
        }
        $script:RouteLastCheckedAt=Get-Date
        $available=@($results|Where-Object {$_.IsAvailable}).Count
        Add-AppLog "[INFO] Качество маршрута ($mode): доступно $available из $($results.Count)."
        foreach($result in $results){
            $phaseText=if([int64]$result.TunnelMs -ge 0){
                "туннель=$($result.TunnelMs)ms"
            }else{
                "DNS=$($result.DnsMs)ms, TCP=$($result.TcpMs)ms"
            }
            Add-AppLog "[INFO] $($result.Target.Name): итог=$($result.LatencyMs)ms, $phaseText, TLS=$($result.TlsMs)ms/$($result.TlsProtocol), TTFB=$($result.TtfbMs)ms, HTTP=$($result.HttpStatusCode), подтверждено=$($result.ContentValidated), байт=$($result.ResponseBytesRead)."
        }
        foreach($failure in @($results|Where-Object {-not $_.IsAvailable})){
            Add-AppLog "[WARN] Маршрут до $($failure.Target.Name): $($failure.Status), $($failure.ErrorReason)."
        }
    }catch [Threading.Tasks.TaskCanceledException]{
        Add-AppLog '[INFO] Проверка качества маршрута отменена.'
    }catch [OperationCanceledException]{
        Add-AppLog '[INFO] Проверка качества маршрута отменена.'
    }catch{
        Add-AppLog "[WARN] Не удалось проверить качество маршрута: $($_.Exception.Message)"
        if($mode -eq 'vpn'){$script:RouteNextCheckAt=(Get-Date).AddSeconds(60)}
    }finally{
        if($script:RouteQualityCancellation){
            try{$script:RouteQualityCancellation.Dispose()}catch{}
        }
        $script:RouteQualityCancellation=$null
        $script:RouteQualityTask=$null
        $script:RouteQualityMode=''
    }
    Refresh-RouteQualityView
    Update-RouteComparisonSummary
}
function Schedule-RouteQualityCheck {
    Stop-RouteQualityCheck
    $script:RouteVpnResults=@{}
    $script:RouteNextCheckAt=(Get-Date).AddSeconds(4)
    Refresh-RouteQualityView
    Update-RouteComparisonSummary
}
function Update-RouteQualityState {
    Complete-RouteQualityCheck
    if($script:ConnectedAt -and -not $script:RouteQualityTask -and
        $script:RouteNextCheckAt -and (Get-Date) -ge $script:RouteNextCheckAt){
        Start-RouteQualityCheck $true
    }
}
function Draw-LatencyGraph {
    $w=[Math]::Max([double]10,[double]$LatencyCanvas.ActualWidth);$h=[Math]::Max([double]10,[double]$LatencyCanvas.ActualHeight)
    $values=@($script:LatencyHistory)
    $LatencyCanvas.Children.Clear();$LossCanvas.Children.Clear()
    foreach($level in @(0,50,100,300,500,700,999)){
        $gridLine=New-Object Windows.Shapes.Line
        $gridLine.X1=0;$gridLine.X2=$w;$gridLine.Y1=$h-($level/999*$h);$gridLine.Y2=$gridLine.Y1
        $gridLine.Stroke='#20254B';$gridLine.StrokeThickness=0.7;[void]$LatencyCanvas.Children.Add($gridLine)
    }
    $valid=@($values|?{$_ -ge 0})
    if($valid.Count -gt 1){
        $diffs=@();for($i=1;$i -lt $valid.Count;$i++){$diffs+=[Math]::Abs($valid[$i]-$valid[$i-1])}
        $JitterLabel.Text="$([Math]::Round(($diffs|Measure-Object -Average).Average,1)) ms"
    }else{$JitterLabel.Text='—'}
    $loss=if($values.Count){[Math]::Round((@($values|?{$_ -lt 0}).Count/$values.Count)*100,1)}else{0}
    $PacketLossLabel.Text="$loss%";$PacketLossLabel.Foreground=if($loss -eq 0){'#65E6A7'}else{'#FF6B7A'}
    if($values.Count){
        $startX=$w-(($values.Count-1)*$w/59)
        for($i=1;$i -lt $values.Count;$i++){
            $previous=[double]$values[$i-1];$current=[double]$values[$i]
            $x1=$startX+(($i-1)*$w/59);$x2=$startX+($i*$w/59)
            $plotPrevious=if($previous -lt 0){999}else{[Math]::Min($previous,999)}
            $plotCurrent=if($current -lt 0){999}else{[Math]::Min($current,999)}
            $y1=$h-($plotPrevious/999*$h);$y2=$h-($plotCurrent/999*$h)
            $color=if($current -lt 0){'#73778A'}elseif($current -le 200){'#55E69D'}elseif($current -le 500){'#FFD166'}elseif($current -le 700){'#FF9F43'}else{'#FF5D6C'}
            $line=New-Object Windows.Shapes.Line
            $line.X1=$x1;$line.X2=$x2;$line.Y1=$y1;$line.Y2=$y2;$line.Stroke=$color;$line.StrokeThickness=2.6
            $line.ToolTip=if($current -lt 0){"-$([Math]::Round(59-$i)) сек: Timeout"}else{"-$([Math]::Round(59-$i)) сек: $current ms"}
            [void]$LatencyCanvas.Children.Add($line)
            $lossLine=New-Object Windows.Shapes.Line
            $lossLine.X1=$x1;$lossLine.X2=$x2;$lossLine.Y1=if($previous -lt 0){2}else{$LossCanvas.ActualHeight-3};$lossLine.Y2=if($current -lt 0){2}else{$LossCanvas.ActualHeight-3}
            $lossLine.Stroke=if($current -lt 0){'#FF5D6C'}else{'#55E69D'};$lossLine.StrokeThickness=2
            $lossLine.ToolTip="Неудачная проверка: $(if($current -lt 0){'да'}else{'нет'})"
            [void]$LossCanvas.Children.Add($lossLine)
        }
    }
}
function Start-LatencyProbe {
    if(-not $script:ConnectedAt -or $script:PingTask){return}
    $profile=$State.profiles|?{$_.id -eq $State.selectedId}|Select-Object -First 1
    if(-not $profile){return}
    $script:PingTask=[LunaLatencyProbe]::MeasureTcpAsync([string]$profile.host,[int]$profile.port,3000)
}
function Complete-LatencyProbe {
    if(-not $script:PingTask){Start-LatencyProbe;return}
    if(-not $script:PingTask.IsCompleted){return}
    try{$ms=[int]$script:PingTask.GetAwaiter().GetResult()}catch{$ms=-1}
    $script:PingTask=$null
    [void]$script:LatencyHistory.Add([double]$ms)
    while($script:LatencyHistory.Count -gt 60){$script:LatencyHistory.RemoveAt(0)}
    $text=if($ms -lt 0){'таймаут'}else{"$ms ms"}
    $LatencyLabel.Text=$text;$GraphValue.Text=$text
    $profile=$State.profiles|?{$_.id -eq $State.selectedId}|Select-Object -First 1
    if($profile){$profile.latency=$text}
    Draw-LatencyGraph
    Start-LatencyProbe
}
function Update-SelectedLatencyDisplay([string]$Text='—') {
    $profile=$State.profiles|Where-Object {$_.id -eq $State.selectedId}|Select-Object -First 1
    $LatencyServerName.Text=if($profile){[string]$profile.name}else{'Сервер не выбран'}
    $LatencyLabel.Text=$Text
    $LatencyLastCheckedHome.Text=if($script:LatencyLastCheckedAt){"Последняя проверка: $($script:LatencyLastCheckedAt.ToString('dd.MM.yyyy HH:mm:ss'))"}else{'Последняя проверка: ещё не выполнялась'}
}
function Test-LunaVpnSessionActive {
    try{
        return [bool]($script:ConnectedAt -and $script:CoreProcess -and -not $script:CoreProcess.HasExited)
    }catch{return $false}
}
function Test-SelectedLatencyAutoRefreshAllowed {
    return [bool]($script:SelectedLatencyAutoEnabled -and $LatencyAutoRefresh.IsChecked -eq $true -and (Test-LunaVpnSessionActive))
}
function Start-SelectedLatencyProbe([switch]$Automatic) {
    if($script:SelectedPingTask){return}
    if($Automatic -and -not (Test-SelectedLatencyAutoRefreshAllowed)){return}
    $profile=$State.profiles|Where-Object {$_.id -eq $State.selectedId}|Select-Object -First 1
    if(-not $profile){Update-SelectedLatencyDisplay '—';return}
    $script:SelectedPingProfileId=[string]$profile.id
    $script:SelectedPingAutomatic=[bool]$Automatic
    $script:SelectedPingGeneration=[int64]$script:SelectedLatencyAutoGeneration
    $LatencyRefreshHome.IsEnabled=$false
    $script:SelectedPingTask=[LunaLatencyProbe]::MeasureTcpAsync([string]$profile.host,[int]$profile.port,3000)
}
function Complete-SelectedLatencyProbe {
    if(-not $script:SelectedPingTask -or -not $script:SelectedPingTask.IsCompleted){return}
    try{$ms=[int]$script:SelectedPingTask.GetAwaiter().GetResult()}catch{$ms=-1}
    $script:SelectedPingTask=$null
    $LatencyRefreshHome.IsEnabled=$true
    if($script:SelectedPingButton){$script:SelectedPingButton.Content='↻';$script:SelectedPingButton.IsEnabled=$true;$script:SelectedPingButton=$null}
    $automaticResult=[bool]$script:SelectedPingAutomatic
    $script:SelectedPingAutomatic=$false
    if($automaticResult -and (-not (Test-SelectedLatencyAutoRefreshAllowed) -or $script:SelectedPingGeneration -ne $script:SelectedLatencyAutoGeneration)){return}
    if($script:SelectedPingProfileId -ne [string]$State.selectedId){return}
    $text=if($ms -lt 0){'таймаут'}else{"$ms ms"}
    $script:LatencyLastCheckedAt=Get-Date
    $profile=$State.profiles|Where-Object {$_.id -eq $State.selectedId}|Select-Object -First 1
    if($profile){$profile.latency=$text;$profile.healthStatus=if($ms -lt 0){'Недоступен'}else{'Доступен'}}
    [void]$script:LatencyHistory.Add([double]$ms)
    while($script:LatencyHistory.Count -gt 60){$script:LatencyHistory.RemoveAt(0)}
    $GraphValue.Text=$text
    Draw-LatencyGraph
    Update-SelectedLatencyDisplay $text
    Refresh-Profiles
}
function Test-ProfileLatency($Profile) {
    $client=New-Object Net.Sockets.TcpClient
    $watch=[Diagnostics.Stopwatch]::StartNew()
    try{
        $connect=$client.ConnectAsync($Profile.host,[int]$Profile.port)
        $timeout=[Threading.Tasks.Task]::Delay(3000)
        $race=[Threading.Tasks.Task]::WhenAny($connect,$timeout)
        Wait-UiTask $race
        if($connect.IsCompleted -and $client.Connected){return [Math]::Max([long]1,[long]$watch.ElapsedMilliseconds)}
        return -1
    }finally{$client.Close()}
}
function Test-AllProfileLatencies {
    $profiles=@($State.profiles|?{$null -eq $_.enabled -or [bool]$_.enabled})
    if(-not $profiles.Count){return @{total=0;available=0;unavailable=0}}
    $available=0;$unavailable=0;$completed=0;$batchSize=20
    for($offset=0;$offset -lt $profiles.Count;$offset+=$batchSize){
        $jobs=@()
        $last=[Math]::Min($offset+$batchSize,$profiles.Count)
        for($i=$offset;$i -lt $last;$i++){
            $profile=$profiles[$i]
            try{
                $client=New-Object Net.Sockets.TcpClient
                $watch=[Diagnostics.Stopwatch]::StartNew()
                $task=$client.ConnectAsync([string]$profile.host,[int]$profile.port)
                $jobs+=,[pscustomobject]@{Profile=$profile;Client=$client;Watch=$watch;Task=$task;Done=$false}
            }catch{
                $profile['latency']='ошибка';$profile['healthStatus']='Недоступен'
                $unavailable++;$completed++
            }
        }
        while(@($jobs|?{-not $_.Done}).Count){
            foreach($job in @($jobs|?{-not $_.Done})){
                if($job.Task.IsCompleted -or $job.Watch.ElapsedMilliseconds -ge 3000){
                    $ok=$job.Task.IsCompleted -and $job.Client.Connected
                    if($ok){
                        $ms=[Math]::Max([long]1,[long]$job.Watch.ElapsedMilliseconds)
                        $job.Profile['latency']="$ms ms";$job.Profile['healthStatus']='Доступен';$available++
                    }else{
                        $job.Profile['latency']='таймаут';$job.Profile['healthStatus']='Недоступен';$unavailable++
                    }
                    $job.Client.Close();$job.Done=$true;$completed++
                    $LoadingText.Text="Проверено $completed из $($profiles.Count)…"
                }
            }
            $Window.Dispatcher.Invoke([action]{},[Windows.Threading.DispatcherPriority]::Background)
            Start-Sleep -Milliseconds 20
        }
        Refresh-Profiles
    }
    Save-State
    Add-AppLog "Массовая проверка: доступно $available, недоступно $unavailable, всего $($profiles.Count)."
    return @{total=$profiles.Count;available=$available;unavailable=$unavailable}
}
function Stop-Tunnel {
    Stop-RouteQualityCheck
    $script:RouteVpnResults=@{}
    $script:SelectedLatencyAutoGeneration=[int64]($script:SelectedLatencyAutoGeneration+1)
    try{[LunaTrafficMeter]::Stop()}catch{}
    if($script:CoreProcess -and -not $script:CoreProcess.HasExited){Stop-Process -Id $script:CoreProcess.Id -Force}
    $script:CoreProcess=$null; Set-SystemProxy $false
    $script:PingTask=$null
    $script:ConnectedAt=$null;$ConnectLabel.Text='ПОДКЛЮЧИТЬ';$SessionTime.Text='00:00:00';$ConnectionStatus.Text='Нет подключения';$ConnectButton.BorderBrush='#7567FF'
    $script:NetworkStart=$null;$script:NetworkLast=$null;$script:NetworkLastAt=$null;$script:SpeedSamples=@()
    $UpSpeed.Text='↑ 0 Mbps';$DownSpeed.Text='↓ 0 Mbps';$HomeUpSpeed.Text='↑ 0 Mbps';$HomeDownSpeed.Text='↓ 0 Mbps'
    $AppsTraffic.ItemsSource=@();$AppsSummary.Text='Ожидаем трафик приложений через Luna…'
    $CoreStatus.Text='● VPN не активен';$CoreStatus.Foreground='#AEB4CC';$ProtectionDetail.Text='Все компоненты работают.'
    Set-TrayStatus 'Luna VPN — нет подключения'
    $script:LatencyHistory.Clear();$LatencyLabel.Text='—';$GraphValue.Text='—';Draw-LatencyGraph
    Refresh-RouteQualityView;Update-RouteComparisonSummary
}
function Start-Tunnel {
    $core=Get-CorePath; if(-not $core){Show-Notice 'Требуется компонент' 'Сначала установите Xray-core в настройках.' 'WARN';return}
    if($State.settings.mode -eq 'TUN' -and (Request-TunElevation)){return}
    $p=$State.profiles|?{$_.id -eq $State.selectedId}|Select-Object -First 1
    if(-not $p){Show-Notice 'Сервер не выбран' 'Добавьте и выберите сервер.' 'WARN';return}
    if($null -ne $p.enabled -and -not [bool]$p.enabled){Show-Notice 'Сервер отключён' 'Этот сервер отключён в локальной конфигурации.' 'WARN';return}
    if($p.extra.security -eq 'reality' -and (-not $p.extra.publicKey -or -not $p.extra.shortId)){
        Show-Notice 'Неполная конфигурация' 'Для Reality-сервера не заполнены publicKey или shortId.' 'ERROR';return
    }
    try{
        $preferredPort=[int]$State.settings.localPort
        $freePort=Get-AvailablePortBlock $preferredPort
        if($freePort -ne $preferredPort){
            $State.settings.localPort=$freePort;$PortBox.Text=$freePort
            Add-AppLog "Порты $preferredPort/$($preferredPort+1) заняты. Выбраны $freePort/$($freePort+1)."
            Save-State
        }
        $xrayPort=$freePort+2
        if($State.settings.mode -eq 'TUN'){
            $coreWorkingDirectory=Split-Path -Parent $core
            $wintunTarget=Join-Path $coreWorkingDirectory 'wintun.dll'
            if(-not (Test-Path $wintunTarget) -and $env:LUNA_APP_DIR){
                $wintunSource=Join-Path $env:LUNA_APP_DIR 'core\wintun.dll'
                if(Test-Path $wintunSource){Copy-Item -LiteralPath $wintunSource -Destination $wintunTarget -Force}
            }
            if(-not (Test-Path $wintunTarget)){throw 'Не найден wintun.dll. Переустановите Luna или Xray-core.'}
        }
        $configJson=Build-XrayConfig $p $xrayPort|ConvertTo-Json -Depth 50
        [IO.File]::WriteAllText($ConfigFile,$configJson,(New-Object Text.UTF8Encoding($false)))
        $testOutput=@(& $core run -test -config $ConfigFile 2>&1)
        if($LASTEXITCODE -ne 0){
            $detail=($testOutput|Select-Object -Last 1)
            Add-AppLog "Проверка Xray не пройдена: $detail"
            throw "Конфигурация несовместима с Xray: $detail"
        }
        Remove-Item $RuntimeErrorFile,$RuntimeOutputFile -Force -ErrorAction SilentlyContinue
        $coreWorkingDirectory=Split-Path -Parent $core
        $xrayArguments='run -config "{0}"' -f $ConfigFile
        $script:CoreProcess=Start-Process -FilePath $core -ArgumentList $xrayArguments -WorkingDirectory $coreWorkingDirectory -WindowStyle Hidden -RedirectStandardError $RuntimeErrorFile -RedirectStandardOutput $RuntimeOutputFile -PassThru
        Start-Sleep -Milliseconds 800
        if($script:CoreProcess.HasExited){
            $detail=''
            if(Test-Path $RuntimeErrorFile){$detail=(Get-Content $RuntimeErrorFile -Tail 1)}
            if(-not $detail -and (Test-Path $RuntimeOutputFile)){$detail=(Get-Content $RuntimeOutputFile -Tail 1)}
            if(-not $detail){$detail='Xray завершился без сообщения.'}
            Add-AppLog "Xray завершился: $detail"
            throw $detail
        }
        $splitProcesses=@();$splitDomains=@();$splitIps=@()
        if([bool]$State.settings.splitEnabled){
            $splitProcesses=@($State.settings.splitApps+$State.settings.splitGames|Where-Object {$_}|Select-Object -Unique)
            $splitDomains=@($State.settings.splitDomains|Where-Object {$_}|Select-Object -Unique)
            $splitIps=@($State.settings.splitIps|Where-Object {$_}|Select-Object -Unique)
        }
        [LunaTrafficMeter]::Start($freePort,$xrayPort,$freePort+1,$xrayPort+1,[string[]]$splitProcesses,[string[]]$splitDomains,[string[]]$splitIps)
        if($State.settings.mode -eq 'System proxy'){Set-SystemProxy $true}
        $script:ConnectedAt=Get-Date;$script:NetworkStart=Get-NetworkTotals;$script:NetworkLast=$script:NetworkStart;$script:NetworkLastAt=$script:ConnectedAt
        $script:SpeedSamples=@([pscustomobject]@{time=$script:ConnectedAt;received=[int64]$script:NetworkStart.received;sent=[int64]$script:NetworkStart.sent})
        $ConnectLabel.Text='ПОДКЛЮЧЕНО';$ConnectionStatus.Text='Защищённый маршрут активен';$ConnectButton.BorderBrush='#74E5B2';$CoreStatus.Text='● VPN активен';$CoreStatus.Foreground='#74E5B2';$ProtectionDetail.Text='Соединение защищено.'
        Set-TrayStatus "Luna VPN — подключено: $($p.name)"
        $StatCountry.Text="Страна: $(Get-Or $p.country 'не указана')";$StatEncryption.Text="Шифрование: $($p.protocol.ToUpper()) / $(Get-Or $p.extra.security 'none')"
        $StatIPv4.Text='Публичный IPv4: в разработке';$StatProvider.Text='Провайдер: в разработке'
        Start-ConnectionWave;Schedule-RouteQualityCheck
    }catch{$detail=$_.Exception.Message;Stop-Tunnel;Show-Notice 'Не удалось подключиться' $detail 'ERROR' $true}
}
function Update-Subscription($sub) {
    $previousSelection=$State.profiles|?{$_.id -eq $State.selectedId}|Select-Object -First 1
    $machineId=''
    try{$machineId=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid}catch{}
    $headers=@{
        # Compatibility identifier required by subscriptions that target Happ Desktop.
        'User-Agent'='Happ/2.6.0/Windows/2603201341504'
        'Accept'='text/plain, application/octet-stream, */*'
        'X-Device-OS'='Windows'
        'X-Ver-OS'=[Environment]::OSVersion.Version.ToString()
        'X-Device-model'='Windows PC'
        'X-Device-Locale'=[Globalization.CultureInfo]::CurrentUICulture.Name
    }
    if($machineId){$headers['X-HWID']=$machineId}
    $lastError=$null
    $r=$null
    for($attempt=1;$attempt -le 3;$attempt++){
        try{
            $r=Invoke-AsyncHttp $sub.url $headers
            break
        }catch{
            $lastError=$_
            if($attempt -lt 3){Start-Sleep -Milliseconds (500*$attempt)}
        }
    }
    if(-not $r){throw $lastError.Exception}
    if($r.ContentType -like '*yaml*'){
        $items=Parse-ClashYaml $r.Content
    }else{
        $items=Parse-SubscriptionBody $r.Content
    }
    $unsupported=@($items|?{[int]$_.port -eq 1 -and $_.name -match 'не поддерживается'})
    if($unsupported.Count){
        $clashHeaders=@{'User-Agent'='clash-verge/v2';'Accept'='text/yaml, */*'}
        $r=Invoke-AsyncHttp $sub.url $clashHeaders
        $items=Parse-ClashYaml $r.Content
    }
    if(-not $items.Count){throw 'Подписка не содержит поддерживаемых серверов.'}
    $State.profiles=@($State.profiles|?{$_.subscriptionId -ne $sub.id})
    foreach($p in $items){$p.subscriptionId=$sub.id;$State.profiles+=,$p}
    if($previousSelection -and $previousSelection.subscriptionId -eq $sub.id){
        $replacement=$items|?{$_.name -eq $previousSelection.name -and $_.host -eq $previousSelection.host}|Select-Object -First 1
        if($replacement){$State.selectedId=$replacement.id}
    }
    return $items.Count
}

$NavHome.Add_Click({Show-Page $HomePage});$NavServers.Add_Click({Show-Page $ServersPage});$NavSubs.Add_Click({Show-Page $SubsPage});$NavRoutes.Add_Click({Show-Page $RoutesPage});$NavLogs.Add_Click({Show-Page $LogsPage});$NavStats.Add_Click({Show-Page $StatsPage});$NavSplit.Add_Click({Show-Page $SplitPage});$NavApps.Add_Click({Show-Page $AppsPage});$NavSettings.Add_Click({Show-Page $SettingsPage});$NavExperts.Add_Click({Show-Page $ExpertsPage});$NavAbout.Add_Click({Show-Page $AboutPage})
$ConnectButton.Add_Click({if($script:CoreProcess -and -not $script:CoreProcess.HasExited){Stop-Tunnel}else{Start-Tunnel}})
$RouteBaselineButton.Add_Click({Start-RouteQualityCheck $false})
$RouteCheckButton.Add_Click({Start-RouteQualityCheck $true})
$QuickServer.Add_SelectionChanged({if(-not $script:RefreshingProfiles -and $QuickServer.SelectedIndex -ge 0 -and $QuickServer.SelectedIndex -lt $State.profiles.Count){$State.selectedId=$State.profiles[$QuickServer.SelectedIndex].id;$script:LatencyLastCheckedAt=$null;Save-State;Refresh-Profiles;Update-SelectedLatencyDisplay ([string]$State.profiles[$QuickServer.SelectedIndex].latency)}})
$HomeServerList.Add_SelectionChanged({
    if($HomeServerList.SelectedItem -and -not $script:RefreshingProfiles){
        $State.selectedId=[string]$HomeServerList.SelectedItem.id
        $script:LatencyLastCheckedAt=$null
        Save-State
        Refresh-Profiles
        Update-SelectedLatencyDisplay ([string]$HomeServerList.SelectedItem.latency)
    }
})
$HomeServerList.AddHandler([Windows.Controls.Button]::ClickEvent,[Windows.RoutedEventHandler]{
    param($sender,$eventArgs)
    $source=$eventArgs.OriginalSource
    while($source -and $source -isnot [Windows.Controls.Button]){$source=[Windows.Media.VisualTreeHelper]::GetParent($source)}
    if($source -is [Windows.Controls.Button] -and $source.Tag){
        $State.selectedId=[string]$source.Tag
        $script:LatencyLastCheckedAt=$null
        $script:SelectedPingButton=$source
        $source.IsEnabled=$false
        $source.Content='◌'
        Save-State
        $selectedProfile=$State.profiles|Where-Object {$_.id -eq $State.selectedId}|Select-Object -First 1
        if($selectedProfile){$SelectedServer.Text=$selectedProfile.name;$LatencyServerName.Text=$selectedProfile.name}
        Start-SelectedLatencyProbe
        $eventArgs.Handled=$true
    }
})
$HomePingAllButton.Add_Click({
    $HomePingAllButton.IsEnabled=$false;$HomePingAllButton.Content='◌ Пинг всех'
    try{$result=Test-AllProfileLatencies;Refresh-Profiles;Show-Notice 'Проверка завершена' "Доступно: $($result.available) · Недоступно: $($result.unavailable) · Всего: $($result.total)" 'SUCCESS'}
    finally{$HomePingAllButton.Content='⚡ Пинг всех';$HomePingAllButton.IsEnabled=$true}
})
$HomeModeBox.Add_SelectionChanged({
    if($HomeModeBox.SelectedIndex -lt 0){return}
    $State.settings.mode=if($HomeModeBox.SelectedIndex -eq 1){'TUN'}else{'System proxy'}
    $ModeBox.SelectedIndex=$HomeModeBox.SelectedIndex;$SplitScopeBox.SelectedIndex=$HomeModeBox.SelectedIndex;$ModeLabel.Text=$State.settings.mode;Save-State;Update-SplitView
})
$LatencyRefreshHome.Add_Click({Start-SelectedLatencyProbe})
$LatencyAutoRefresh.Add_Checked({$script:SelectedLatencyAutoEnabled=$true;$State.settings.latencyAutoRefresh=$true;Save-State})
$LatencyAutoRefresh.Add_Unchecked({$script:SelectedLatencyAutoEnabled=$false;$script:SelectedLatencyAutoGeneration=[int64]($script:SelectedLatencyAutoGeneration+1);$State.settings.latencyAutoRefresh=$false;Save-State})
$SearchBox.Add_TextChanged({Refresh-Profiles})
$ImportClipboard.Add_Click({try{$links=Parse-SubscriptionBody ([Windows.Clipboard]::GetText());if(-not $links.Count){$links=@(Parse-ProxyLink ([Windows.Clipboard]::GetText()))};$State.profiles+=@($links);Save-State;Refresh-Profiles;Show-Notice 'Импорт завершён' "Добавлено: $(@($links).Count)" 'SUCCESS'}catch{Show-Notice 'Ошибка импорта' $_.Exception.Message 'ERROR'}})
$AddLink.Add_Click({$text=[Microsoft.VisualBasic.Interaction]::InputBox('Вставьте ссылку VLESS, VMess, Trojan, Shadowsocks или SOCKS5:','Добавить сервер','');if($text){try{$State.profiles+=,(Parse-ProxyLink $text);Save-State;Refresh-Profiles;Show-Notice 'Сервер добавлен' 'Конфигурация сохранена.' 'SUCCESS'}catch{Show-Notice 'Ошибка импорта' $_.Exception.Message 'ERROR'}}})
$RefreshBackendButton.Add_Click({Sync-LunaBackend})
$ServerList.Add_SelectionChanged({
    if($ServerList.SelectedItem -and -not $script:RefreshingProfiles){
        $State.selectedId=$ServerList.SelectedItem.id
        $index=-1
        for($i=0;$i -lt $State.profiles.Count;$i++){if($State.profiles[$i].id -eq $State.selectedId){$index=$i;break}}
        $script:RefreshingProfiles=$true
        try{if($index -ge 0){$QuickServer.SelectedIndex=$index;$HomeServerList.SelectedItem=($HomeServerList.ItemsSource|Where-Object {$_.id -eq $State.selectedId}|Select-Object -First 1);$SelectedServer.Text=$State.profiles[$index].name;$LatencyServerName.Text=$State.profiles[$index].name}}finally{$script:RefreshingProfiles=$false}
        Save-State
    }
})
$DeleteServer.Add_Click({if($ServerList.SelectedItem){$id=$ServerList.SelectedItem.id;$profile=$State.profiles|?{$_.id -eq $id}|Select-Object -First 1;if($profile.source -eq 'backend-api'){Show-Notice 'Сервер управляется backend' 'Удалите или отключите его через панель администратора Luna.' 'INFO';return};$State.profiles=@($State.profiles|?{$_.id -ne $id});Save-State;Refresh-Profiles}})
$PingAllButton.Add_Click({Set-Loading $true 'Запускаем проверку серверов…';try{$result=Test-AllProfileLatencies;Refresh-Profiles}finally{Set-Loading $false};Show-Notice 'Проверка завершена' "Доступно: $($result.available) · Недоступно: $($result.unavailable) · Всего: $($result.total)" 'SUCCESS'})
$PingButton.Add_Click({if($ServerList.SelectedItem){$p=$State.profiles|?{$_.id -eq $ServerList.SelectedItem.id}|Select-Object -First 1;Set-Loading $true 'Проверяем задержку…';try{$ms=Test-ProfileLatency $p;if($ms -lt 0){$p['latency']='таймаут';$p['healthStatus']='Недоступен'}else{$p['latency']="$ms ms";$p['healthStatus']='Доступен'};Save-State;Refresh-Profiles}finally{Set-Loading $false}}})
$AddSubscription.Add_Click({if($SubscriptionUrl.Text){$sub=@{id=[guid]::NewGuid().ToString();name=([Uri]$SubscriptionUrl.Text).Host;url=$SubscriptionUrl.Text};$State.subscriptions+=,$sub;Set-Loading $true 'Добавляем подписку…';try{$count=Update-Subscription $sub;Save-State;Refresh-Profiles;Refresh-Subscriptions;$SubscriptionUrl.Text='';Show-Notice 'Подписка добавлена' "Получено серверов: $count" 'SUCCESS'}catch{$State.subscriptions=@($State.subscriptions|?{$_.id -ne $sub.id});Show-Notice 'Не удалось добавить подписку' $_.Exception.Message 'ERROR' $true}finally{Set-Loading $false}}})
$UpdateSubscriptions.Add_Click({Set-Loading $true 'Обновляем подписки…';$errors=@();try{$index=0;foreach($s in $State.subscriptions){$index++;$LoadingText.Text="Обновляем подписку $index из $($State.subscriptions.Count)…";try{[void](Update-Subscription $s)}catch{$errors+=$_.Exception.Message}};Save-State;Refresh-Profiles;Refresh-Subscriptions}finally{Set-Loading $false};if($errors.Count){Show-Notice 'Не все подписки обновлены' ($errors -join "`n") 'WARN' $true}else{Show-Notice 'Подписки обновлены' 'Список серверов актуален.' 'SUCCESS'}})
$DeleteSubscription.Add_Click({if($SubscriptionList.SelectedItem){$id=$SubscriptionList.SelectedItem.id;$State.subscriptions=@($State.subscriptions|?{$_.id -ne $id});$State.profiles=@($State.profiles|?{$_.subscriptionId -ne $id});if(-not @($State.profiles|?{$_.id -eq $State.selectedId}).Count){$State.selectedId=if(@($State.profiles).Count){[string]$State.profiles[0].id}else{''}};Save-State;Refresh-Subscriptions;Refresh-Profiles;Add-AppLog "Подписка удалена: $id"}})
$SaveRoutes.Add_Click({$State.settings.directDomains=$DirectDomains.Text;$State.settings.blockDomains=$BlockDomains.Text;$State.settings.bypassLan=$BypassLan.IsChecked;$State.settings.blockAds=$BlockAds.IsChecked;Save-State;Show-Notice 'Правила сохранены' 'Переподключитесь для применения.' 'SUCCESS'})
$LogFilter.SelectedIndex=0
$LogFilter.Add_SelectionChanged({$script:LogFollow=$true;$LiveLogButton.Visibility='Collapsed';Refresh-LogView});$LogSearch.Add_TextChanged({$script:LogFollow=$true;$LiveLogButton.Visibility='Collapsed';Refresh-LogView})
$LogView.Add_PreviewMouseWheel({$script:LogFollow=$false;$LiveLogButton.Visibility='Visible'})
$LiveLogButton.Add_Click({$script:LogFollow=$true;$LiveLogButton.Visibility='Collapsed';Refresh-LogView})
$ClearLogs.Add_Click({[IO.File]::WriteAllText($LogFile,'',[Text.UTF8Encoding]::new($false));Refresh-LogView})
$ExportLogs.Add_Click({$dialog=New-Object Microsoft.Win32.SaveFileDialog;$dialog.Filter='Text files (*.txt)|*.txt';$dialog.FileName="Luna-log-$(Get-Date -Format 'yyyyMMdd-HHmm').txt";if($dialog.ShowDialog()){$content=if(Test-Path $LogFile){Get-Content -Raw $LogFile}else{''};[IO.File]::WriteAllText($dialog.FileName,$content,[Text.UTF8Encoding]::new($true))}})
$SaveSettings.Add_Click({
    $oldLanguage=$State.settings.language;$oldTheme=$State.settings.theme
    $State.settings.mode=if($ModeBox.SelectedIndex -eq 1){'TUN'}else{'System proxy'};$State.settings.localPort=[int]$PortBox.Text;$State.settings.dns=$DnsBox.Text;$State.settings.autoStart=$AutoStart.IsChecked;$State.settings.startMinimized=$StartMinimized.IsChecked
    $supportedLanguages=@('Русский','English')
    $languageIndex=[Math]::Max([int]0,[Math]::Min([int]$LanguageBox.SelectedIndex,[int]($supportedLanguages.Count-1)))
    $State.settings.language=$supportedLanguages[$languageIndex]
    $State.settings.theme=@('Темная','Светлая','Авто')[[Math]::Max([int]0,[int]$ThemeBox.SelectedIndex)]
    $State.settings.autoConnect=$AutoConnect.IsChecked;$State.settings.killSwitch=$KillSwitch.IsChecked;$State.settings.dnsProtection=$DnsProtection.IsChecked;$State.settings.enableIPv6=$EnableIPv6.IsChecked;$State.settings.webRtcProtection=$WebRtcProtection.IsChecked;$State.settings.dnsLeakProtection=$DnsLeakProtection.IsChecked;$State.settings.checkUpdates=$CheckUpdates.IsChecked;$State.settings.anonymousStats=$AnonymousStats.IsChecked
    $State.settings.telemetryConsentAsked=$true
    $run='HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    $launchPath=if($env:LUNA_EXECUTABLE_PATH){$env:LUNA_EXECUTABLE_PATH}else{$PSCommandPath}
    $runValue="`"$launchPath`""
    if($StartMinimized.IsChecked){$runValue+=' --tray'}
    if($AutoStart.IsChecked){Set-ItemProperty $run Luna $runValue}else{Remove-ItemProperty $run Luna -ErrorAction SilentlyContinue}
    Save-State;$ModeLabel.Text=$State.settings.mode;$script:SettingsDirty=$false;$SaveSettings.IsEnabled=$false
    if($oldLanguage -ne $State.settings.language -or $oldTheme -ne $State.settings.theme){Show-Notice 'Требуется перезапуск приложения Luna' 'Новый язык и тема применятся после следующего запуска.' 'INFO'}
})
$SplitEnabled.Add_Checked({
    $State.settings.splitEnabled=$true;Save-State;Update-SplitView
    if(-not $script:InitializingUi){
        if($script:CoreProcess -and -not $script:CoreProcess.HasExited){Apply-SplitConfiguration}else{Show-Notice 'Split Tunneling включён' 'При подключении Luna запросит права администратора и применит исключения ко всему системному трафику.' 'SUCCESS'}
    }
})
$SplitEnabled.Add_Unchecked({$State.settings.splitEnabled=$false;Save-State;Update-SplitView;if(-not $script:InitializingUi -and $script:CoreProcess -and -not $script:CoreProcess.HasExited){Apply-SplitConfiguration}})
$AddSplitDomain.Add_Click({try{$value=Normalize-SplitDomain $SplitDomainInput.Text;$State.settings.splitDomains=@($State.settings.splitDomains+$value|Select-Object -Unique);$SplitDomainInput.Text='';Save-State;Update-SplitView}catch{Show-Notice 'Сайт не добавлен' $_.Exception.Message 'WARN'}})
$RemoveSplitDomain.Add_Click({if($SplitDomainList.SelectedItem){$remove=[string]$SplitDomainList.SelectedItem;$State.settings.splitDomains=@($State.settings.splitDomains|Where-Object {$_ -ne $remove});Save-State;Update-SplitView}})
$AddSplitIp.Add_Click({try{$value=Normalize-SplitIp $SplitIpInput.Text;$State.settings.splitIps=@($State.settings.splitIps+$value|Select-Object -Unique);$SplitIpInput.Text='';Save-State;Update-SplitView}catch{Show-Notice 'IP не добавлен' $_.Exception.Message 'WARN'}})
$RemoveSplitIp.Add_Click({if($SplitIpList.SelectedItem){$remove=[string]$SplitIpList.SelectedItem;$State.settings.splitIps=@($State.settings.splitIps|Where-Object {$_ -ne $remove});Save-State;Update-SplitView}})
$AddSplitApp.Add_Click({Add-SplitExecutables 'app'})
$AddRunningSplitApp.Add_Click({Show-RunningProcessPicker 'app'})
$RemoveSplitApp.Add_Click({if($SplitAppList.SelectedItem){$remove=[string]$SplitAppList.SelectedItem;$State.settings.splitApps=@($State.settings.splitApps|Where-Object {$_ -ne $remove});Save-State;Update-SplitView}})
$AddSplitGame.Add_Click({Add-SplitExecutables 'game'})
$AddRunningSplitGame.Add_Click({Show-RunningProcessPicker 'game'})
$RemoveSplitGame.Add_Click({if($SplitGameList.SelectedItem){$remove=[string]$SplitGameList.SelectedItem;$State.settings.splitGames=@($State.settings.splitGames|Where-Object {$_ -ne $remove});Save-State;Update-SplitView}})
$ApplySplitRules.Add_Click({Apply-SplitConfiguration})
$SplitScopeBox.Add_SelectionChanged({
    if($script:InitializingUi -or $SplitScopeBox.SelectedIndex -lt 0){return}
    $State.settings.mode=if($SplitScopeBox.SelectedIndex -eq 1){'TUN'}else{'System proxy'}
    $HomeModeBox.SelectedIndex=$SplitScopeBox.SelectedIndex
    $ModeBox.SelectedIndex=$SplitScopeBox.SelectedIndex
    $ModeLabel.Text=$State.settings.mode
    Save-State;Update-SplitView
})
$ExportSplitRules.Add_Click({
    $dialog=New-Object Microsoft.Win32.SaveFileDialog;$dialog.Filter='Luna Split Tunneling (*.json)|*.json';$dialog.FileName="luna-split-rules-$(Get-Date -Format 'yyyyMMdd').json"
    if($dialog.ShowDialog()){$export=[ordered]@{schema='luna.split.v2';enabled=[bool]$State.settings.splitEnabled;scope=if($State.settings.mode -eq 'TUN'){'tun'}else{'system-proxy'};domains=@($State.settings.splitDomains);ips=@($State.settings.splitIps);applications=@($State.settings.splitApps);games=@($State.settings.splitGames)};[IO.File]::WriteAllText($dialog.FileName,($export|ConvertTo-Json -Depth 8),(New-Object Text.UTF8Encoding($false)));Show-Notice 'Экспорт завершён' 'Правила Split Tunneling сохранены.' 'SUCCESS'}
})
$ImportSplitRules.Add_Click({
    $dialog=New-Object Microsoft.Win32.OpenFileDialog;$dialog.Filter='Luna Split Tunneling (*.json)|*.json'
    if($dialog.ShowDialog()){try{$data=Get-Content -Raw -Encoding UTF8 $dialog.FileName|ConvertFrom-Json;if($data.schema -notin @('luna.split.v1','luna.split.v2')){throw 'Файл имеет неподдерживаемый формат.'};$domains=@($data.domains|ForEach-Object {Normalize-SplitDomain ([string]$_)});$ips=@($data.ips|ForEach-Object {Normalize-SplitIp ([string]$_)});$apps=@($data.applications|Where-Object {[IO.Path]::GetExtension([string]$_) -ieq '.exe'});$games=@($data.games|Where-Object {[IO.Path]::GetExtension([string]$_) -ieq '.exe'});$State.settings.splitDomains=@($domains|Select-Object -Unique);$State.settings.splitIps=@($ips|Select-Object -Unique);$State.settings.splitApps=@($apps|Select-Object -Unique);$State.settings.splitGames=@($games|Select-Object -Unique);$State.settings.splitEnabled=[bool]$data.enabled;if($data.schema -eq 'luna.split.v2'){$State.settings.mode=if($data.scope -eq 'tun'){'TUN'}else{'System proxy'}};Save-State;Update-SplitView;Show-Notice 'Импорт завершён' 'Правила проверены и загружены.' 'SUCCESS'}catch{Show-Notice 'Импорт не выполнен' $_.Exception.Message 'ERROR'}}
})
$script:SplitResetArmed=$false
$ResetSplitRules.Add_Click({if(-not $script:SplitResetArmed){$script:SplitResetArmed=$true;$ResetSplitRules.Content='Нажмите ещё раз';return};$State.settings.splitEnabled=$false;$State.settings.splitDomains=@();$State.settings.splitIps=@();$State.settings.splitApps=@();$State.settings.splitGames=@();$script:SplitResetArmed=$false;$ResetSplitRules.Content='Сбросить';Save-State;$script:InitializingUi=$true;Update-SplitView;$script:InitializingUi=$false;if($script:CoreProcess -and -not $script:CoreProcess.HasExited){Apply-SplitConfiguration}else{Show-Notice 'Правила сброшены' 'Все исключения Split Tunneling удалены.' 'SUCCESS'}})
$EngineBox.Add_SelectionChanged({if($EngineBox.SelectedIndex -gt 0){$EngineStatus.Text='○ Адаптер этого движка не установлен';$EngineStatus.Foreground='#FFD166'}else{$State.settings.engine='Xray-core';$EngineStatus.Text='● Xray-core установлен';$EngineStatus.Foreground='#65E6A7';Save-State}})
$script:ResetArmed=$false
$ResetSettings.Add_Click({if(-not $script:ResetArmed){$script:ResetArmed=$true;$ResetSettings.Content='Нажмите ещё раз для полного сброса';return};$script:State=ConvertTo-Hashtable $defaultState;Initialize-ServerCatalog;Save-State;Refresh-Profiles;Refresh-Subscriptions;$ResetSettings.Content='Сброс выполнен';$script:ResetArmed=$false})
$InstallCore.Add_Click({
    if(Get-CorePath){Show-Notice 'Компонент готов' 'Xray-core уже установлен.' 'SUCCESS';return}
    Set-Loading $true 'Загружаем Xray-core…'
    try{
        $api=Invoke-AsyncHttp 'https://api.github.com/repos/XTLS/Xray-core/releases/latest' @{'User-Agent'="Luna/$AppVersion";'Accept'='application/vnd.github+json'}
        $release=$api.Content|ConvertFrom-Json
        $assetName=if([Environment]::Is64BitOperatingSystem){'Xray-windows-64.zip'}else{'Xray-windows-32.zip'}
        $asset=$release.assets|?{$_.name -eq $assetName}|Select-Object -First 1
        $download=Invoke-AsyncHttp $asset.browser_download_url @{'User-Agent'="Luna/$AppVersion";'Accept'='application/octet-stream'} -AsBytes
        $zip=Join-Path $env:TEMP 'luma-xray.zip';[IO.File]::WriteAllBytes($zip,$download.Content)
        Expand-Archive $zip $CoreDir -Force;Remove-Item $zip -Force;Refresh-CoreStatus
        Show-Notice 'Установка завершена' 'Xray-core установлен.' 'SUCCESS'
    }catch{Show-Notice 'Ошибка установки' $_.Exception.Message 'ERROR' $true}finally{Set-Loading $false}
})
$CloseToast.Add_Click({$script:ToastTimer.Stop();$ToastPanel.Visibility='Collapsed'})
$FixButton.Add_Click({$FixButton.IsEnabled=$false;$FixButton.Content='Исправляем…';try{Stop-Tunnel;Clear-DnsClientCache -ErrorAction SilentlyContinue;Start-Sleep -Milliseconds 400;Start-Tunnel;Show-Notice 'Исправление выполнено' 'DNS-кэш очищен, ядро перезапущено и выполнено переподключение.' 'SUCCESS'}catch{Show-Notice 'Исправление не помогло' $_.Exception.Message 'ERROR'}finally{$FixButton.IsEnabled=$true;$FixButton.Content='Исправить'}})

$timer=New-Object Windows.Threading.DispatcherTimer;$timer.Interval=[TimeSpan]::FromSeconds(1)
$timer.Add_Tick({if($script:ConnectedAt){$SessionTime.Text=((Get-Date)-$script:ConnectedAt).ToString('hh\:mm\:ss');if($script:CoreProcess.HasExited){Stop-Tunnel}else{Update-SessionStatistics}};Update-RouteQualityState;Update-SystemTrafficStatistics})
$script:SelectedLatencyTimer=New-Object Windows.Threading.DispatcherTimer
$script:SelectedLatencyTimer.Interval=[TimeSpan]::FromMilliseconds(670)
$script:SelectedLatencyAutoEnabled=[bool]$State.settings.latencyAutoRefresh
$script:SelectedLatencyAutoGeneration=[int64]0
$script:SelectedLatencyTimer.Add_Tick({
    Complete-SelectedLatencyProbe
    if((Test-SelectedLatencyAutoRefreshAllowed) -and -not $script:SelectedPingTask){
        Start-SelectedLatencyProbe -Automatic
    }
})
$script:SelectedLatencyTimer.Start()
$logTimer=New-Object Windows.Threading.DispatcherTimer;$logTimer.Interval=[TimeSpan]::FromMilliseconds(1500)
$logTimer.Add_Tick({if($LogsPage.Visibility -eq 'Visible'){Refresh-LogView}});$logTimer.Start()
$script:BackendTimer=New-Object Windows.Threading.DispatcherTimer
$script:BackendTimer.Interval=[TimeSpan]::FromMinutes(5)
$script:BackendTimer.Add_Tick({Sync-LunaBackend -Silent})
$script:BackendTimer.Start()
$script:AllowExit=$false
$Window.Add_Closing({
    param($sender,$eventArgs)
    if(-not $script:AllowExit){
        $eventArgs.Cancel=$true
        Hide-LunaToTray
        return
    }
    Stop-Tunnel
    Save-State
    $timer.Stop();$logTimer.Stop();$script:BackendTimer.Stop();$script:SelectedLatencyTimer.Stop()
    if($script:TrayIcon){$script:TrayIcon.Visible=$false;$script:TrayIcon.Dispose()}
    if($script:TrayIconImage){$script:TrayIconImage.Dispose()}
})
$Window.Add_StateChanged({if($Window.WindowState -eq 'Minimized'){Hide-LunaToTray}})

$script:InitializingUi=$true
$DirectDomains.Text=$State.settings.directDomains;$BlockDomains.Text=$State.settings.blockDomains;$BypassLan.IsChecked=$State.settings.bypassLan;$BlockAds.IsChecked=$State.settings.blockAds
$modeIndex=if($State.settings.mode -eq 'TUN'){1}else{0};$ModeBox.SelectedIndex=$modeIndex;$HomeModeBox.SelectedIndex=$modeIndex;$State.settings.mode=if($modeIndex -eq 1){'TUN'}else{'System proxy'};$PortBox.Text=$State.settings.localPort;$DnsBox.Text=$State.settings.dns;$AutoStart.IsChecked=$State.settings.autoStart;$StartMinimized.IsChecked=$State.settings.startMinimized;$ModeLabel.Text=$State.settings.mode
$supportedLanguages=@('Русский','English');$savedLanguageIndex=[Array]::IndexOf($supportedLanguages,[string]$State.settings.language);$LanguageBox.SelectedIndex=if($savedLanguageIndex -ge 0){$savedLanguageIndex}else{0};$ThemeBox.SelectedIndex=switch($State.settings.theme){'Светлая'{1}'Авто'{2}default{0}};$AutoConnect.IsChecked=$State.settings.autoConnect;$KillSwitch.IsChecked=$State.settings.killSwitch;$DnsProtection.IsChecked=$State.settings.dnsProtection;$EnableIPv6.IsChecked=$State.settings.enableIPv6;$WebRtcProtection.IsChecked=$State.settings.webRtcProtection;$DnsLeakProtection.IsChecked=$State.settings.dnsLeakProtection;$CheckUpdates.IsChecked=$State.settings.checkUpdates;$AnonymousStats.IsChecked=$State.settings.anonymousStats;$LatencyAutoRefresh.IsChecked=[bool]$State.settings.latencyAutoRefresh;$EngineBox.SelectedIndex=0;Update-SplitView
$script:InitializingUi=$false
if($env:LUNA_PACKAGED -eq '1'){$AutoStart.IsChecked=$false;$AutoStart.IsEnabled=$false;$AutoStart.Content='Автозапуск — управляйте через параметры Windows (Store)'}
$SaveSettings.IsEnabled=$false
$markSettingsDirty={$script:SettingsDirty=$true;$SaveSettings.IsEnabled=$true}
$PortBox.Add_TextChanged($markSettingsDirty);$DnsBox.Add_TextChanged($markSettingsDirty)
$restartRequiredChanged={& $markSettingsDirty;Show-Notice 'Требуется перезапуск приложения Luna' 'Новый язык или тема применятся после следующего запуска.' 'INFO'}
$LanguageBox.Add_SelectionChanged($restartRequiredChanged);$ThemeBox.Add_SelectionChanged($restartRequiredChanged);$ModeBox.Add_SelectionChanged({
    & $markSettingsDirty
    if($ModeBox.SelectedIndex -ge 0){$State.settings.mode=if($ModeBox.SelectedIndex -eq 1){'TUN'}else{'System proxy'};$HomeModeBox.SelectedIndex=$ModeBox.SelectedIndex;$SplitScopeBox.SelectedIndex=$ModeBox.SelectedIndex;$ModeLabel.Text=$State.settings.mode}
})
foreach($settingToggle in @($AutoStart,$StartMinimized,$AutoConnect,$KillSwitch,$DnsProtection,$EnableIPv6,$WebRtcProtection,$DnsLeakProtection,$CheckUpdates,$AnonymousStats)){$settingToggle.Add_Click($markSettingsDirty)}
Initialize-ServerCatalog;Refresh-CoreStatus;Refresh-Profiles;Refresh-Subscriptions;Initialize-SystemTray;Refresh-RouteQualityView;Update-RouteComparisonSummary;$timer.Start()
$script:ConsentPromptActive=$false
$script:BackendStartupSyncDone=$false
$script:StartHidden=$env:LUNA_START_IN_TRAY -eq '1'
$Window.Add_Activated({
    if(-not $script:StartHidden -and -not $State.settings.telemetryConsentAsked -and -not $script:ConsentPromptActive){
        $script:ConsentPromptActive=$true
        try{Show-TelemetryConsentDialog}finally{$script:ConsentPromptActive=$false}
    }
})
$Window.Add_ContentRendered({
    $script:BackendStartupSilent=[bool]$script:StartHidden
    if($script:StartHidden){Hide-LunaToTray;$script:StartHidden=$false}
    if(-not $script:BackendStartupSyncDone){
        $script:BackendStartupSyncDone=$true
        [void]$Window.Dispatcher.BeginInvoke([action]{
            if($script:BackendStartupSilent){Sync-LunaBackend -Silent}else{Sync-LunaBackend}
        },[Windows.Threading.DispatcherPriority]::Background)
    }
    if($env:LUNA_TUN_AUTOCONNECT -eq '1'){
        [void]$Window.Dispatcher.BeginInvoke([action]{Start-Tunnel},[Windows.Threading.DispatcherPriority]::Background)
    }
})
$script:WpfApplication=[Windows.Application]::Current
if(-not $script:WpfApplication){$script:WpfApplication=New-Object Windows.Application}
$script:WpfApplication.ShutdownMode='OnExplicitShutdown'
[void]$script:WpfApplication.Run($Window)
