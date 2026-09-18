using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ClientMessageCript
{
    internal record TransportMessage
    {
        public string? SenderId { get; init; }
        public string? RecipientId { get; init; }
        public string? SenderPublicKey { get; init; }
        public string? PayloadBase64 { get; init; }
    }

    internal static class Program
    {
        private static ECDiffieHellmanCng? _ecdh;
        private static string _clientId = string.Empty;
        private static readonly Dictionary<string, Conversation> _conversations = new();
        private static readonly object _consoleLock = new();
        private static string _dataPath = Path.Combine(Directory.GetCurrentDirectory(), "client_data");
        private static string _messagesPath = Path.Combine(Directory.GetCurrentDirectory(), "messages");
        private static CancellationTokenSource? _cts;

        private static ServerConnection? _serverConn;
        private static bool _useServer = false;

        private static void Main()
        {
            Directory.CreateDirectory(_dataPath);
            Directory.CreateDirectory(_messagesPath);

            Console.Write("Informe um identificador para este cliente (ex: user1): ");
            _clientId = Console.ReadLine()?.Trim() ?? "client";

            Console.Write("IP do servidor (ENTER para modo local arquivos): ");
            string? serverIp = Console.ReadLine()?.Trim();
            _useServer = !string.IsNullOrWhiteSpace(serverIp);

            _ecdh = new ECDiffieHellmanCng(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            _ecdh.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
            _ecdh.HashAlgorithm = CngAlgorithm.Sha256;

            LoadConversations();

            if (_useServer)
            {
                _serverConn = new ServerConnection(serverIp!, 9000, _clientId);
                _serverConn.OnMessageReceived += OnServerMessage;
                _serverConn.Start();
            }
            else
            {
                _cts = new CancellationTokenSource();
                var token = _cts.Token;
                var thread = new Thread(() => ReceiverLoop(token)) { IsBackground = true };
                thread.Start();
            }

            MainMenu();

            _cts?.Cancel();
            _serverConn?.Stop();
        }

        private static void OnServerMessage(TransportMessage msg)
        {
            try
            {
                // garante conversa
                if (!_conversations.TryGetValue(msg.SenderId ?? string.Empty, out var conv))
                {
                    var c = new Conversation(msg.SenderId ?? string.Empty, msg.SenderPublicKey ?? string.Empty);
                    c.DeriveSharedKey(_ecdh!);
                    _conversations[c.PeerId] = c;
                    SaveConversations();
                    conv = c;
                }

                string clear = DecryptWithSharedKey(conv.SharedKey!, msg.PayloadBase64 ?? string.Empty);
                ConsoleWriteLine($"[{msg.SenderId}] {clear}");
            }
            catch (Exception ex)
            {
                ConsoleWriteLine($"Erro ao processar mensagem do servidor: {ex.Message}");
            }
        }

        private static void MainMenu()
        {
            while (true)
            {
                Console.WriteLine();
                Console.WriteLine("Menu:");
                Console.WriteLine("1) Listar conversas");
                Console.WriteLine("2) Iniciar nova conversa");
                Console.WriteLine("3) Mostrar minha chave pública (base64)");
                Console.WriteLine("4) Sair");
                Console.Write("Escolha: ");

                var key = Console.ReadLine();
                if (string.IsNullOrWhiteSpace(key)) continue;

                switch (key.Trim())
                {
                    case "1": ListConversations(); break;
                    case "2": StartConversation(); break;
                    case "3": ShowMyPublicKey(); break;
                    case "4": return;
                    default: ConsoleWriteLine("Opção inválida"); break;
                }
            }
        }

        private static void ShowMyPublicKey()
        {
            ConsoleWriteLine("Minha chave pública (base64):");
            ConsoleWriteLine(GetPublicKeyBase64());
        }

        private static void ListConversations()
        {
            if (_conversations.Count == 0)
            {
                ConsoleWriteLine("Nenhuma conversa");
                return;
            }

            Console.WriteLine();
            int i = 1;
            foreach (var kv in _conversations)
            {
                Console.WriteLine($"{i}) {kv.Key}");
                i++;
            }
            Console.Write("Escolha número para entrar, D<num> para deletar, ou ENTER para voltar: ");
            string? sel = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(sel)) return;

            sel = sel.Trim();
            if (sel.StartsWith("D", StringComparison.OrdinalIgnoreCase))
            {
                if (int.TryParse(sel.Substring(1), out int idx) && idx >= 1 && idx <= _conversations.Count)
                {
                    var key = _conversations.Keys.ElementAt(idx - 1);
                    _conversations.Remove(key);
                    SaveConversations();
                    ConsoleWriteLine($"Conversa com {key} removida");
                }
                else ConsoleWriteLine("Índice inválido");
                return;
            }

            if (int.TryParse(sel, out int selIdx) && selIdx >= 1 && selIdx <= _conversations.Count)
            {
                var peerId = _conversations.Keys.ElementAt(selIdx - 1);
                EnterConversation(peerId);
            }
            else ConsoleWriteLine("Índice inválido");
        }

        private static void StartConversation()
        {
            Console.Write("Id do destinatário: ");
            string peerId = Console.ReadLine()?.Trim() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(peerId)) { ConsoleWriteLine("Id inválido"); return; }

            if (_conversations.ContainsKey(peerId))
            {
                ConsoleWriteLine("Conversa já existe. Entrando...");
                EnterConversation(peerId);
                return;
            }

            // mostra nossa chave pública e pede a do par
            string myPub = GetPublicKeyBase64();
            ConsoleWriteLine("Minha chave pública (compartilhe com o par):");
            ConsoleWriteLine(myPub);
            Console.Write("Cole a chave pública do par (base64) para estabelecer a conversa: ");
            string? peerPub = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(peerPub)) { ConsoleWriteLine("Public key vazia"); return; }

            try
            {
                var conv = new Conversation(peerId, peerPub.Trim());
                conv.DeriveSharedKey(_ecdh!);
                _conversations[peerId] = conv;
                SaveConversations();
                ConsoleWriteLine("Conversa estabelecida. Entrando...");
                EnterConversation(peerId);
            }
            catch (Exception ex)
            {
                ConsoleWriteLine($"Erro ao estabelecer conversa: {ex.Message}");
            }
        }

        private static void EnterConversation(string peerId)
        {
            if (!_conversations.TryGetValue(peerId, out var conv))
            {
                ConsoleWriteLine("Conversa não encontrada");
                return;
            }

            ConsoleWriteLine($"=== Conversa com {peerId} === (digite /exit para voltar)");
            while (true)
            {
                Console.Write("Você: ");
                string? line = Console.ReadLine();
                if (line is null) continue;
                if (line.Trim().Equals("/exit", StringComparison.OrdinalIgnoreCase)) break;

                SendMessage(peerId, conv, line);
            }
        }

        private static void SendMessage(string peerId, Conversation conv, string text)
        {
            try
            {
                var payload = EncryptWithSharedKey(conv.SharedKey!, text);
                var msg = new TransportMessage
                {
                    SenderId = _clientId,
                    RecipientId = peerId,
                    SenderPublicKey = GetPublicKeyBase64(),
                    PayloadBase64 = payload
                };

                if (_useServer && _serverConn != null)
                {
                    // envia ao servidor para encaminhamento
                    _serverConn.SendTransportMessageAsync(msg).GetAwaiter().GetResult();
                }
                else
                {
                    var file = Path.Combine(_messagesPath, $"{peerId}_{DateTime.UtcNow:yyyyMMddHHmmssfff}_{Guid.NewGuid()}.json");
                    var json = JsonSerializer.Serialize(msg);
                    File.WriteAllText(file, json);
                }

                ConsoleWriteLine($"[enviado para {peerId}] {text}");
            }
            catch (Exception ex)
            {
                ConsoleWriteLine($"Erro ao enviar: {ex.Message}");
            }
        }

        private static void ReceiverLoop(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    var files = Directory.GetFiles(_messagesPath, $"{_clientId}_*.json");
                    foreach (var f in files)
                    {
                        try
                        {
                            var json = File.ReadAllText(f);
                            var msg = JsonSerializer.Deserialize<TransportMessage>(json);
                            if (msg is null) { File.Delete(f); continue; }

                            // ensure conversation exists
                            if (!_conversations.TryGetValue(msg.SenderId!, out var conv))
                            {
                                var c = new Conversation(msg.SenderId!, msg.SenderPublicKey ?? string.Empty);
                                c.DeriveSharedKey(_ecdh!);
                                _conversations[msg.SenderId!] = c;
                                SaveConversations();
                                conv = c;
                            }

                            string clear = DecryptWithSharedKey(conv.SharedKey!, msg.PayloadBase64 ?? string.Empty);
                            ConsoleWriteLine($"[{msg.SenderId}] {clear}");
                        }
                        catch (Exception ex)
                        {
                            ConsoleWriteLine($"Erro ao processar mensagem: {ex.Message}");
                        }
                        finally
                        {
                            try { File.Delete(f); } catch { }
                        }
                    }
                }
                catch { }

                Thread.Sleep(800);
            }
        }

        private static string GetPublicKeyBase64()
        {
            byte[] pub = _ecdh!.PublicKey.ToByteArray();
            return Convert.ToBase64String(pub);
        }

        private static string EncryptWithSharedKey(byte[] key, string plain)
        {
            byte[] plainBytes = Encoding.UTF8.GetBytes(plain);
            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            byte[] ciphertext = new byte[plainBytes.Length];
            byte[] tag = new byte[16];
            using var aesgcm = new AesGcm(key);
            aesgcm.Encrypt(nonce, plainBytes, ciphertext, tag);
            byte[] outBuf = new byte[nonce.Length + tag.Length + ciphertext.Length];
            Buffer.BlockCopy(nonce, 0, outBuf, 0, nonce.Length);
            Buffer.BlockCopy(tag, 0, outBuf, nonce.Length, tag.Length);
            Buffer.BlockCopy(ciphertext, 0, outBuf, nonce.Length + tag.Length, ciphertext.Length);
            return Convert.ToBase64String(outBuf);
        }

        private static string DecryptWithSharedKey(byte[] key, string base64)
        {
            byte[] buf = Convert.FromBase64String(base64);
            byte[] nonce = new byte[12];
            byte[] tag = new byte[16];
            byte[] ciphertext = new byte[buf.Length - nonce.Length - tag.Length];
            Buffer.BlockCopy(buf, 0, nonce, 0, nonce.Length);
            Buffer.BlockCopy(buf, nonce.Length, tag, 0, tag.Length);
            Buffer.BlockCopy(buf, nonce.Length + tag.Length, ciphertext, 0, ciphertext.Length);
            byte[] plain = new byte[ciphertext.Length];
            using var aesgcm = new AesGcm(key);
            aesgcm.Decrypt(nonce, ciphertext, tag, plain);
            return Encoding.UTF8.GetString(plain);
        }

        private static void SaveConversations()
        {
            try
            {
                var path = Path.Combine(_dataPath, "conversations.json");
                var list = _conversations.Values.ToList();
                var json = JsonSerializer.Serialize(list);
                File.WriteAllText(path, json);
            }
            catch { }
        }

        private static void LoadConversations()
        {
            try
            {
                var path = Path.Combine(_dataPath, "conversations.json");
                if (!File.Exists(path)) return;
                var json = File.ReadAllText(path);
                var list = JsonSerializer.Deserialize<List<Conversation>>(json);
                if (list is null) return;
                foreach (var c in list) _conversations[c.PeerId] = c;
            }
            catch { }
        }

        private static void ConsoleWriteLine(string text)
        {
            lock (_consoleLock) Console.WriteLine(text);
        }

        private class Conversation
        {
            public string PeerId { get; set; }
            public string PeerPublicKeyBase64 { get; set; }

            [JsonIgnore]
            public byte[]? SharedKey { get; private set; }

            public Conversation() { PeerId = string.Empty; PeerPublicKeyBase64 = string.Empty; }
            public Conversation(string peerId, string peerPublicKey)
            {
                PeerId = peerId;
                PeerPublicKeyBase64 = peerPublicKey;
            }

            public void DeriveSharedKey(ECDiffieHellmanCng local)
            {
                byte[] peerPub = Convert.FromBase64String(PeerPublicKeyBase64);
                using var otherPub = ECDiffieHellmanCngPublicKey.FromByteArray(peerPub, CngKeyBlobFormat.EccPublicBlob);
                byte[] derived = local.DeriveKeyMaterial(otherPub);
                using var sha = SHA256.Create();
                SharedKey = sha.ComputeHash(derived);
            }
        }

        private class ServerConnection
        {
            private readonly string _ip;
            private readonly int _port;
            private readonly string _clientId;
            private TcpClient? _tcp;
            private NetworkStream? _ns;
            private CancellationTokenSource? _cts;

            public event Action<TransportMessage>? OnMessageReceived;

            public ServerConnection(string ip, int port, string clientId)
            {
                _ip = ip;
                _port = port;
                _clientId = clientId;
            }

            public void Start()
            {
                _cts = new CancellationTokenSource();
                Task.Run(() => RunAsync(_cts.Token));
            }

            public void Stop()
            {
                try { _cts?.Cancel(); } catch { }
                try { _ns?.Close(); } catch { }
                try { _tcp?.Close(); } catch { }
            }

            private async Task RunAsync(CancellationToken token)
            {
                while (!token.IsCancellationRequested)
                {
                    try
                    {
                        _tcp = new TcpClient();
                        await _tcp.ConnectAsync(_ip, _port, token).ConfigureAwait(false);
                        _ns = _tcp.GetStream();

                        // send register
                        var reg = new { type = "register", clientId = _clientId };
                        await SendProtocolAsync(reg, token).ConfigureAwait(false);

                        // receive loop
                        while (!token.IsCancellationRequested && _ns != null && _tcp.Connected)
                        {
                            // read length
                            byte[] lenBuf = new byte[4];
                            int read = await ReadExactAsync(_ns, lenBuf, 0, 4, token).ConfigureAwait(false);
                            if (read == 0) break;
                            int len = BitConverter.ToInt32(lenBuf, 0);
                            if (len <= 0) continue;
                            byte[] buf = new byte[len];
                            await ReadExactAsync(_ns, buf, 0, len, token).ConfigureAwait(false);
                            var json = Encoding.UTF8.GetString(buf);
                            using var doc = JsonDocument.Parse(json);
                            if (doc.RootElement.TryGetProperty("type", out var typeEl))
                            {
                                var type = typeEl.GetString();
                                if (type == "message" && doc.RootElement.TryGetProperty("payload", out var payload))
                                {
                                    var msg = JsonSerializer.Deserialize<TransportMessage>(payload.GetRawText());
                                    if (msg != null) OnMessageReceived?.Invoke(msg);
                                }
                            }
                        }
                    }
                    catch (OperationCanceledException) { break; }
                    catch
                    {
                        // retry after delay
                        await Task.Delay(1000, token).ConfigureAwait(false);
                    }
                    finally
                    {
                        try { _ns?.Close(); } catch { }
                        try { _tcp?.Close(); } catch { }
                        _ns = null; _tcp = null;
                    }
                }
            }

            private static async Task<int> ReadExactAsync(Stream s, byte[] buffer, int offset, int count, CancellationToken token)
            {
                int readTotal = 0;
                while (readTotal < count)
                {
                    int r = await s.ReadAsync(buffer, offset + readTotal, count - readTotal, token).ConfigureAwait(false);
                    if (r == 0) return 0;
                    readTotal += r;
                }
                return readTotal;
            }

            private async Task SendProtocolAsync(object protoObj, CancellationToken token)
            {
                if (_ns == null) throw new InvalidOperationException("Conexão não estabelecida");
                var json = JsonSerializer.Serialize(protoObj);
                var bytes = Encoding.UTF8.GetBytes(json);
                var len = BitConverter.GetBytes(bytes.Length);
                await _ns.WriteAsync(len, 0, len.Length, token).ConfigureAwait(false);
                await _ns.WriteAsync(bytes, 0, bytes.Length, token).ConfigureAwait(false);
                await _ns.FlushAsync(token).ConfigureAwait(false);
            }

            public async Task SendTransportMessageAsync(TransportMessage msg)
            {
                if (_ns == null) throw new InvalidOperationException("Conexão não estabelecida");
                var proto = new { type = "message", payload = msg };
                await SendProtocolAsync(proto, CancellationToken.None).ConfigureAwait(false);
            }
        }
    }
}
