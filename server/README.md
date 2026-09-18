README - Servidor para ClientMessageCript

Objetivo

Especificar o protocolo e comportamento do servidor que receberá, encaminhará e armazenará mensagens criptografadas entre clientes. O servidor fica em projeto separado; este README documenta tudo que você precisa implementar para compatibilizar com o cliente existente.

Resumo do protocolo

- Transporte: TCP (porta 9000 por padrão). Cada mensagem é enviada como frame length-prefixed: 4 bytes (Int32 little-endian) com o tamanho do JSON, seguido pelo JSON em UTF-8.
- Mensagens JSON com o formato { "type": "register" | "message", "payload": {...} }.

Tipos de pacote

1) register
- enviado pelo cliente assim que conecta
- payload: { "clientId": "string" }
- servidor deve associar o stream/socket ao clientId

Exemplo register frame (JSON):
{
  "type": "register",
  "payload": { "clientId": "user1" }
}

2) message
- usado para enviar/enfileirar/encaminhar mensagens entre clientes
- payload contém o objeto TransportMessage

TransportMessage (payload do message)
{
  "SenderId": "user1",
  "RecipientId": "user2",
  "SenderPublicKey": "BASE64_ECC_PUBLIC_BLOB",
  "PayloadBase64": "BASE64_NONCE_TAG_CIPHERTEXT"
}

Observações:
- SenderPublicKey pode ser enviado em cada mensagem (cliente atual faz isso). Servidor deve atualizar a chave conhecida do remetente sempre que receber.
- PayloadBase64 é resultado do AES-GCM (nonce|tag|ciphertext) em base64 — o servidor NÃO deve tentar desencriptar o conteúdo.

Comportamento esperado do servidor

1) Conexão e registro
- Cliente conecta via TCP
- Lê frame register
- Associa clientId -> conexão (thread-safe)
- Se já houver conexão ativa com mesmo clientId, decidir política (desconectar anterior ou recusar novo)

2) Recepção de message
- Desserializar TransportMessage do payload
- Atualizar/armazenar a chave pública do SenderId (opcionalmente em memória/permanente)
- Se RecipientId estiver conectado: encaminhar o frame JSON { type: "message", payload: TransportMessage } para o socket do recipient (usando framing de 4 bytes + JSON)
- Caso RecipientId não esteja conectado: enfileirar (persistente ou em memória) para entrega quando conectar

3) Entrega
- Ao entregar, apenas reenvia o mesmo TransportMessage (sem alteração). Não tenta descriptografar.

4) Erros e validações
- Validar JSON e campos obrigatórios (SenderId, RecipientId, PayloadBase64)
- Rejeitar/marcar mensagens inválidas sem derrubar conexão
- Timeouts e keep-alive para conexões inativas

Regras práticas de implementação

- Implementar com async/await (Sockets/TcpListener + NetworkStream) para escala.
- Estruturas thread-safe: ConcurrentDictionary<string, ConnectionContext> para clientes conectados.
- Fila de mensagens: para simplificar, uma fila por usuário (persistir em disco se quiser garantir entrega após reinício).
- Logging: registrar eventos (connect, disconnect, message received, forward, error).
- Segurança: usar TLS/SSL em produção. Para testes locais pode ser plain TCP.

Exemplo de loop do servidor (pseudocódigo)

- Start TcpListener(0.0.0.0, 9000)
- while listening: AcceptTcpClientAsync -> HandleClient(connection)

HandleClient(conn):
- ns = conn.GetStream()
- while connected:
  - len = ReadInt32(ns)
  - buf = ReadExact(ns, len)
  - doc = JsonDocument.Parse(buf)
  - type = doc["type"]
  - if type == "register": id = doc.payload.clientId; registerConnection(id, conn)
  - if type == "message": tm = deserialize(payload); storeSenderKey(tm.SenderId, tm.SenderPublicKey); enqueueOrForward(tm)

Forwarding: if recipient connected: send framed JSON { type:"message", payload: tm } to recipient's stream

Testes locais

- Rodar o servidor localmente (porta 9000).
- Rodar duas instâncias do cliente (no mesmo computador) fornecendo "localhost" como IP do servidor e ids diferentes (user1, user2).
- No client user1 iniciar conversa com user2 e enviar mensagens. O servidor deverá encaminhar para user2 e user2 deve mostrar a mensagem (descriptografada localmente).

Itens opcionais e melhorias

- Persistência de fila (SQLite / arquivo) para garantir entrega após reinício.
- Mensagens de ACK para confirmar entrega e permitir reenvio se necessário.
- Autenticação e TLS.
- Limites de tamanho e rate-limiting por cliente.

Notas sobre ECDH e fluxo de chaves

- O cliente gera par ECDH localmente e envia a chave pública repetidamente dentro de cada TransportMessage (campo SenderPublicKey). O servidor só precisa encaminhar essa chave ao destinatário junto com a mensagem; o par e a derivação de chave são realizados entre clientes localmente (cliente receptor usa SenderPublicKey para derivar shared key com sua chave privada).
- Alternativamente, o servidor pode armazenar a última chave pública conhecida de cada cliente e prover endpoints para requisição de chave, mas isso não é necessário para o protocolo atual.

Formato de entrega (framing)

- Para enviar JSON X:
  - bytes = UTF8(JSON)
  - write Int32(bytes.Length) little-endian
  - write bytes

Exemplo minimal de mensagem JSON enviada ao servidor (stringified):
{
  "type": "message",
  "payload": {
	"SenderId": "user1",
	"RecipientId": "user2",
	"SenderPublicKey": "BASE64...",
	"PayloadBase64": "BASE64..."
  }
}

Conclusão

Este README descreve o protocolo e o comportamento mínimo do servidor para funcionar com o cliente atual. Quando quiser, posso gerar um projeto de servidor .NET 10 esqueleto com listener TCP, roteamento em memória e persistência simples (opcional).