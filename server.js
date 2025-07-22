// server.js (Versione completa e finale)
const { WebSocketServer } = require('ws');
const http = require('http');
const express = require('express');
const cors = require('cors'); // Importa il middleware CORS
const app = express();
// Middleware
app.use(cors()); // Abilita CORS per tutte le richieste HTTP
app.use(express.json({ limit: '10mb' })); // Permette di parsare body JSON grandi
const server = http.createServer(app);
const wss = new WebSocketServer({ server });
// Strutture dati in memoria
const clients = new Map();
const mailboxes = new Map();
const preKeyBundles = new Map();
// Gestione Connessioni WebSocket
wss.on('connection', ws => {
  let userId = null;
  ws.on('message', rawMessage => {
    try {
      const message = JSON.parse(rawMessage);
      switch (message.type) {
        case 'register':
          userId = message.userId;
          clients.set(userId, ws);
          console.log(`[+] Utente registrato: ${userId}`);
          // Controlla e invia messaggi in sospeso (offline)
          const pendingMessages = mailboxes.get(userId) || [];
          if (pendingMessages.length > 0) {
            console.log(
              `[Mailbox] Invio ${pendingMessages.length} messaggi in sospeso a ${userId}`,
            );
            pendingMessages.forEach(msg => {
              // Il messaggio salvato include già 'from' e 'wireMessage'
              ws.send(JSON.stringify({ type: 'offline-message', ...msg }));
            });
            mailboxes.delete(userId); // Svuota la mailbox
          }
          break;
        case 'signal':
          console.log(
            `[Signal] Ricevuto segnale da ${userId} per ${message.to}.`,
          );
          const recipient = clients.get(message.to);
          if (recipient?.readyState === recipient.OPEN) {
            console.log(
              `[Signal] Destinatario ${message.to} trovato e online. Inoltro il segnale...`,
            );
            recipient.send(
              JSON.stringify({
                type: 'signal',
                from: userId,
                signal: message.signal,
              }),
            );
          } else {
            console.log(
              `[Signal] ATTENZIONE: Destinatario ${message.to} non trovato o non connesso. Impossibile inoltrare il segnale.`,
            );
          }
          break;
        default:
          console.warn(
            `[WebSocket] Tipo di messaggio sconosciuto ricevuto da ${userId}: ${message.type}`,
          );
      }
    } catch (e) {
      console.error(
        `[WebSocket] Errore nel processare il messaggio: ${e.message}`,
      );
    }
  });
  ws.on('close', () => {
    if (userId) {
      clients.delete(userId);
      console.log(`[-] Utente disconnesso: ${userId}`);
    }
  });
  ws.on('error', error => {
    console.error(
      `[WebSocket] Errore per l'utente ${userId || 'sconosciuto'}: ${error.message}`,
    );
  });
});
// Endpoint HTTP per l'invio di messaggi (fallback se offline)
app.post('/send', (req, res) => {
  const { to, from, wireMessage } = req.body;
  if (!to || !from || !wireMessage) {
    return res.status(400).send({
      error: 'Richiesta incompleta. Mancano "to", "from", o "wireMessage".',
    });
  }
  const recipientSocket = clients.get(to);
  if (recipientSocket?.readyState === recipientSocket.OPEN) {
    // Il destinatario è online, invia direttamente via WebSocket
    recipientSocket.send(
      JSON.stringify({ type: 'new-message', from, wireMessage }),
    );
  } else {
    // Il destinatario è offline, salva il messaggio nella sua mailbox
    if (!mailboxes.has(to)) {
      mailboxes.set(to, []);
    }
    mailboxes.get(to).push({ from, wireMessage });
  }
  res.status(200).send({ success: true });
});
// Endpoint HTTP per il caricamento delle chiavi crittografiche
app.post('/keys/upload', (req, res) => {
  const { userId, identityKey, signedPreKey, oneTimePreKeys } = req.body;
  console.log(
    `[HTTP] Ricevuta richiesta POST su /keys/upload per l'utente ${userId || 'sconosciuto'}`,
  );
  if (!userId || !identityKey || !signedPreKey || !oneTimePreKeys) {
    console.error(
      `[HTTP] ERRORE: Dati del Pre-Key Bundle mancanti per /keys/upload.`,
    );
    return res.status(400).send({ error: 'Bundle incompleto.' });
  }
  // Le chiavi monouso vengono salvate in una Mappa per una facile e veloce rimozione
  const opkMap = new Map(oneTimePreKeys.map(key => [key.id, key.publicKey]));
  preKeyBundles.set(userId, {
    identityKey,
    signedPreKey,
    oneTimePreKeys: opkMap,
  });
  console.log(
    `[HTTP] OK: Bundle per ${userId} salvato. OPK disponibili: ${opkMap.size}`,
  );
  res.status(200).send({ success: true });
});
// Endpoint HTTP per richiedere le chiavi di un utente per iniziare una sessione
app.get('/keys/:userId', (req, res) => {
  const { userId } = req.params;
  console.log(`[HTTP] Ricevuta richiesta GET su /keys/${userId}`);
  const bundle = preKeyBundles.get(userId);
  if (!bundle) {
    console.error(`[HTTP] ERRORE: Chiavi non trovate per l'utente ${userId}.`);
    return res.status(404).send({ error: 'Chiavi non trovate.' });
  }
  if (bundle.oneTimePreKeys.size === 0) {
    console.error(
      `[HTTP] ERRORE: L'utente ${userId} ha esaurito le OPK (chiavi monouso).`,
    );
    return res.status(503).send({ error: 'OPK esaurite.' });
  }
  // Prendi la prima chiave monouso disponibile, la rimuovi e la restituisci
  const opkIterator = bundle.oneTimePreKeys.entries().next();
  const [opkId, opkPublicKey] = opkIterator.value;
  bundle.oneTimePreKeys.delete(opkId); // Rimuovi la chiave per garantire che sia "one-time"
  preKeyBundles.set(userId, bundle); // Aggiorna il bundle sul server
  console.log(
    `[HTTP] OK: Distribuita OPK #${opkId} per ${userId}. Rimaste: ${bundle.oneTimePreKeys.size}`,
  );
  res.status(200).json({
    identityKey: bundle.identityKey,
    signedPreKey: bundle.signedPreKey,
    oneTimeKey: { id: opkId, publicKey: opkPublicKey },
  });
});
// Avvio del server
const PORT = process.env.PORT || 8080; // Usa la porta fornita dall'host, o 8080 in locale
server.listen(PORT, () => {
  console.log(
    `Server Whisper (PROD - CORS Abilitato) in ascolto sulla porta ${PORT}`,
  );
});
