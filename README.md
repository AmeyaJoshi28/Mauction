# Secure Auction System

A multi-client, encrypted auction system over TCP/UDP with peer-to-peer messaging, built in C++.

---

## How to Run

### 1. Compile

```bash
g++ server.cpp -o serve
g++ client.cpp -o c
```

### 2. Start the Server

```bash
./serve
```

### 3. Start 5 Clients (each in a separate terminal)

```bash
./c 1 127.0.0.1
./c 2 127.0.0.1
./c 3 127.0.0.1
./c 4 127.0.0.1
./c 5 127.0.0.1
```

### 4. Available Commands (in each client terminal)

| Command | Description |
|---|---|
| `bid <amount>` | Place an encrypted bid |
| `pass` | Skip the current player |
| `chat <id> <msg>` | Send an encrypted private P2P message |
| `team` | Show your current squad |
| `help` | List all available commands |

### 5. Results

Final auction results are written to `auction_results.txt` at the end of the auction.

---

## Configuration (`protocol.h`)

| Parameter | Description |
|---|---|
| `BID_TIME` | Time window (seconds) for placing bids |
| `NUM_PLAYERS` | Number of players up for auction |
| `BUDGET` | Starting budget for each client |
| `MAX_CLIENTS` | Number of clients that can connect |

---

## Architecture

### `server.cpp`

1. Waits for `MAX_CLIENTS` clients to connect over TCP.
2. Performs a key exchange with each client:
   - Receives the client's RSA public key
   - Sends the server's RSA public key
   - Generates an AES session key, encrypts it with the client's RSA key, and sends it
3. Once all clients are connected, starts the auction loop:
   - Announces each player to all clients (encrypted)
   - Waits `BID_TIME` seconds for bids
   - Broadcasts live bids to all clients via UDP multicast
   - Awards the player to the highest bidder, or marks them unsold
4. Relays peer-to-peer messages and serves public keys on request

### `client.cpp`

1. Connects to the server over TCP.
2. Performs key exchange (receives AES session key, decrypts with own RSA private key).
3. Spawns three background threads:
   - **`udp_thread`** — listens for multicast bid updates
   - **`p2p_thread`** — listens for incoming private chat messages
   - **`server_thread`** — receives auction announcements and results from the server
4. Main thread handles user commands.

### `crypto.h` — RSA + AES Encryption

```
Step 1: Each party generates an RSA key pair (public + private).
Step 2: Server generates a random AES session key (8 bytes),
        encrypts it with the client's RSA public key, and sends it.
        Only the client can decrypt it using their RSA private key.
Step 3: All subsequent messages are encrypted with AES (XOR keystream).
        RSA is only used once, for the initial key exchange.
```

> This mirrors the hybrid encryption approach used in TLS/HTTPS.

### `protocol.h` — Message Format

Every message between server and client follows this structure:

```
[ type (1 byte) | length (2 bytes) | data (N bytes) ]
```

- **`type`** — identifies the message kind
- **`length`** — number of data bytes that follow
- **`data`** — the actual content (may be AES-encrypted)

---

## Concepts Used

1. **UDP Multicast** — live bid broadcasting to all clients
2. **TCP Sockets** — reliable server-client communication
3. **Mutex (Mutual Exclusion)** — thread-safe access to shared state
4. **Threads** — concurrent handling of server, UDP, and P2P channels
5. **Auction Logic** — timer-based bidding with highest-bid resolution
6. **Timer Management** — per-player bid timers with appropriate resets
7. **Peer-to-Peer Messaging** — direct encrypted messages, relayed via server if needed
8. **RSA Encryption** — public key distribution and private key decryption for key exchange
9. **AES Encryption** — IV-based keystream XOR for all session messages
10. **Shared-Secret Encryption** — pre-agreed key (derived by formula) for direct P2P channels
