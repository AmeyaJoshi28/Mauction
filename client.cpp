#include <iostream>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <mutex>
#include <atomic>
#include <sstream>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "protocol.h"
#include "crypto.h"


int     my_id;
int     server_fd;
RSAKey  my_rsa;
uint8_t aes_key[8];        // AES session key from server
uint16_t send_iv = 0;      // IV counter for messages we send to server

int     my_budget = BUDGET;
char    my_team[10][40];   
int     my_team_size = 0;

// Current player being auctioned
char cur_player_name[40] = {};
int  cur_player_id = 0;
int  cur_base      = 0;

std::atomic<bool> auction_on{false};   //all threads can modify the value safely, without overlapping(Helps in simultaneous)
std::mutex print_mtx;   //mutex: Mutual Exclusion Lock (only one threads enters at a time)

//Known public keys of other clients (they are indexed by client id)
uint64_t peer_e[6] = {};
uint64_t peer_n[6] = {};

//Peer to Peer session keys (for encrypted chat), indexed by peer id
uint8_t p2p_key[6][8] = {};
bool p2p_key_ready[6] = {};

// Sending AES-encrypted message to the server
void send_to_server(uint8_t type, const char* data, int len) {
    char buf[2048];
    uint64_t iv = send_iv++;
    int enc_len = aes_encrypt(data, len, aes_key, iv, buf, sizeof(buf));
    Packet p = make_packet(type, buf, (uint16_t)enc_len);
    send_packet(server_fd, p);
}

// Decrypt a packet received from server
int decrypt_server(const Packet& p, char* out, int out_max) {
    return aes_decrypt(p.data, p.length, aes_key, out, out_max);
}

// Print the current team in a nice box
void print_team() {
    std::lock_guard<std::mutex> lock(print_mtx);
    printf("\n┌─────────────────────────────────────┐\n");
    printf("│  MY TEAM  (Client %d)                │\n", my_id);
    printf("├─────────────────────────────────────┤\n");
    if (my_team_size == 0)
        printf("│  (no players yet)                   │\n");
    for (int i = 0; i < my_team_size; i++)
        printf("│  %-35s│\n", my_team[i]);
    printf("├─────────────────────────────────────┤\n");
    printf("│  Budget left: %-4d Cr               │\n", my_budget);
    printf("└─────────────────────────────────────┘\n\n");
}


// Receiving live bid updates which the server had broadcasted 
void udp_thread() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)); // Reuse of the socket , to bind the port even if it was busy.

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(MCAST_PORT);
    bind(sock, (sockaddr*)&addr, sizeof(addr));

    
    ip_mreq mreq{};  //Multicast group to be joined 
    inet_pton(AF_INET, MCAST_GROUP, &mreq.imr_multiaddr);
    mreq.imr_interface.s_addr = INADDR_ANY;
    setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)); //Send any traffic for the multicast address to me

    char buf[256];
    while (true) {
        int r = recv(sock, buf, sizeof(buf) - 1, 0);
        if (r <= 0) break;
        buf[r] = '\0';
        std::lock_guard<std::mutex> lock(print_mtx);
        printf("\n  [LIVE BID] %s\n", buf);
    }
    close(sock);
}

//Listening for incoming encrypted private messages from other clients.
void p2p_thread() {
    int port = P2P_BASE_PORT + my_id; //listening on this port
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);
    bind(srv, (sockaddr*)&addr, sizeof(addr));
    listen(srv, 10);

    printf("[P2P] Listening on port %d\n", port);

    while (true) {
        sockaddr_in peer_addr{}; 
        socklen_t peer_len = sizeof(peer_addr);
        int peer_fd = accept(srv, (sockaddr*)&peer_addr, &peer_len);
        if (peer_fd < 0) continue;

        //A peer is connected, so receive their message in a new thread.
        std::thread([peer_fd]() {
            Packet p;
            if (!recv_packet(peer_fd, p)) { 
                close(peer_fd); 
                return; 
            }

            // 1st 1 byte of data = sender id
            int from_id = (uint8_t)p.data[0];

            if (p.type == MSG_CHAT) {
                // The rest of data is AES-encrypted with our P2P key
                // P2P key: we agreed on it being XOR of our AES keys
                // (simple approach as both sides can derive it)
                char dec[512] = {};
                // Derive the same shared key: smaller ID first, same formula as sender
                int id_a = (my_id < from_id) ? my_id : from_id;
                int id_b = (my_id < from_id) ? from_id : my_id;
                uint8_t pkey[8];
                for (int i = 0; i < 8; i++)
                    pkey[i] = (uint8_t)(id_a * 31 + id_b * 17 + i * 7);

                int dec_len = aes_decrypt(p.data + 1, p.length - 1,
                                          pkey, dec, sizeof(dec));
                if (dec_len > 0) {
                    dec[dec_len] = '\0';
                    std::lock_guard<std::mutex> lock(print_mtx);
                    printf("\n  [PRIVATE from Client %d]: %s\n", from_id, dec);
                }
            }
            close(peer_fd);
        }).detach(); //To run the thread inpendently.
    }
    close(srv);
}

// Handling all messages coming FROM the server
void server_thread() {
    while (true) {
        Packet p;
        if (!recv_packet(server_fd, p)) {
            printf("[Client %d] Lost connection to server.\n", my_id);
            auction_on = false;
            break;
        }

        char dec[512] = {};

        switch (p.type) {

        case MSG_PLAYER_UP: {
            // Format: "id|name|role|base"
            decrypt_server(p, dec, sizeof(dec));
            int id, base;
            char name[40], role[20];
            sscanf(dec, "%d|%39[^|]|%19[^|]|%d", &id, name, role, &base);

            cur_player_id = id;
            cur_base      = base;
            strncpy(cur_player_name, name, sizeof(cur_player_name));

            std::lock_guard<std::mutex> lock(print_mtx);
            printf("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
            printf("  PLAYER UP: %s\n", name);
            printf("  Role: %s  |  Base: %d Cr\n", role, base);
            printf("  Your budget: %d Cr\n", my_budget);
            printf("  Commands: bid <amount>  |  pass\n");
            printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
            break;
        }

        case MSG_SOLD: {
            // Format: "name|SOLD|amount|buyer_id"
            decrypt_server(p, dec, sizeof(dec));
            char name[40], status[10];
            int amount, buyer;
            sscanf(dec, "%39[^|]|%9[^|]|%d|%d", name, status, &amount, &buyer);

            printf("\n  [SOLD] %s → Client %d for %d Cr\n", name, buyer, amount);

            if (buyer == my_id) {
                my_budget -= amount;
                strncpy(my_team[my_team_size++], name, 40);
                print_team();   // showing updated team after every purchase
            }
            break;
        }

        case MSG_UNSOLD: {
            decrypt_server(p, dec, sizeof(dec));
            char name[40];
            sscanf(dec, "%39[^|]", name);
            printf("\n  [UNSOLD] %s\n", name);
            break;
        }

        case MSG_KEY_REPLY: {
            // Server gave us another client's RSA public key
            // Format: "id e n"
            decrypt_server(p, dec, sizeof(dec));
            int id; uint64_t e, n;
            // Raw bytes: [id:4][e:8][n:8]
            memcpy(&id, dec,      4);
            memcpy(&e,  dec + 4,  8);
            memcpy(&n,  dec + 12, 8);
            peer_e[id] = e;
            peer_n[id] = n;
            printf("[PKI] Got public key for Client %d\n", id);
            break;
        }

        case MSG_AUCTION_END: {
            printf("\n  [AUCTION OVER]\n");
            print_team();
            auction_on = false;
            break;
        }

        }
    }
}

//Sending a Peer to Peer chat message 
void send_p2p(int target_id, const char* target_ip, const char* msg) {
    //If we don't have their public key yet, ask server for it
    if (peer_n[target_id] == 0) {
        char req[16];
        snprintf(req, sizeof(req), "%d", target_id);
        send_to_server(MSG_GET_KEY, req, strlen(req));

        //Waiting up to 2 seconds for server's reply
        for (int i = 0; i < 40; i++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            if (peer_n[target_id] != 0) break;
        }
        if (peer_n[target_id] == 0) {
            printf("[P2P] Could not get key for Client %d\n", target_id);
            return;
        }
    }

    //Deriving a shared P2P key using both client IDs
    //Both sides compute the same key because they use the same two IDs
    //We always put the smaller ID first so order doesn't matter
    int id_a = (my_id < target_id) ? my_id : target_id;
    int id_b = (my_id < target_id) ? target_id : my_id;
    uint8_t pkey[8];
    for (int i = 0; i < 8; i++)
        pkey[i] = (uint8_t)(id_a * 31 + id_b * 17 + i * 7);  //Calculation of the key

    //Encrypting the message with the P2P key
    char enc[512];
    static uint16_t p2p_iv = 0;
    int enc_len = aes_encrypt(msg, strlen(msg), pkey, p2p_iv++, enc, sizeof(enc));

    //Connecting TCP directly to target's P2P port and send
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(P2P_BASE_PORT + target_id);
    inet_pton(AF_INET, target_ip, &addr.sin_addr);

    if (connect(fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        printf("[P2P] Cannot reach Client %d\n", target_id);
        close(fd);
        return;
    }

    // Prefix the data with my id (1 byte), so that receiver knows who sent it.
    char payload[513];
    payload[0] = (char)my_id;
    memcpy(payload + 1, enc, enc_len);

    Packet pkt = make_packet(MSG_CHAT, payload, 1 + enc_len);
    send_packet(fd, pkt);
    close(fd);

    printf("[P2P] Encrypted message sent to Client %d\n", target_id);
}

int main(int argc, char* argv[]) {  //eg: ./c 1 127.0.0.1 
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <id 1-5> <server_ip>\n", argv[0]);
        return 1;
    }
    my_id = atoi(argv[1]);
    const char* server_ip = argv[2];

    // Generate my RSA key pair
    my_rsa = rsa_keygen();
    printf("[Client %d] RSA keys ready. n=%lu\n", my_id, my_rsa.n);

    // Connecting to the server
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(SERVER_PORT);
    inet_pton(AF_INET, server_ip, &addr.sin_addr); //server_ip taken from argv

    if (connect(server_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Cannot connect to %s\n", server_ip);
        return 1;
    }
    printf("[Client %d] Connected to server.\n", my_id);

    //Now sending my RSA public key
    char reg[16];
    // Send RSA public key as raw bytes: [e:8][n:8]
    memcpy(reg,     &my_rsa.e, 8);
    memcpy(reg + 8, &my_rsa.n, 8);
    Packet reg_pkt = make_packet(MSG_REGISTER, reg, 16);
    send_packet(server_fd, reg_pkt);

    //Now recieving server's RSA public key 
    Packet welcome;
    recv_packet(server_fd, welcome);
    uint64_t srv_e, srv_n;
    // Server sends RSA public key as raw bytes: [e:8][n:8]
    memcpy(&srv_e, welcome.data,     8);
    memcpy(&srv_n, welcome.data + 8, 8);
    printf("[Client %d] Got server public key. n=%lu\n", my_id, srv_n);

    //Now recieving AES session key (RSA-encrypted) 
    Packet sk_pkt;
    recv_packet(server_fd, sk_pkt);
    // Decrypting the 8-byte AES key using my RSA private key
    // Server sent 8 bytes × 8 (each byte RSA-encrypted) = 64 bytes
    rsa_decrypt_bytes((uint8_t*)sk_pkt.data, sk_pkt.length,my_rsa.d, my_rsa.n, aes_key, sizeof(aes_key));
    printf("[Client %d] AES session key decrypted. Secure channel ready!\n\n", my_id);

    auction_on = true;

    // Starting the background threads
    std::thread(udp_thread).detach();     // live bid updates(Thread for UDP Multicast)
    std::thread(p2p_thread).detach();     // incoming private chats
    std::thread(server_thread).detach();  // auction messages from server

    std::string line;
    while (auction_on && std::getline(std::cin, line)) {
        if (line.empty()) continue;
        std::istringstream ss(line);  //for separating white spaces
        std::string cmd;
        ss >> cmd;

        if (cmd == "bid") {
            int amount;
            if (!(ss >> amount)){ 
                printf("Usage: bid <amount>\n"); 
                continue; 
            }
            if (amount > my_budget) {
                printf("Not enough budget! (%d Cr left)\n", my_budget);
                continue;
            }
            char msg[16];
            snprintf(msg, sizeof(msg), "%d", amount);
            send_to_server(MSG_BID, msg, strlen(msg));
            printf("[Bid sent] %d Cr for %s\n", amount, cur_player_name);

        } else if (cmd == "pass") {
            send_to_server(MSG_PASS, "p", 1);
            printf("[Pass]\n");

        } else if (cmd == "team") {
            print_team();

        } else if (cmd == "chat") {
            int target;
            std::string msg;
            if (!(ss >> target)) { 
                printf("Usage: chat <id> <message>\n"); 
                continue; 
            }
            std::getline(ss, msg);
            if (!msg.empty() && msg[0] == ' ') msg = msg.substr(1);
            send_p2p(target, server_ip, msg.c_str());  //c_str() for bridging gap between c and c++

        } else if (cmd == "help") {
            printf("  bid <amount>       — bid on current player\n");
            printf("  pass               — skip current player\n");
            printf("  team               — show your squad\n");
            printf("  chat <id> <msg>    — private encrypted chat\n");
        }
    }

    close(server_fd);
    return 0;
}