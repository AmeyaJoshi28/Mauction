

#include <iostream>
#include <cstring>
#include <cstdio>
#include <thread>
#include <mutex>
#include <chrono>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "protocol.h"
#include "crypto.h"


struct Player {
    int  id;
    char name[40];
    char role[20];     
    int  base;          
    int  sold_for;      
    int  owner;         
};

Player players[NUM_PLAYERS] = {
    {1,  "Virat Kohli",      "Batsman",     15, 0, -1},
    {2,  "Rohit Sharma",     "Batsman",     14, 0, -1},
    {3,  "MS Dhoni",         "WK",          12, 0, -1},
    {4,  "Jasprit Bumrah",   "Bowler",      13, 0, -1},
    {5,  "Ravindra Jadeja",  "All-rounder", 11, 0, -1},
    {6,  "Ben Stokes",       "All-rounder", 12, 0, -1},
    {7,  "Pat Cummins",      "All-rounder", 11, 0, -1},
    {8,  "Shubhman Gill",    "Batsman",     11, 0, -1},
    {9,  "Rashid Khan",      "All-rounder",  9, 0, -1},
    {10, "Kane Williamson",  "Batsman",     10, 0, -1},
    {11, "KL Rahul",         "WK",          10, 0, -1},
    {12, "Shaheen Afridi",   "Bowler",      10, 0, -1},
    {13, "Andre Russell",    "All-rounder",  9, 0, -1},
    {14, "Kagiso Rabada",    "Bowler",       9, 0, -1},
    {15, "Jos Buttler",      "WK",           9, 0, -1},
    {16, "Suryakumar Yadav", "Batsman",     10, 0, -1},
    {17, "Hardik Pandya",    "All-rounder", 10, 0, -1},
    {18, "Wanindu Hasaranga","All-rounder",  9, 0, -1},
    {19, "David Warner",     "Batsman",     10, 0, -1},
    {20, "Trent Boult",      "Bowler",       8, 0, -1},
};

struct Client {
    int      fd;               // TCP socket (sockfd)
    int      id;                
    bool     active;           //Whether client is active or not
    uint64_t rsa_e, rsa_n;     // RSA public key of the client 
    uint8_t  aes_key[8];       // AES session key which the server will give to the client
    int      budget;
    char     team[10][40];     // Team, the list of players the client bought 
    int      team_size;
    uint16_t iv;               // Initial Vector for AES 
};

Client clients[MAX_CLIENTS];
int    num_connected = 0;
std::mutex mtx; // protects shared state, that is not sharing same state between 2 hosts

RSAKey server_key; 

// Here UDP socket is used for multicast broadcast done by the server to all the clients.
int udp_sock = -1;

// Auction state
int  cur_player   = 0;         
int  cur_bid      = 0;
int  cur_bidder   = -1;       
std::chrono::steady_clock::time_point last_bid_time; // set when each player is announced or bid.


// Sending a plain packet to a client
void send_plain(int fd, uint8_t type, const char* data, int len) {
    Packet p = make_packet(type, data, (uint16_t)len); //Function from protocol.h
    send_packet(fd, p);
}

// Sending an AES-encrypted packet to a specific client slot(id).
void send_enc(int slot, uint8_t type, const char* data, int len) {
    char buf[2048];
    uint64_t iv = clients[slot].iv++;
    int enc_len = aes_encrypt(data, len, clients[slot].aes_key, iv, buf, sizeof(buf));
    Packet p = make_packet(type, buf, (uint16_t)enc_len);
    send_packet(clients[slot].fd, p);
}

// Decrypting an incoming packet's data for a given client slot
int decrypt_from(int slot, const Packet& p, char* out, int out_max) {
    return aes_decrypt(p.data, p.length, clients[slot].aes_key, out, out_max);
}

// Broadcasting a message to all connected clients (encrypted individually)
void broadcast(uint8_t type, const char* data, int len) {
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (clients[i].active)
            send_enc(i, type, data, len);
}

// Sending bid update over UDP multicast, everyone on the network sees this
void udp_broadcast_bid(int player_id, int amount, int bidder) {
    char msg[128];
    int len = snprintf(msg, sizeof(msg),
                       "BID | Player #%d | %d Cr | by Client %d",
                       player_id, amount, bidder);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(MCAST_PORT);     //Defined in protocol.h
    inet_pton(AF_INET, MCAST_GROUP, &addr.sin_addr);
    sendto(udp_sock, msg, len, 0, (sockaddr*)&addr, sizeof(addr));
}

// Print final teams 
void save_results() {
    // Save auction results into auction_results.txt
    FILE* f = fopen("auction_results.txt", "w");
    if (!f) {
        printf("[Server] Error: Could not open auction_results.txt for writing\n");
        return;
    }

    fprintf(f, "╔════════════════════════════════════════════╗\n");
    fprintf(f, "║          CRICKET AUCTION RESULTS           ║\n");
    fprintf(f, "║          Final Teams and Budgets           ║\n");
    fprintf(f, "╚════════════════════════════════════════════╝\n\n");
    fprintf(f, "Total Players: %d\n\n", NUM_PLAYERS);

    int total_spent = 0;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!clients[i].active) continue;
        
        int spent = BUDGET - clients[i].budget;
        total_spent += spent;
        
        fprintf(f, "─────────────────────────────────────────────\n");
        fprintf(f, "       CLIENT %d\n", clients[i].id);
        fprintf(f, "─────────────────────────────────────────────\n");
        fprintf(f, "Budget Spent:     %d Cr\n", spent);
        fprintf(f, "Budget Remaining: %d Cr\n", clients[i].budget);
        fprintf(f, "Players Owned:    %d\n", clients[i].team_size);
        fprintf(f, "\n");
        //Printing the team.
        if (clients[i].team_size == 0) {
            fprintf(f, "  (No players purchased)\n\n");
        } else {
            for (int j = 0; j < clients[i].team_size; j++) {
                for (int p = 0; p < NUM_PLAYERS; p++) {
                    if (strcmp(players[p].name, clients[i].team[j]) == 0) {
                        fprintf(f, "  %d. %-25s [%-12s] Sold: %d Cr\n",  //-25s left alligned within 25 char
                                j + 1,    //Sr No.
                                players[p].name,
                                players[p].role,
                                players[p].sold_for);
                        break;
                    }
                }
            }
            fprintf(f, "\n");
        }
    }

    fprintf(f, "═════════════════════════════════════════════\n");
    fprintf(f, "              AUCTION SUMMARY\n");
    fprintf(f, "═════════════════════════════════════════════\n");
    fprintf(f, "Total Amount Spent: %d Cr\n", total_spent);
    fprintf(f, "Average per Client: %.1f Cr\n", total_spent / (float)MAX_CLIENTS);
    
    int sold = 0, unsold = 0;
    for (int i = 0; i < NUM_PLAYERS; i++) {
        if (players[i].owner == -1) unsold++;
        else sold++;
    }
    fprintf(f, "Number of Players Sold:       %d\n", sold);
    fprintf(f, "Number of Players Unsold:     %d\n", unsold);
    
    fprintf(f, "\n");
    fclose(f);
    printf("[Server] Results saved to auction_results.txt\n");
}

void print_teams() {  
    printf("\n══════════════ FINAL TEAMS ══════════════\n");
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!clients[i].active) continue;
        printf("Client %d | Budget left: %d Cr\n", clients[i].id, clients[i].budget);
        for (int j = 0; j < clients[i].team_size; j++)
            printf("   → %s\n", clients[i].team[j]);
        if (clients[i].team_size == 0) printf("   (no players)\n");
    }
    printf("═════════════════════════════════════════\n\n");
}

// Handles messages coming FROM a client
void client_thread(int slot) {
    int fd = clients[slot].fd;

    //Recieving client's RSA public key
    Packet p;
    if (!recv_packet(fd, p) || p.type != MSG_REGISTER) {
        clients[slot].active = false;
        close(fd);
        return;
    }
    // Client RSA public key was sent as raw bytes [e:8][n:8]
    uint64_t e, n;
    memcpy(&e, p.data,     8);
    memcpy(&n, p.data + 8, 8);
    clients[slot].rsa_e = e;
    clients[slot].rsa_n = n;
    printf("[Server] Client %d registered. RSA n=%lu\n", clients[slot].id, n);

    // Now sending server RSA public key as raw bytes [e:8][n:8] to the client
    char server_pub[16];
    memcpy(server_pub,     &server_key.e, 8);
    memcpy(server_pub + 8, &server_key.n, 8);
    send_plain(fd, MSG_WELCOME, server_pub, 16);

    // Make a random 8-byte AES key for this client
    srand(time(NULL) ^ fd);  //Generate based on current time and client's socket
    for (int i = 0; i < 8; i++)
        clients[slot].aes_key[i] = rand() % 256;
    // Encrypt the 8 AES key bytes using the client's RSA public key
    uint8_t enc_key[8 * 8];   // each byte becomes 8 bytes (RSA output)
    rsa_encrypt_bytes(clients[slot].aes_key, 8,
                      clients[slot].rsa_e, clients[slot].rsa_n,
                      enc_key, sizeof(enc_key));

    // Send the encrypted AES key to the client
    send_plain(fd, MSG_SESSION_KEY, (char*)enc_key, sizeof(enc_key));
    printf("[Server] Sent AES session key to Client %d (RSA-encrypted)\n",
           clients[slot].id);

    //Waiting until all clients are connected 
    {
        std::lock_guard<std::mutex> lock(mtx);  //This helps in protecting the part from changing by other client threads
        num_connected++;
        printf("[Server] %d/%d clients ready\n", num_connected, MAX_CLIENTS);
    }
    while (num_connected < MAX_CLIENTS)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Recieve Loop
    while (true) {
        Packet in;
        if (!recv_packet(fd, in)) {
            printf("[Server] Client %d disconnected\n", clients[slot].id);
            clients[slot].active = false;
            break;
        }

        //Client wants another client's public key in order to send a message.
        if (in.type == MSG_GET_KEY) {
            char dec[64] = {};
            decrypt_from(slot, in, dec, sizeof(dec)); //decrypt the message coming from client.
            int want_id = atoi(dec);

            // Find that client's RSA public key, send as raw bytes [id:4][e:8][n:8]
            char reply[20] = {};
            int reply_len = 4;  // default: just zeros = not found
            memcpy(reply, &want_id, 4);
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (clients[i].active && clients[i].id == want_id) {
                    memcpy(reply + 4,  &clients[i].rsa_e, 8);
                    memcpy(reply + 12, &clients[i].rsa_n, 8);
                    reply_len = 20;
                    break;
                }
            }
            send_enc(slot, MSG_KEY_REPLY, reply, reply_len);
            printf("[Server] Sent public key of Client %d to Client %d\n",
                   want_id, clients[slot].id);
        }

        //Client places a bid.
        if (in.type == MSG_BID) {
            char dec[64] = {};
            decrypt_from(slot, in, dec, sizeof(dec));
            int amount = atoi(dec);

            std::lock_guard<std::mutex> lock(mtx);//Lock so that no other clients affects it.

            if (amount <= cur_bid) {
                printf("[Server] Bid %d Cr from Client %d rejected (too low)\n",
                       amount, clients[slot].id);
                continue;
            }
            if (amount > clients[slot].budget) {
                printf("[Server] Bid %d Cr from Client %d rejected (over budget)\n",
                       amount, clients[slot].id);
                continue;
            }

            cur_bid = amount;
            cur_bidder = clients[slot].id;
            last_bid_time = std::chrono::steady_clock::now(); // reset the timer.
            printf("[Server] New highest bid: %d Cr by Client %d\n",
                   cur_bid, cur_bidder);

            // Broadcasting this bid to all the clients.
            udp_broadcast_bid(players[cur_player].id, cur_bid, cur_bidder);
        }

        //Client passes the player.
        if (in.type == MSG_PASS) {
            printf("[Server] Client %d passed\n", clients[slot].id);
        }
    }
}

// Runs independently, selling each player after BID_TIME seconds.
void auction_runner() {
    // Wait for all clients
    while (num_connected < MAX_CLIENTS)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    for (cur_player = 0; cur_player < NUM_PLAYERS; cur_player++) {
        Player& pl = players[cur_player];
        cur_bid    = pl.base;
        cur_bidder = -1;

        // Announcing the player to all clients.
        char msg[128];
        snprintf(msg, sizeof(msg), "%d|%s|%s|%d", pl.id, pl.name, pl.role, pl.base);
        broadcast(MSG_PLAYER_UP, msg, strlen(msg));
        printf("[Server] Player up: %s (base %d Cr)\n", pl.name, pl.base);

        // Reset the timer for this player, then wait until BID_TIME seconds
        // pass with NO new bid. Every new bid resets the countdown.
        {
            std::lock_guard<std::mutex> lock(mtx);
            last_bid_time = std::chrono::steady_clock::now();
        }
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            
            int secs_left;
            {
                std::lock_guard<std::mutex> lock(mtx);
                auto elapsed = std::chrono::steady_clock::now() - last_bid_time;
                secs_left = BID_TIME - (int)std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
            }
            if (secs_left > 0)
                printf("[Server] %s — %d sec left (current bid: %d Cr)\n",
                       pl.name, secs_left, cur_bid);
            else
                break;  // Time is up, sell the player.
        }

        // Sell or mark unsold
        std::lock_guard<std::mutex> lock(mtx);
        if (cur_bidder == -1) {
            printf("[Server] %s — UNSOLD\n", pl.name);
            snprintf(msg, sizeof(msg), "%s|UNSOLD|0|0", pl.name);
            broadcast(MSG_UNSOLD, msg, strlen(msg));
        } else {
            pl.sold_for = cur_bid;
            pl.owner    = cur_bidder;
            printf("[Server] %s SOLD to Client %d for %d Cr\n",
                   pl.name, cur_bidder, cur_bid);

            // Deducting the budget and adding to team
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (clients[i].active && clients[i].id == cur_bidder) {
                    clients[i].budget -= cur_bid;
                    strcpy(clients[i].team[clients[i].team_size++], pl.name);
                    break;
                }
            }

            snprintf(msg, sizeof(msg), "%s|SOLD|%d|%d", pl.name, cur_bid, cur_bidder);
            broadcast(MSG_SOLD, msg, strlen(msg));
        }
    }

    broadcast(MSG_AUCTION_END, "DONE", 4);
    print_teams();
    save_results(); 
}


int main() {
    // Generate server's RSA key pair
    server_key = rsa_keygen();
    printf("[Server] RSA keys ready. n=%lu  e=%lu\n",
           server_key.n, server_key.e);

    // Setting up the UDP multicast socket for broadcasting.
    udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    int ttl = 1;
    setsockopt(udp_sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
    printf("[Server] UDP multicast ready → %s:%d\n", MCAST_GROUP, MCAST_PORT);

    // Setting up the TCP server socket
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)); //Tells the OS to reuse the port and bind to it even if waiting.

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(SERVER_PORT);
    bind(srv, (sockaddr*)&addr, sizeof(addr));
    listen(srv, MAX_CLIENTS);
    printf("[Server] Listening on TCP port %d\n", SERVER_PORT);
    printf("[Server] Waiting for %d clients...\n\n", MAX_CLIENTS);

    // Starting the auction runner thread in background and run it independently.
    std::thread(auction_runner).detach(); 

    // Accepting the clients.
    for (int slot = 0; slot < MAX_CLIENTS; slot++) {
        sockaddr_in ca{}; socklen_t cl = sizeof(ca);
        int cfd = accept(srv, (sockaddr*)&ca, &cl);

        clients[slot].fd        = cfd;
        clients[slot].id        = slot + 1;
        clients[slot].active    = true;
        clients[slot].budget    = BUDGET;
        clients[slot].team_size = 0;
        clients[slot].iv        = 0;

        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ca.sin_addr, ip, sizeof(ip));
        printf("[Server] Client %d connected from %s\n", slot + 1, ip);

        std::thread(client_thread, slot).detach();
    }

    // Keep server alive
    std::this_thread::sleep_for(std::chrono::hours(1));
    close(srv);
    close(udp_sock);
    return 0;
}