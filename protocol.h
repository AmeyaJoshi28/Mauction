#pragma once
#include <cstdint>
#include <cstring>


// Message types(1 byte)
#define MSG_REGISTER    1   // Client to Server: hi, here is my RSA public key
#define MSG_WELCOME     2   // Server to Client: hi, here is the server's RSA public key
#define MSG_SESSION_KEY 3   // Server to Client: AES key (encrypted with client's RSA key)
#define MSG_PLAYER_UP   4   // Server to Client: this player is now up for auction
#define MSG_BID         5   // Client to Server: I bid X crores (encrypted with AES)
#define MSG_PASS        6   // Client to Server: I pass on this player
#define MSG_SOLD        7   // Server to Client: player sold to client X for Y crores
#define MSG_UNSOLD      8   // Server to Client: player unsold
#define MSG_CHAT        9   // Client to Client: private encrypted chat (P2P)
#define MSG_AUCTION_END 10  // Server to Client: auction is over
#define MSG_GET_KEY     11  // Client to Server: give me public key of client X
#define MSG_KEY_REPLY   12  // Server to Client: here is the requested public key


#pragma pack(push, 1)   // Tell compiler: No padding bytes between fields to have an allignment based on 1 byte
struct Packet {
    uint8_t  type;         
    uint16_t length;       
    char     data[2048];    
};
#pragma pack(pop)


inline int packet_size(const Packet& p) {
    return 3 + p.length;    // 1 byte type + 2 bytes length + data
}

inline Packet make_packet(uint8_t type, const char* data, uint16_t len) {
    Packet p;
    p.type   = type;
    p.length = len;
    memcpy(p.data, data, len);
    return p;
}


inline bool send_packet(int fd, const Packet& p) {
    int sz = packet_size(p);
    return send(fd, &p, sz, 0) == sz;
}


inline bool recv_packet(int fd, Packet& p) {
    // First read the 3-byte header (type + length)
    if (recv(fd, &p, 3, MSG_WAITALL) != 3) return false;
    // Then read exactly p.length bytes of data
    if (p.length > 0) {
        if (recv(fd, p.data, p.length, MSG_WAITALL) != p.length) return false;
    }
    return true;
}

#define SERVER_PORT     8080          // TCP port the server listens on
#define MCAST_GROUP    "239.0.0.1"   // UDP multicast address (bid updates)
#define MCAST_PORT      9090          // UDP multicast port
#define P2P_BASE_PORT   10000         // Client i listens on 10000+i for P2P chat
#define MAX_CLIENTS     5
#define BUDGET          100           // each team gets 100 crores
#define NUM_PLAYERS     20            
#define BID_TIME        10            // seconds per player