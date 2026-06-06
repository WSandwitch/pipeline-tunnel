#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <cstdint>
#include <vector>
#include <string>

enum MessageType : uint8_t {
    MSG_AUTH_CHALLENGE = 0x01,
    MSG_AUTH_RESPONSE  = 0x02,
    MSG_AUTH_OK        = 0x03,
    MSG_RECONNECT       = 0x05,
    MSG_MODULE_LIST_REQ = 0x10,
    MSG_MODULE_LIST_RES = 0x11,
    MSG_CHAIN_CREATE    = 0x20,
    MSG_CHAIN_READY     = 0x21,
    MSG_CONNECT_REQ     = 0x30,
    MSG_CONNECT_OK      = 0x31,
    MSG_CONNECT_FAIL    = 0x32,
    MSG_MODULE_MSG      = 0x40,
    MSG_DISCONNECT      = 0x51,
    MSG_CONNECT_PAUSE   = 0x52,
    MSG_CONNECT_RESUME  = 0x53,
};

struct Packet {
    MessageType type;
    std::vector<uint8_t> payload;
};

class Protocol {
public:
    Protocol() = default;

    std::vector<uint8_t> serialize(const Packet &pkt) const;

    size_t try_parse(const uint8_t *buf, size_t len, Packet &out) const;

    static Packet make_msg(MessageType type, const void *data = nullptr, size_t len = 0);
    static Packet make_msg(MessageType type, const std::vector<uint8_t> &data);
};

// Wire-level protocol types (in the varint-framed wire format, after it's decoded)
const uint8_t WIRE_DATA = 0;
const uint8_t WIRE_HEARTBEAT_PING = 1;
const uint8_t WIRE_HEARTBEAT_PONG = 2;
const uint8_t WIRE_SHUTDOWN_WR = 3;
const uint8_t WIRE_SHUTDOWN_WR_ACK = 4;

#endif
