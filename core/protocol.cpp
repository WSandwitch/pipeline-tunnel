#include "protocol.h"
#include <cstring>

static void write_varint(std::vector<uint8_t> &buf, uint64_t val) {
    while (val > 0x7F) {
        buf.push_back((uint8_t)((val & 0x7F) | 0x80));
        val >>= 7;
    }
    buf.push_back((uint8_t)(val & 0x7F));
}

static uint64_t read_varint(const uint8_t *buf, size_t len, size_t &consumed) {
    uint64_t val = 0;
    int shift = 0;
    consumed = 0;
    for (size_t i = 0; i < len && i < 10; i++) {
        consumed++;
        val |= (uint64_t)(buf[i] & 0x7F) << shift;
        if (!(buf[i] & 0x80)) return val;
        shift += 7;
    }
    return 0;
}

std::vector<uint8_t> Protocol::serialize(const Packet &pkt) const {
    std::vector<uint8_t> out;
    write_varint(out, (uint64_t)pkt.type);
    write_varint(out, (uint64_t)pkt.payload.size());
    out.insert(out.end(), pkt.payload.begin(), pkt.payload.end());
    return out;
}

size_t Protocol::try_parse(const uint8_t *buf, size_t len, Packet &out) const {
    size_t consumed = 0;

    uint64_t type_val = read_varint(buf, len, consumed);
    if (consumed == 0 || type_val > 0xFF) return 0;

    size_t offset = consumed;
    uint64_t pay_len = read_varint(buf + offset, len - offset, consumed);
    if (consumed == 0) return 0;
    offset += consumed;

    size_t total = offset + (size_t)pay_len;
    if (len < total) return 0;

    out.type = (MessageType)(uint8_t)type_val;
    out.payload.assign(buf + offset, buf + offset + (size_t)pay_len);
    return total;
}

Packet Protocol::make_msg(MessageType type, const void *data, size_t len) {
    Packet p;
    p.type = type;
    if (data && len) {
        p.payload.assign((const uint8_t *)data, (const uint8_t *)data + len);
    }
    return p;
}

Packet Protocol::make_msg(MessageType type, const std::vector<uint8_t> &data) {
    Packet p;
    p.type = type;
    p.payload = data;
    return p;
}
