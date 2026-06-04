#ifndef SESSION_H
#define SESSION_H

#include <cstdint>
#include <memory>
#include <vector>
#include <string>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include "core/kernel.h"
#include "core/protocol.h"
#include "common/write_buffer.h"
#include "common/utils.h"

class Session : public std::enable_shared_from_this<Session> {
public:
    Session(int client_fd, const std::string &password, std::shared_ptr<Kernel> kernel);
    ~Session();

    int client_fd() const { return client_fd_; }
    uint64_t session_id() const { return session_id_; }

    // Auth state machine
    enum State {
        AWAIT_AUTH1_CHALLENGE_RESP,
        AWAIT_AUTH1_OK,
        AWAIT_AUTH2_RESPONSE,
        AUTH_DONE,
        AWAIT_CONNECT_REQ,
        RUNNING,
        DISCONNECTED,
    };

    State state() const { return state_; }

    // Process incoming data from client
    void on_data(const uint8_t *data, size_t len);

    // Send packet to client
    void send_packet(const Packet &pkt);

    // Set auth challenge
    void set_challenge(const std::string &challenge) { challenge1_ = challenge; }

    void on_disconnect();
    bool reconnect(int new_client_fd);

    void add_data_connection(uint8_t output_idx, int fd);

private:
    int client_fd_;
    std::string password_;
    std::shared_ptr<Kernel> kernel_;
    uint64_t session_id_;

    FrameBuf frame_buf_;

    std::mutex io_mutex_;

    State state_ = AWAIT_AUTH1_CHALLENGE_RESP;
    Protocol proto_;
    std::vector<uint8_t> recv_buf_;

    std::string challenge1_;

    // Single data connection (passthrough, no chain)
    struct DataConnection {
        int fd = -1;
        WriteBuffer writer;
        std::vector<uint8_t> read_buf;
        size_t read_offset = 0;
        std::vector<uint8_t> paused_data;
        bool paused = false;
    };
    // data_connections_[0] is the client-facing fd (tunnel wire)
    std::vector<DataConnection> data_connections_;

    // Per-target epollout registration
    void register_target_epollout(uint8_t conn_id, int tfd);
    void register_data_conn_epollout(size_t idx, int fd);

    void send_pause(uint8_t conn_id);
    void send_resume(uint8_t conn_id);
    void send_control(const Packet &pkt);

    void register_data_connection_reader(size_t idx);
    void dispatch_data_conn_packet(uint8_t conn_id, const uint8_t *payload, size_t len);

    // Target connections
    struct TargetConn {
        int fd = -1;
        std::string addr;
        WriteBuffer writer;
        bool paused_by_client = false;
        bool pause_sent = false;
        bool paused_by_backpressure = false;
    };
    std::unordered_map<uint8_t, TargetConn> targets_;
    uint8_t next_conn_id_ = 0;

    std::vector<std::pair<uint8_t, std::string>> saved_targets_;
    std::atomic<bool> paused_{false};

    void handle_auth_challenge_response(const Packet &pkt);
    void handle_auth2_challenge(const Packet &pkt);
    void handle_auth2_response(const Packet &pkt);
    void handle_reconnect(const Packet &pkt);
    void handle_connect_req(const Packet &pkt);
    void handle_disconnect(const Packet &pkt);
    void handle_connect_pause(const Packet &pkt);
    void handle_connect_resume(const Packet &pkt);
    bool setup_tunnel_target(const std::string &target_addr, uint8_t conn_id = 0);
    void close_target(uint8_t conn_id);
    void close_all_targets();
};

#endif
