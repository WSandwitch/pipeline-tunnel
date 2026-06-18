#ifndef SESSION_H
#define SESSION_H

#include <cstdint>
#include <memory>
#include <vector>
#include <string>
#include <atomic>
#include <mutex>
#include <functional>
#include <unordered_map>
#include <chrono>
#include "core/kernel.h"
#include "core/protocol.h"
#include "core/config.h"
#include "core/chain.h"
#include "core/chain_ref.h"
#include "core/kernel_api.h"
#include "common/write_buffer.h"

class Session : public std::enable_shared_from_this<Session> {
public:
    Session(int client_fd, const std::string &password, std::shared_ptr<Kernel> kernel,
            int heartbeat_interval_ms = 30000);
    ~Session();

    int client_fd() const { return client_fd_; }
    uint64_t session_id() const { return session_id_; }

    enum State {
        AWAIT_AUTH1_CHALLENGE_RESP,
        AWAIT_AUTH1_OK,
        AWAIT_AUTH2_RESPONSE,
        AUTH_DONE,
        AWAIT_CONNECT_REQ,
        AWAIT_CHAIN_CREATE,
        RUNNING,
        DISCONNECTED,
    };

    State state() const { return state_; }

    void on_data(const uint8_t *data, size_t len);
    void send_packet(const Packet &pkt);
    void set_challenge(const std::string &challenge) { challenge1_ = challenge; }
    void on_disconnect();
    bool reconnect(int new_client_fd);
    void add_data_connection(uint8_t output_idx, int fd);

private:
    int client_fd_;
    std::string password_;
    std::shared_ptr<Kernel> kernel_;
    uint64_t session_id_;

    std::mutex io_mutex_;

    State state_ = AWAIT_AUTH1_CHALLENGE_RESP;
    Protocol proto_;
    std::vector<uint8_t> recv_buf_;

    std::string challenge1_;

    // Chain integration
    KernelAPI chain_kapi_;
    ChainRef chain_ref_;
    std::unique_ptr<Chain> chain_;
    ChainConfig chain_config_;

    // Data connections for split outputs (index 0 = primary)
    struct DataConnection {
        int fd = -1;
        WriteBuffer writer;
        std::vector<uint8_t> read_buf;
        size_t read_offset = 0;
        // Note: DC fds are never gated — gating one connection kills merge
        // which needs chunks from all connections to reassemble packets.
    };
    std::vector<DataConnection> data_connections_;

    void register_target_epollout(uint8_t conn_id, int tfd);
    void register_data_conn_epollout(size_t idx, int fd);

    void send_writer_pause(uint8_t conn_id);
    void send_writer_resume(uint8_t conn_id);
    void send_chain_pause();
    void send_chain_resume();
    void send_control(const Packet &pkt);

    void register_data_connection_reader(size_t idx);
    void dispatch_data_conn_packet(const uint8_t *payload, size_t len, int src_idx);
    void process_wire_buffer(const uint8_t *data, size_t len);

    // Target connections
    struct TargetConn {
        int fd = -1;
        std::string addr;
        WriteBuffer writer;
        bool writer_paused = false;        // received MSG_WRITER_PAUSE — remote socket full
        bool local_writer_sent = false;    // sent MSG_WRITER_PAUSE
        bool ext_overflow_paused = false;  // local writer overflow (dc writer full)
        bool chain_paused = false;         // received MSG_CHAIN_PAUSE — remote chain full
        bool local_chain_sent = false;     // sent MSG_CHAIN_PAUSE
        bool shutdown_wr = false;      // received SHUTDOWN_WR from client
        bool shutdown_wr_sent = false; // shutdown(fd, SHUT_WR) called
        bool epollin_removed = false;    // EPOLLIN was removed from fd
    };
    std::unordered_map<uint8_t, TargetConn> targets_;
    std::mutex targets_mtx_;

    // Server-side conn_id allocation
    uint8_t alloc_conn_id();

    std::vector<std::pair<uint8_t, std::string>> saved_targets_;
    // Targets to reconnect after all data connections are ready
    std::vector<std::pair<uint8_t, std::string>> pending_reconnect_targets_;
    std::atomic<bool> paused_{false};
    std::atomic<bool> destroying_{false};

    void handle_auth_challenge_response(const Packet &pkt);
    void handle_auth2_challenge(const Packet &pkt);
    void handle_auth2_response(const Packet &pkt);
    void handle_reconnect(const Packet &pkt);
    void handle_connect_req(const Packet &pkt);
    void handle_disconnect(const Packet &pkt);
    void handle_writer_pause(const Packet &pkt);
    void handle_writer_resume(const Packet &pkt);
    void handle_chain_pause(const Packet &pkt);
    void handle_chain_resume(const Packet &pkt);
    void handle_module_list_req(const Packet &pkt);
    void handle_chain_create(const Packet &pkt);
    bool setup_tunnel_target(const std::string &target_addr, uint8_t conn_id);
    void handle_target_eof(uint8_t conn_id);
    void close_target(uint8_t conn_id);
    void close_all_targets();

    // Pending data connections that arrived before chain create (9-byte handshake)
    std::vector<std::pair<uint8_t, int>> pending_data_conns_;
    void process_pending_data_conns();
    void process_pending_reconnect_targets();

    // Total extra outputs needed (from _requested_outputs)
    int total_extra_outputs_ = 0;
    // RR counter for send_control
    std::atomic<int> control_rr_counter_{0};

    // Heartbeat
    std::chrono::steady_clock::time_point last_wire_activity_;
    bool heartbeating_ = false;
    int heartbeat_interval_ms_;

    bool dc_paused_ = false;
    std::mutex data_mtx_;
    std::vector<std::function<void()>> pending_io_;

    // Deferred disconnect: MSG_DISCONNECT sent after chain drains
    bool disconnect_pending_ = false;
    std::vector<uint8_t> disconnect_ids_;

    // Client-initiated disconnect: just close target, no message sent back
    std::vector<uint8_t> pending_disconnect_targets_;

public:
    void process_pending_io();
    void check_heartbeat();

private:
    void send_disconnect_now(uint8_t conn_id);
    void send_pending_disconnects();
};

#endif
