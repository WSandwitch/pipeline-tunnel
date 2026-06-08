#ifndef CLIENT_H
#define CLIENT_H

#include <string>
#include <memory>
#include <vector>
#include <deque>
#include <cstdint>
#include <functional>
#include <netinet/in.h>
#include <unordered_map>
#include <chrono>
#include "core/kernel.h"
#include "core/protocol.h"
#include "core/config.h"
#include "core/chain.h"
#include "core/chain_ref.h"
#include "core/kernel_api.h"
#include "common/write_buffer.h"

class Client {
public:
    Client(const std::string &server_host, uint16_t server_port,
           const std::string &password,
           const std::string &listen_addr, uint16_t listen_port,
           const std::string &target_addr,
           const std::vector<ModuleSpec> &modules,
           const std::string &mod_dir = "");
    ~Client();

    bool start();
    void stop();

    bool setup_ok() const { return setup_ok_; }

private:
    std::string server_host_;
    uint16_t server_port_;
    std::string password_;
    std::string listen_addr_;
    uint16_t listen_port_ = 0;
    std::string target_addr_;

    int tcp_fd_ = -1;
    int listen_fd_ = -1;

    Protocol proto_;
    std::vector<uint8_t> recv_buf_;

    uint64_t session_id_ = 0;

    enum State {
        DISCONNECTED,
        AWAIT_AUTH1_CHALLENGE,
        AWAIT_AUTH1_OK,
        AWAIT_AUTH2_OK,
        AWAIT_MODULE_LIST_RES,
        AWAIT_CHAIN_READY,
        RUNNING,
    };
    State state_ = DISCONNECTED;
    std::string challenge1_;
    std::string client_challenge_;

    bool setup_ok_ = false;

    // Chain integration
    KernelAPI chain_kapi_;
    ChainRef chain_ref_;
    std::unique_ptr<Chain> chain_;
    std::vector<ModuleSpec> modules_;
    std::string mod_dir_;
    ChainConfig chain_config_;

    // External connections from listener
    struct ExternalConn {
        int fd = -1;
        struct sockaddr_in addr;
        bool connected = false;
        WriteBuffer writer;
        bool paused = false;
        bool pause_sent = false;
        bool disconnecting = false;
        bool paused_by_backpressure = false;
        bool shutting_down_wr = false;
    };
    std::unordered_map<uint8_t, ExternalConn> conns_;

    // Pending ext fds waiting for conn_id from server
    struct PendingConn {
        int fd;
        struct sockaddr_in addr;
    };
    std::deque<PendingConn> pending_ext_;

    std::shared_ptr<Kernel> kernel_;

    struct DataConnection {
        int fd = -1;
        WriteBuffer writer;
        std::vector<uint8_t> priority_buf; // control msgs sent before data
        std::vector<uint8_t> read_buf;
        size_t read_offset = 0;
        bool paused = false;
    };
    std::vector<DataConnection> data_connections_;

    // Heartbeat
    std::chrono::steady_clock::time_point last_wire_activity_;
    bool heartbeating_ = false;  // true after idle_timeout, waiting for response

    bool connect_to_server();
    void start_listener();
    void stop_listener();
    void on_listener_accept(int client_fd, const struct sockaddr_in &addr);
    void on_external_recv(uint8_t conn_id, const uint8_t *data, size_t len);
    void on_external_disconnect(uint8_t conn_id);
    void on_server_data(const uint8_t *data, size_t len);

    void send_packet(const Packet &pkt);
    void send_control(const Packet &pkt);
    void send_raw_to_external(uint8_t conn_id, const uint8_t *data, size_t len);
    void finish_disconnect(uint8_t conn_id);

    void register_data_conn_epollout(size_t idx, int fd);
    void register_external_epollout(uint8_t conn_id, int fd);

    void register_data_connection_reader(size_t idx);
    void dispatch_data_conn_packet(const uint8_t *payload, size_t len);
    void process_wire_buffer(const uint8_t *data, size_t len);

    void send_pause(uint8_t conn_id);
    void send_resume(uint8_t conn_id);
    void resume_paused_dcfds();

    void handle_auth1_challenge(const Packet &pkt);
    void handle_auth1_ok(const Packet &pkt);
    void handle_auth2_challenge(const Packet &pkt);
    void handle_module_list_res(const Packet &pkt);
    void handle_connect_ok(const Packet &pkt);
    void handle_connect_fail(const Packet &pkt);
    void handle_disconnect(const Packet &pkt);
    void handle_connect_pause(const Packet &pkt);
    void handle_connect_resume(const Packet &pkt);
    void handle_chain_ready(const Packet &pkt);

    // Heartbeat check — called from kernel tick
    void check_heartbeat();
};

#endif
