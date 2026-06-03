#ifndef CLIENT_H
#define CLIENT_H

#include <string>
#include <memory>
#include <vector>
#include <cstdint>
#include <functional>
#include <mutex>
#include <condition_variable>
#include <netinet/in.h>
#include <unordered_map>
#include "core/chain.h"
#include "core/kernel.h"
#include "core/protocol.h"
#include "core/config.h"
#include "common/write_buffer.h"

using DataCallback = std::function<void(const uint8_t *, size_t)>;

class Client {
public:
    // Blocks until chain is ready or fails
    bool wait_ready();
public:
    Client(const std::string &server_host, uint16_t server_port,
           const std::string &password,
           const std::string &listen_addr, uint16_t listen_port,
           const std::string &target_addr,
           const std::vector<ModuleSpec> &modules,
           const std::string &mod_dir = "",
           int thread_count = 4);
    ~Client();

    bool start();
    void stop();

    // Set callback for raw data received after tunnel is running
    void set_data_callback(DataCallback cb) { on_data_callback_ = std::move(cb); }

    // Send raw data to server (only valid after RUNNING)
    void send_raw(const uint8_t *data, size_t len);

private:
    std::string server_host_;
    uint16_t server_port_;
    std::string password_;

    // For tunnel mode: listen address and port (for accepting external clients)
    std::string listen_addr_;
    uint16_t listen_port_ = 0;
    // Target address where server forwards connections (from -L target:port)
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
        AWAIT_CONNECT_OK,
        RUNNING,
    };
    State state_ = DISCONNECTED;
    std::string challenge1_;
    std::string client_challenge_;

    // Multiplexed external connections (connection_id → external fd)
    struct ExternalConn {
        int fd = -1;
        struct sockaddr_in addr;
        bool connected = false;
        WriteBuffer writer;          // buffered writes to external_fd
        bool paused = false;         // MSG_CONNECT_PAUSE from server
        bool pause_sent = false;     // we sent MSG_CONNECT_PAUSE to server
        bool disconnecting = false;  // MSG_DISCONNECT received, waiting for buffer drain
        bool paused_by_backpressure = false;  // chain_in_writer full, EPOLLIN removed
    };
    std::unordered_map<uint8_t, ExternalConn> conns_;
    std::mutex conns_mtx_;
    uint8_t next_conn_id_ = 0;

    std::vector<ModuleSpec> modules_;
    std::string mod_dir_;
    std::unordered_map<std::string, std::string> module_registry_;
    int thread_count_ = 4;

    std::shared_ptr<Kernel> kernel_;
    std::shared_ptr<Chain> chain_;

    // Write buffers for non-blocking writes
    WriteBuffer chain_in_writer_;     // on_external_recv → chain input fd
    WriteBuffer chain_out_writer_;    // handle_data → chain output fd
    std::vector<uint8_t> chain_in_read_buf_;

    // Data connections — one per chain output (raw varint framing)
    struct DataConnection {
        int fd = -1;
        WriteBuffer writer;
        std::vector<uint8_t> read_buf;
        bool paused = false;           // EPOLLIN removed due to chain_out_writer back-pressure
        std::unique_ptr<std::mutex> pause_mtx = std::make_unique<std::mutex>();
    };
    std::vector<DataConnection> data_connections_;
    uint8_t num_outputs_ = 0;

    DataCallback on_data_callback_;
    std::mutex ready_mutex_;
    std::condition_variable ready_cv_;
    bool ready_ = false;
    bool failed_ = false;

    bool connect_to_server();
    void open_additional_connections();
    void start_listener();
    void stop_listener();
    void on_listener_accept(int client_fd, const struct sockaddr_in &addr);
    void on_external_recv(int conn_id, const uint8_t *data, size_t len);
    void on_external_disconnect(uint8_t conn_id);
    void on_server_data(const uint8_t *data, size_t len);

    void send_packet(const Packet &pkt);
    void send_control(const Packet &pkt);
    void send_raw_to_external(uint8_t conn_id, const uint8_t *data, size_t len);
    void finish_disconnect(uint8_t conn_id);
    void build_client_chain();

    // Epollout registration helpers
    void register_chain_in_epollout(int fd);
    void register_chain_out_epollout(int fd);
    void register_data_conn_epollout(size_t idx, int fd);
    void register_external_epollout(uint8_t conn_id, int fd);

    // Data connection reader
    void register_data_connection_reader(size_t idx);
    void dispatch_data_conn_packet(uint8_t conn_id, const uint8_t *payload, size_t len);

    // Pause/resume helpers
    void send_pause(uint8_t conn_id);
    void send_resume(uint8_t conn_id);
    void resume_paused_cfds();
    void resume_paused_dcfds();

    void load_module_registry(const std::string &dir);

    void handle_auth1_challenge(const Packet &pkt);
    void handle_auth1_ok(const Packet &pkt);
    void handle_auth2_challenge(const Packet &pkt);
    void handle_module_list_res(const Packet &pkt);
    void handle_chain_ready(const Packet &pkt);
    void handle_connect_ok(const Packet &pkt);
    void handle_connect_fail(const Packet &pkt);
    void handle_disconnect(const Packet &pkt);
    void handle_connect_pause(const Packet &pkt);
    void handle_connect_resume(const Packet &pkt);
};

#endif
