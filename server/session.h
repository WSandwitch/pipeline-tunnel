#ifndef SESSION_H
#define SESSION_H

#include <cstdint>
#include <memory>
#include <vector>
#include <string>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include "core/chain.h"
#include "core/kernel.h"
#include "core/protocol.h"
#include "common/write_buffer.h"

class Session : public std::enable_shared_from_this<Session> {
public:
    Session(int client_fd, const std::string &password, std::shared_ptr<Kernel> kernel);
    ~Session();

    int client_fd() const { return client_fd_; }
    uint64_t session_id() const { return session_id_; }

    // Auth state machine
    enum State {
        AWAIT_AUTH1_CHALLENGE_RESP, // sent challenge, wait response
        AWAIT_AUTH1_OK,             // sent OK, wait client challenge
        AWAIT_AUTH2_RESPONSE,       // sent response, wait OK
        AUTH_DONE,
        AWAIT_MODULE_LIST_REQ,
        AWAIT_CHAIN_CREATE,
        AWAIT_CONNECT_REQ,
        RUNNING,
        DISCONNECTED,
    };

    State state() const { return state_; }

    // Process incoming data from client (serialized by io_mutex_)
    void on_data(const uint8_t *data, size_t len);

    // Send packet to client
    void send_packet(const Packet &pkt);

    // Set auth challenge (called by server before sending)
    void set_challenge(const std::string &challenge) { challenge1_ = challenge; }

    // Get chain
    std::shared_ptr<Chain> chain() const { return chain_; }

    // Called when client disconnects — pauses chain, saves for reconnection
    void on_disconnect();

    // Called on reconnection — reassigns client_fd, restarts chain handlers
    bool reconnect(int new_client_fd);

    // Add a data connection (from handshake accept)
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

    struct ModuleInfo { uint8_t id; std::string name; };
    std::vector<ModuleInfo> loaded_modules_;

    std::shared_ptr<Chain> chain_;

    // Data connections — one per chain output, used after chain setup
    struct DataConnection {
        int fd = -1;
        WriteBuffer writer;                      // buffered writes to this data connection
        std::vector<uint8_t> read_buf;           // varint parse buffer
        bool paused = false;                     // EPOLLIN removed due to chain_out_writers back-pressure
    };
    std::vector<DataConnection> data_connections_;
    uint8_t num_outputs_ = 0;

    // Write buffering for chain input backpressure
    WriteBuffer chain_in_writer_;
    std::vector<WriteBuffer> chain_out_writers_;  // per chain output fd (target→chain)

    // Read buffers for streaming varint parsing (avoids data loss on partial reads)
    std::vector<uint8_t> chain_in_read_buf_;

    void flush_write_buf();
    void register_chain_input_out();
    void resume_paused_targets();

    // Per-target epollout registration (chain output → target_fd)
    void register_target_epollout(uint8_t conn_id, int tfd);
    // Per-chain-output epollout (target_fd → chain output pipe)
    void register_chain_out_epollout(size_t idx, int out_fd);
    // Register epollout on a data connection
    void register_data_conn_epollout(size_t idx, int fd);

    void send_pause(uint8_t conn_id);
    void send_resume(uint8_t conn_id);

    // Send a control message (conn_id=255) over the data connection
    void send_control(const Packet &pkt);

    // Register data connection reader (reads raw varint, dispatches by conn_id)
    void register_data_connection_reader(size_t idx);

    // Dispatch a raw varint payload from a data connection
    void dispatch_data_conn_packet(uint8_t conn_id, const uint8_t *payload, size_t len);

    // Target connections (connection_id → target fd)
    struct TargetConn {
        int fd = -1;
        std::string addr;
        WriteBuffer writer;                // buffered writes to target_fd
        bool paused_by_client = false;     // MSG_CONNECT_PAUSE received from client
        bool pause_sent = false;           // we sent MSG_CONNECT_PAUSE to client
        bool paused_by_backpressure = false; // chain_in_writer full, EPOLLIN removed
    };
    std::unordered_map<uint8_t, TargetConn> targets_;
    uint8_t next_conn_id_ = 0;

    std::vector<std::pair<uint8_t, std::string>> saved_targets_;
    std::atomic<bool> paused_{false};

    void handle_auth_challenge_response(const Packet &pkt);
    void handle_auth2_challenge(const Packet &pkt);
    void handle_auth2_response(const Packet &pkt);
    void handle_module_list_req(const Packet &pkt);
    void handle_chain_create(const Packet &pkt);
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
