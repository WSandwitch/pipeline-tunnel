#!/usr/bin/env ruby
# frozen_string_literal: true

# Tests reconnection: client disconnects, reconnects with same session_id,
# chain resumes, data flows again.
#
# Scenarios (all run by default):
#   simple   -- auth -> chain -> data -> disconnect -> reconnect -> data
#   load     -- send 10 MB, disconnect mid-stream, reconnect, verify
#   multi    -- 3 disconnect/reconnect cycles

require 'optparse'
require 'socket'
require 'digest'
require 'timeout'

HOST = '127.0.0.1'
PASS = 'testpass'

options = {
  build_dir: nil,
  mod_dir: nil,
  scenarios: %w[simple load multi],
}

op = OptionParser.new do |o|
  o.banner = "Usage: #{$PROGRAM_NAME} -S <build_dir> -M <mod_dir> [scenarios...]"
  o.on('-S', '--server-dir DIR', 'Build dir') { |v| options[:build_dir] = v }
  o.on('-M', '--module-dir DIR', 'Module .so dir') { |v| options[:mod_dir] = v }
end
def find_bin(dir, name)
  [File.join(dir, name), File.join(dir, 'server', name), File.join(dir, 'client', name)].find { |f| File.exist?(f) }
end

rest = op.parse(ARGV)
options[:scenarios] = rest unless rest.empty?

SERVER = options[:build_dir] ? find_bin(options[:build_dir], 'ppltunnel-server') : nil
MPATH = options[:mod_dir]
unless SERVER && MPATH
  puts op.help
  exit 1
end

def find_free_port(low = 30_000, high = 34_000)
  50.times do
    port = rand(low..high)
    begin
      s = Socket.new(:INET, :STREAM)
      s.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
      s.bind(Addrinfo.tcp('0.0.0.0', port))
      s.close
      return port
    rescue Errno::EADDRINUSE, Errno::EACCES
    end
  end
  raise 'no free port'
end

def wait_port_listen(port, timeout = 10)
  deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
  while Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
    out = `ss -tln sport = #{port} 2>/dev/null`
    return if out.include?(":#{port}")
    sleep 0.05
  end
  raise "port #{port} not ready after #{timeout}s"
end

def killall
  system('killall', '-9', 'ppltunnel-server', 'ppltunnel-client', 'iperf3', %i[out err] => File::NULL)
end

# ---- Wire protocol helpers ----

def write_varint(val)
  buf = ''.b
  while val > 0x7F
    buf << (((val & 0x7F) | 0x80)).chr
    val >>= 7
  end
  buf << (val & 0x7F).chr
  buf
end

def read_varint(sock)
  val = 0
  shift = 0
  loop do
    buf = sock.recv(1)
    return nil if buf.nil? || buf.empty?
    c = buf.getbyte(0)
    val |= (c & 0x7F) << shift
    return val if (c & 0x80) == 0
    shift += 7
  end
end

def msg(t, p = +'')
  p = p.dup.force_encoding('BINARY') unless p.encoding == Encoding::BINARY
  write_varint(t) + write_varint(p.bytesize) + p
end

def recv_msg(s, timeout = 5)
  Timeout.timeout(timeout) do
    t = read_varint(s)
    return nil if t.nil?
    sz = read_varint(s)
    return nil if sz.nil?
    p = +''
    while p.bytesize < sz
      chunk = s.recv([sz - p.bytesize, 65536].min)
      return nil if chunk.nil? || chunk.empty?
      p << chunk
    end
    [t, p]
  end
rescue Timeout::Error
  nil
end

def sha256(s)
  Digest::SHA256.hexdigest(s)
end

def auth(sock)
  pkt = recv_msg(sock)
  raise 'no auth challenge' unless pkt && pkt[0] == 0x01
  sock.send(msg(0x02, sha256(pkt[1] + PASS)), 0)
  pkt = recv_msg(sock)
  raise 'auth1 failed' unless pkt && pkt[0] == 0x03 && pkt[1].getbyte(0) == 1

  c2 = "c#{rand(999_999)}"
  sock.send(msg(0x01, c2), 0)
  pkt = recv_msg(sock)
  raise 'no auth2 challenge' unless pkt && pkt[0] == 0x02
  raise 'auth2 challenge mismatch' unless pkt[1] == sha256(c2 + PASS)
  sock.send(msg(0x03, "\x01"), 0)
  puts "auth OK sid=#{$sid}"
end

# After auth, the server switches to wire format (data connection reader).
# All post-auth messages must be wrapped in WIRE_CONTROL frames.
def send_control(sock, type, payload = +'')
  payload = payload.dup.force_encoding('BINARY') unless payload.encoding == Encoding::BINARY
  inner = write_varint(type) + write_varint(payload.bytesize) + payload
  frame = write_varint(1 + inner.bytesize) + "\x05" + inner
  sock.send(frame, 0)
end

def recv_control(sock, timeout = 10)
  Timeout.timeout(timeout) do
    flen = read_varint(sock)
    return nil if flen.nil? || flen < 2
    wire_type = sock.recv(1)
    return nil if wire_type.nil? || wire_type.empty? || wire_type.getbyte(0) != 5
    t = read_varint(sock)
    return nil if t.nil?
    sz = read_varint(sock)
    return nil if sz.nil?
    p = +''
    while p.bytesize < sz
      chunk = sock.recv([sz - p.bytesize, 65536].min)
      return nil if chunk.nil? || chunk.empty?
      p << chunk
    end
    [t, p]
  end
rescue Timeout::Error
  nil
end

def send_wire_data(sock, conn_id, data)
  data = data.b
  payload = conn_id.chr.b + data
  len = write_varint(1 + payload.bytesize)
  frame = len + "\x00".b + payload
  sock.send(frame, 0)
  frame
end

def recv_wire_data(sock, timeout = 10)
  Timeout.timeout(timeout) do
    flen = read_varint(sock)
    return nil if flen.nil? || flen < 2
    type = sock.recv(1)
    return nil if type.nil? || type.empty? || type.getbyte(0) != 0
    conn_id_byte = sock.recv(1)
    return nil if conn_id_byte.nil? || conn_id_byte.empty?
    conn_id = conn_id_byte.getbyte(0)
    payload_len = flen - 2
    data = +''
    while data.bytesize < payload_len
      chunk = sock.recv([payload_len - data.bytesize, 65536].min)
      return nil if chunk.nil? || chunk.empty?
      data << chunk
    end
    [conn_id, data]
  end
rescue Timeout::Error
  nil
end

def create_chain(sock)
  send_control(sock, 0x10, "\x00")   # MSG_MODULE_LIST_REQ (count=0)
  r = recv_control(sock)
  raise "no module list response: got #{r.inspect}" unless r && r[0] == 0x11
  send_control(sock, 0x20, "\x00")   # MSG_CHAIN_CREATE (empty chain)
  r = recv_control(sock)
  raise "expected TRANSMIT_READY, got #{r.inspect}" unless r && r[0] == 0x22
  r = recv_control(sock)
  raise "no chain ready: got #{r.inspect}" unless r && r[0] == 0x21 && r[1].getbyte(0) == 0x01
  sid = r[1][1..8].unpack1('Q<')
  r = recv_control(sock)
  raise "expected trailing TRANSMIT_READY, got #{r.inspect}" unless r && r[0] == 0x22
  sid
end

def send_connect_req(sock, addr)
  payload = [addr.bytesize, addr].pack('CA*')
  send_control(sock, 0x30, payload)  # MSG_CONNECT_REQ
  r = recv_control(sock)
  raise "connect failed: #{r.inspect}" unless r && r[0] == 0x31
  r[1].getbyte(0)  # conn_id
end

# ---- Test scenarios ----

def start_echo(port)
  ls = TCPServer.new(HOST, port)
  thr = Thread.new do
    loop do
      conn = ls.accept rescue break
      Thread.new(conn) do |c|
        while (d = c.recv(65536))
          break if d.empty?
          c.send(d, 0)
        end
        c.close rescue nil
      end
    end
  end
  sleep 0.2
  [ls, thr]
end

def wait_for_pause
  sleep 1.5
end

def wait_for_reconnect_targets
  sleep 1.0
end

def test_simple
  svr = nil
  begin
    svr_port = find_free_port
    svr = Process.spawn(SERVER, "-l#{HOST}:#{svr_port}", "-A#{PASS}",
                        "-M#{MPATH}", "-vv")
    wait_port_listen(svr_port)

    tgt = find_free_port
    echo_ls, echo_thr = start_echo(tgt)

    # --- First connection ---
    sock1 = Socket.new(:INET, :STREAM)
    sock1.connect(Addrinfo.tcp(HOST, svr_port))
    auth(sock1)
    sid = create_chain(sock1)
    conn_id = send_connect_req(sock1, "#{HOST}:#{tgt}")
    wait_for_reconnect_targets

    data1 = 'HelloEcho'
    send_wire_data(sock1, conn_id, data1)
    r = recv_wire_data(sock1)
    raise "no echo" if r.nil?
    _cid, echo1 = r
    raise "data mismatch pre: #{echo1.bytesize} vs #{data1.bytesize}" unless echo1 == data1
    puts "  simple: pre-disconnect OK"

    # --- Disconnect ---
    sock1.close
    wait_for_pause

    # --- Reconnect: new TCP connection, send MSG_RECONNECT as varint ---
    sock2 = Socket.new(:INET, :STREAM)
    sock2.connect(Addrinfo.tcp(HOST, svr_port))
    # Wait for server poll timeout (200ms) to avoid the 9-byte data-connection
    # handshake check consuming MSG_RECONNECT bytes
    sleep 0.25
    sock2.send(msg(0x05, [sid].pack('Q<')), 0)  # MSG_RECONNECT
    # Drain MSG_AUTH_CHALLENGE (sent during the wait period), then read AUTH_OK
    pkt = nil
    loop do
      pkt = recv_msg(sock2)
      break if pkt.nil? || pkt.empty?
      break if pkt[0] == 0x03  # MSG_AUTH_OK
    end
    raise "reconnect failed: #{pkt.inspect}" unless pkt && pkt[0] == 0x03 && pkt[1].getbyte(0) == 1
    wait_for_reconnect_targets

    data2 = 'B' * 2048
    send_wire_data(sock2, conn_id, data2)
    _cid, echo2 = recv_wire_data(sock2)
    raise "data mismatch post" unless echo2 == data2

    puts "  simple: post-reconnect OK"
    sock2.close
  ensure
    echo_ls.close rescue nil
    echo_thr.kill rescue nil
    Process.kill('TERM', svr) if svr
    Timeout.timeout(3) { Process.wait(svr) rescue nil } rescue nil
    killall
  end
end

def test_load
  svr = nil
  begin
    svr_port = find_free_port
    svr = Process.spawn(SERVER, "-l#{HOST}:#{svr_port}", "-A#{PASS}",
                        "-M#{MPATH}", %i[out err] => File::NULL)
    wait_port_listen(svr_port)

    tgt = find_free_port
    echo_ls, echo_thr = start_echo(tgt)

    sock1 = Socket.new(:INET, :STREAM)
    sock1.connect(Addrinfo.tcp(HOST, svr_port))
    auth(sock1)
    sid = create_chain(sock1)
    conn_id = send_connect_req(sock1, "#{HOST}:#{tgt}")
    wait_for_reconnect_targets

    # Send a large chunk, then disconnect mid-stream
    big = 'X' * 5_000_000
    send_wire_data(sock1, conn_id, big)

    # Start reading, but disconnect before all data arrives
    Thread.new do
    sleep 1.0
      sock1.close
    end
    begin
      recv_wire_data(sock1, 2)
    rescue
    end

    wait_for_pause

    sock2 = Socket.new(:INET, :STREAM)
    sock2.connect(Addrinfo.tcp(HOST, svr_port))
    sleep 0.25
    sock2.send(msg(0x05, [sid].pack('Q<')), 0)
    pkt = nil
    loop do
      pkt = recv_msg(sock2)
      break if pkt.nil? || pkt.empty?
      break if pkt[0] == 0x03  # MSG_AUTH_OK
    end
    raise "reconnect failed (load): #{pkt.inspect}" unless pkt && pkt[0] == 0x03 && pkt[1].getbyte(0) == 1
    wait_for_reconnect_targets

    verify = 'C' * 512
    send_wire_data(sock2, conn_id, verify)
    _cid, echo_v = recv_wire_data(sock2)
    raise "data mismatch after load disconnect" unless echo_v == verify
    puts "  load: OK"
    sock2.close
  ensure
    echo_ls.close rescue nil
    echo_thr.kill rescue nil
    Process.kill('TERM', svr) if svr
    Timeout.timeout(3) { Process.wait(svr) rescue nil } rescue nil
    killall
  end
end

def test_multi
  svr = nil
  begin
    svr_port = find_free_port
    svr = Process.spawn(SERVER, "-l#{HOST}:#{svr_port}", "-A#{PASS}",
                        "-M#{MPATH}", %i[out err] => File::NULL)
    wait_port_listen(svr_port)

    tgt = find_free_port
    echo_ls, echo_thr = start_echo(tgt)

    sock = Socket.new(:INET, :STREAM)
    sock.connect(Addrinfo.tcp(HOST, svr_port))
    auth(sock)
    sid = create_chain(sock)
    conn_id = send_connect_req(sock, "#{HOST}:#{tgt}")
    wait_for_reconnect_targets

    3.times do |i|
      pre = 'M' * (256 * (i + 1))
      send_wire_data(sock, conn_id, pre)
      _cid, echo_pre = recv_wire_data(sock)
      raise "multi: pre-disconnect iter #{i}" unless echo_pre == pre

      sock.close
      wait_for_pause

      sock = Socket.new(:INET, :STREAM)
      sock.connect(Addrinfo.tcp(HOST, svr_port))
      sleep 0.25
      sock.send(msg(0x05, [sid].pack('Q<')), 0)
      pkt = nil
      loop do
        pkt = recv_msg(sock)
        break if pkt.nil? || pkt.empty?
        break if pkt[0] == 0x03
      end
      raise "multi: reconnect failed iter #{i}: #{pkt.inspect}" unless pkt && pkt[0] == 0x03 && pkt[1].getbyte(0) == 1
      wait_for_reconnect_targets

      post = 'N' * (512 * (i + 1))
      send_wire_data(sock, conn_id, post)
      _cid, echo_post = recv_wire_data(sock)
      raise "multi: data mismatch iter #{i}" unless echo_post == post
    end

    puts "  multi: 3 cycles OK"
    sock.close
  ensure
    echo_ls.close rescue nil
    echo_thr.kill rescue nil
    Process.kill('TERM', svr) if svr
    Timeout.timeout(3) { Process.wait(svr) rescue nil } rescue nil
    killall
  end
end

# ---- Main ----

scenarios = {
  'simple' => method(:test_simple),
  'load'   => method(:test_load),
  'multi'  => method(:test_multi),
}

all_ok = true
options[:scenarios].each do |name|
  fn = scenarios[name]
  unless fn
    puts "Unknown scenario: #{name}"
    all_ok = false
    next
  end
  begin
    fn.call
  rescue => e
    puts "  #{name}: FAIL -- #{e}"
    all_ok = false
  end
end

killall
exit all_ok ? 0 : 1
