#!/usr/bin/env ruby
# frozen_string_literal: true

$stdout.sync = true

require 'socket'
require 'digest'
require 'timeout'

PASS = 'testpass'

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
    sz = read_varint(s)
    p = +''
    while p.bytesize < sz
      chunk = s.recv([sz - p.bytesize, 65536].min)
      p << chunk
    end
    [t, p]
  end
rescue Timeout::Error
  nil
end

def sha256(s) = Digest::SHA256.hexdigest(s)

def auth(sock)
  pkt = recv_msg(sock)
  raise "no auth challenge: #{pkt}" unless pkt && pkt[0] == 0x01
  sock.send(msg(0x02, sha256(pkt[1] + PASS)), 0)
  pkt = recv_msg(sock)
  raise "auth1 failed: #{pkt}" unless pkt && pkt[0] == 0x03 && pkt[1].getbyte(0) == 1
  c2 = "c#{rand(999_999)}"
  sock.send(msg(0x01, c2), 0)
  pkt = recv_msg(sock)
  raise "no auth2 challenge: #{pkt}" unless pkt && pkt[0] == 0x02
  raise "auth2 challenge mismatch" unless pkt[1] == sha256(c2 + PASS)
  sock.send(msg(0x03, "\x01"), 0)
end

def send_control(sock, type, payload = +'')
  payload = payload.dup.force_encoding('BINARY') unless payload.encoding == Encoding::BINARY
  inner = write_varint(type) + write_varint(payload.bytesize) + payload
  frame = write_varint(1 + inner.bytesize) + "\x05" + inner
  sock.send(frame, 0)
end

def recv_control(sock, timeout = 10)
  Timeout.timeout(timeout) do
    flen = read_varint(sock)
    return nil if flen.nil?
    wire_type = sock.recv(1)
    return nil if wire_type.nil? || wire_type.getbyte(0) != 5
    t = read_varint(sock)
    sz = read_varint(sock)
    p = +''
    while p.bytesize < sz
      chunk = sock.recv([sz - p.bytesize, 65536].min)
      p << chunk
    end
    [t, p]
  end
rescue Timeout::Error
  nil
end

def send_wire_data(sock, conn_id, data)
  payload = conn_id.chr + data
  len = write_varint(1 + payload.bytesize)
  sock.send(len + "\x00" + payload, 0)
end

def recv_wire_data(sock, timeout = 10)
  Timeout.timeout(timeout) do
    flen = read_varint(sock)
    return nil if flen.nil?
    type = sock.recv(1)
    return nil if type.nil? || type.getbyte(0) != 0
    conn_id_byte = sock.recv(1)
    conn_id = conn_id_byte.getbyte(0)
    payload_len = flen - 2
    data = +''
    while data.bytesize < payload_len
      chunk = sock.recv([payload_len - data.bytesize, 65536].min)
      data << chunk
    end
    [conn_id, data]
  end
rescue Timeout::Error
  nil
end

def find_free_port(low = 30000, high = 34000)
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
  raise "port #{port} not ready"
end

SERVER = '/tmp/module_tunnel_build/server/ppltunnel-server'
MPATH = '/sharedata/work/github/module_tunnel/application/tests/test_modules'

# Start echo server on a port
echo_port = find_free_port
echo_ls = TCPServer.new('127.0.0.1', echo_port)
echo_thr = Thread.new do
  loop do
    c = echo_ls.accept rescue break
    Thread.new(c) do |conn|
      while (d = conn.recv(65536))
        break if d.empty?
        $stderr.puts "ECHO received #{d.bytesize} bytes"
        conn.send(d, 0)
      end
      conn.close rescue nil
    end
  end
end
sleep 0.2

svr_port = find_free_port
svr = Process.spawn(SERVER, "-l127.0.0.1:#{svr_port}", "-A#{PASS}",
                    "-M#{MPATH}", %i[out err] => File::NULL)
wait_port_listen(svr_port)

sock = Socket.new(:INET, :STREAM)
sock.connect(Addrinfo.tcp('127.0.0.1', svr_port))
$stderr.puts "Connected"

auth(sock)
$stderr.puts "Auth done"

send_control(sock, 0x10, "\x00")
r = recv_control(sock)
$stderr.puts "MODULE_LIST_RES: #{r.inspect}"

send_control(sock, 0x20, "\x00")
r = recv_control(sock)
$stderr.puts "First response: #{r.inspect}"
r = recv_control(sock)
$stderr.puts "Second response: #{r.inspect}"
sid = r[1][1..8].unpack1('Q<') rescue nil
r = recv_control(sock)
$stderr.puts "Third response: #{r.inspect}"
$stderr.puts "Chain created, sid=#{sid}"

addr = "127.0.0.1:#{echo_port}"
payload = [addr.bytesize, addr].pack('CA*')
send_control(sock, 0x30, payload)
r = recv_control(sock)
$stderr.puts "CONNECT_RES: #{r.inspect}"
conn_id = r[1].getbyte(0)
$stderr.puts "conn_id=#{conn_id}"

sleep 1

test_data = "HELLO_ECHO_TEST"
send_wire_data(sock, conn_id, test_data)
$stderr.puts "Sent wire data, waiting for echo..."

r = recv_wire_data(sock)
$stderr.puts "Echo response: #{r.inspect}"

if r && r[1] == test_data
  puts "ECHO TEST PASSED"
else
  puts "ECHO TEST FAILED"
end

sock.close
echo_ls.close rescue nil
echo_thr.kill rescue nil
Process.kill('TERM', svr) rescue nil
Process.wait(svr) rescue nil
