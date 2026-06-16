#!/usr/bin/env ruby
# frozen_string_literal: true

$stdout.sync = true
$stderr.sync = true

require 'optparse'
require 'socket'
require 'securerandom'
require 'tempfile'
require 'timeout'
require 'fileutils'

HOST = '127.0.0.1'
PASS = 'testpass'

SHORT_COUNT = Integer(ENV.fetch('INTEGRATION_SHORT', '50'))
LONG_COUNT = Integer(ENV.fetch('INTEGRATION_LONG', '3'))
LONG_SIZE = Integer(ENV.fetch('INTEGRATION_LONG_SIZE', '262144'))
BIDI_SIZE = Integer(ENV.fetch('INTEGRATION_BIDI_SIZE', '262144'))
BLOCKING_SIZE = Integer(ENV.fetch('INTEGRATION_BLOCKING_SIZE', '2097152'))
BLOCKING_CHUNK = Integer(ENV.fetch('INTEGRATION_BLOCKING_CHUNK', '131072'))
TEST_TIMEOUT = Integer(ENV.fetch('INTEGRATION_TIMEOUT', '120'))
TUNNEL_MIN_PCT = Integer(ENV.fetch('INTEGRATION_MIN_PCT', '90'))

options = {
  build_dir: nil,
  mod_dir: nil,
  config: nil,
  client_threads: 1,
  server_threads: 1,
  quiet: false,
  verbose: false,
  test_types: %w[short long blocking bidi blocking_bidi],
}

op = OptionParser.new do |o|
  o.banner = "Usage: #{$PROGRAM_NAME} -S <build_dir> -M <mod_dir> -C <config> [options] [test_types...]"
  o.on('-S', '--server-dir DIR', 'Path to build dir') { |v| options[:build_dir] = v }
  o.on('-M', '--module-dir DIR', 'Path to .so modules dir') { |v| options[:mod_dir] = v }
  o.on('-C', '--config CONFIG', 'Chain config string') { |v| options[:config] = v }
  o.on('-c', '--client-threads N', Integer, 'Client worker thread count') { |v| options[:client_threads] = v }
  o.on('-s', '--server-threads N', Integer, 'Server worker thread count') { |v| options[:server_threads] = v }
  o.on('-q', '--quiet', 'Suppress output') { options[:quiet] = true }
  o.on('-v', '--verbose', 'Print commands before execution') { options[:verbose] = true }
end
rest = op.parse(ARGV)
options[:test_types] = rest unless rest.empty?

def find_bin(dir, name)
  candidates = [
    File.join(dir, name),
    File.join(dir, 'server', name),
    File.join(dir, 'client', name),
  ]
  candidates.find { |f| File.exist?(f) }
end

SERVER = options[:build_dir] ? find_bin(options[:build_dir], 'ppltunnel-server') : nil
CLIENT = options[:build_dir] ? find_bin(options[:build_dir], 'ppltunnel-client') : nil
MPATH = options[:mod_dir]

unless SERVER && CLIENT && MPATH && options[:config]
  puts op.help
  exit 1
end

def log(s)
  $stderr.puts s unless $options[:quiet]
end
$options = options

# ---- helpers ----

def find_free_port(low = 31_000, high = 34_000)
  50.times do
    port = rand(low..high)
    begin
      s = Socket.new(:INET, :STREAM)
      s.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
      s.bind(Addrinfo.tcp('0.0.0.0', port))
      s.close
      return port
    rescue Errno::EADDRINUSE, Errno::EACCES
      next
    end
  end
  raise 'no free port found'
end

def read_log(f)
  return '' unless f
  f.rewind
  f.read
end

def alive_check(pid, name, log = nil)
  _, status = Process.waitpid2(pid, Process::WNOHANG)
  return unless status
  err = read_log(log)
  msg = "#{name} (pid #{pid}) died immediately: #{status.inspect}"
  msg += "\n#{err}" unless err.empty?
  raise msg
end

def wait_port_or_die(pid, port, log, timeout = 10)
  deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
  while Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
    _, status = Process.waitpid2(pid, Process::WNOHANG)
    if status
      err = read_log(log)
      raise "Process died before listening:\n#{err.empty? ? '(no output)' : err}"
    end
    out = `ss -tln sport = #{port} 2>/dev/null`
    if out.include?("127.0.0.1:#{port}") || out.include?("0.0.0.0:#{port}")
      return
    end
    sleep 0.05
  end
  _, status = Process.waitpid2(pid, Process::WNOHANG)
  extra = status ? "(died: #{status.inspect})" : "(still running, port #{port} not listening)"
  err = read_log(log)
  msg = "port #{port} not ready after #{timeout}s #{extra}"
  msg += "\n#{err}" unless err.empty?
  raise msg
end

def killall
  system('killall', '-9', 'ppltunnel-server', 'ppltunnel-client', %i[out err] => File::NULL)
end

def server_thread_args
  n = $options[:server_threads]
  ['-t', n.to_s]
end

def client_thread_args
  n = $options[:client_threads]
  ['-t', n.to_s]
end

def start_tunnel(svr_port, cli_port, tgt_port)
  svr_log = Tempfile.new(%w[ppltunnel-server- .log])
  cli_log = Tempfile.new(%w[ppltunnel-client- .log])

  svr_argv = [SERVER, "-l#{HOST}:#{svr_port}", "-A#{PASS}",
              "-M#{MPATH}", '-H60', *server_thread_args]
  if $options[:verbose]
    $stderr.puts "  + #{svr_argv.map { |a| a.include?(' ') ? "'#{a}'" : a }.join(' ')} 2>&1 | tee #{svr_log.path}"
  end
  svr = Process.spawn(*svr_argv, out: svr_log, err: [:child, :out])
  alive_check(svr, 'ppltunnel-server', svr_log)
  wait_port_or_die(svr, svr_port, svr_log)

  chain = if $options[:config]&.start_with?(';')
             $options[:config]
           else
             $options[:config] ? ";#{$options[:config]}" : ''
           end
  cli_argv = [CLIENT, "-L#{HOST}:#{cli_port}:#{HOST}:#{tgt_port}",
              "-M#{MPATH}", '-H60',
              "#{HOST}:#{svr_port},#{PASS}#{chain}",
              *client_thread_args]
  if $options[:verbose]
    $stderr.puts "  + #{cli_argv.map { |a| a.include?(' ') ? "'#{a}'" : a }.join(' ')} 2>&1 | tee #{cli_log.path}"
  end
  cli = Process.spawn(*cli_argv, out: cli_log, err: [:child, :out])
  alive_check(cli, 'ppltunnel-client', cli_log)
  wait_port_or_die(cli, cli_port, cli_log)
  [svr, cli, svr_log, cli_log]
end

def stop_procs(*pids)
  pids.compact.each { |pid| Process.kill('TERM', pid) rescue nil }
  Timeout.timeout(3) do
    pids.compact.each { |pid| Process.wait(pid) rescue nil }
  end
rescue Timeout::Error
  pids.compact.each { |pid| Process.kill('KILL', pid) rescue nil }
end

def with_tunnel(tgt_port)
  svr_port = find_free_port(32_001, 33_000)
  cli_port = find_free_port(33_001, 34_000)
  svr_log = cli_log = nil
  begin
    svr, cli, svr_log, cli_log = start_tunnel(svr_port, cli_port, tgt_port)
    yield cli_port
  rescue => e
    [svr_log, cli_log].compact.each do |f|
      f.rewind
      data = f.read
      unless data.empty?
        log "  # #{File.basename(f.path)}:\n#{data.each_line.map { |l| "  # #{l}" }.join}"
      end
    end
    raise
  ensure
    stop_procs(cli, svr)
    [svr_log, cli_log].compact.each { |f| f.close rescue nil }
    killall
  end
end

def start_echo_server(port)
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
  sleep 0.1
  [ls, thr]
end

# ---- test implementations ----

def short_http(port, count)
  ok = 0
  count.times do |i|
    s = Socket.new(:INET, :STREAM)
    begin
      s.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVTIMEO, [5, 0].pack('l_2'))
      s.connect(Addrinfo.tcp(HOST, port))
      s.send("GET / HTTP/1.0\r\nHost: x\r\n\r\n", 0)
      resp = +''
      loop do
        d = s.recv(65536) rescue break
        break if d.empty?
        resp << d
      end
      ok += 1 if resp.include?('200 OK') || resp.include?('200 ok')
    rescue
    end
    s.close
  end
  ok
end

def long_echo(port, count, size)
  ok = 0
  count.times do
    data = SecureRandom.random_bytes(size)
    s = Socket.new(:INET, :STREAM)
    begin
      s.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVTIMEO, [30, 0].pack('l_2'))
      s.connect(Addrinfo.tcp(HOST, port))
      s.send(data, 0)
      total = +''
      while total.bytesize < data.bytesize
        d = s.recv(65536) rescue break
        break if d.empty?
        total << d
      end
      ok += 1 if total == data
    rescue
    end
    s.close
  end
  ok
end

def blocking_echo(port)
  data = SecureRandom.random_bytes(BLOCKING_SIZE)
  s = Socket.new(:INET, :STREAM)
  begin
    s.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVTIMEO, [30, 0].pack('l_2'))
    s.connect(Addrinfo.tcp(HOST, port))
    # Send all data using blocking writes in chunks
    off = 0
    while off < data.bytesize
      n = s.send(data.byteslice(off, BLOCKING_CHUNK), 0)
      off += n
    end
    # Read all echo back
    total = +''
    while total.bytesize < data.bytesize
      d = s.recv(BLOCKING_CHUNK)
      break if d.empty?
      total << d
    end
    return total == data
  rescue
    return false
  ensure
    s.close
  end
end

def bidi_once(port, tgt_port, size)
  client_data = SecureRandom.random_bytes(size)
  server_data = SecureRandom.random_bytes(size)

  ls = Socket.new(:INET, :STREAM)
  ls.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
  ls.bind(Addrinfo.tcp(HOST, tgt_port))
  ls.listen(1)

  cconn = Socket.new(:INET, :STREAM)
  begin
    cconn.connect(Addrinfo.tcp(HOST, port))
  rescue
    ls.close; cconn.close; return 0
  end

  begin
    tconn, = ls.accept
  rescue
    ls.close; cconn.close; return 0
  end
  ls.close

  results = {}
  threads = [
    Thread.new { cconn.send(client_data, 0) rescue nil },
    Thread.new { d = recv_exact(tconn, client_data.bytesize); results[:tr] = d if d.bytesize == client_data.bytesize },
    Thread.new { tconn.send(server_data, 0) rescue nil },
    Thread.new { d = recv_exact(cconn, server_data.bytesize); results[:cr] = d if d.bytesize == server_data.bytesize },
  ]
  threads.each(&:join)

  cconn.close; tconn.close
  (results[:tr] == client_data && results[:cr] == server_data) ? 1 : 0
end

def recv_exact(sock, size)
  buf = +''
  while buf.bytesize < size
    d = sock.recv(size - buf.bytesize)
    break if d.empty?
    buf << d
  end
  buf
end

def blocking_bidi_once(cli_port)
  data0 = SecureRandom.random_bytes(BLOCKING_SIZE)
  data1 = SecureRandom.random_bytes(BLOCKING_SIZE)

  results = {}
  s0 = Socket.new(:INET, :STREAM)
  s0.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVTIMEO, [30, 0].pack('l_2'))
  s0.connect(Addrinfo.tcp(HOST, cli_port))
  s1 = Socket.new(:INET, :STREAM)
  s1.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVTIMEO, [30, 0].pack('l_2'))
  s1.connect(Addrinfo.tcp(HOST, cli_port))

  t0 = Thread.new { results[:a] = blocking_bidi_worker(s0, data0) }
  t1 = Thread.new { results[:b] = blocking_bidi_worker(s1, data1) }
  [t0, t1].each(&:join)
  s0.close; s1.close
  results[:a] && results[:b]
end

def blocking_bidi_worker(sock, data)
  off = 0
  while off < data.bytesize
    n = sock.send(data.byteslice(off, BLOCKING_CHUNK), 0)
    off += n
  end
  total = +''
  while total.bytesize < data.bytesize
    d = sock.recv(BLOCKING_CHUNK)
    return false if d.empty?
    total << d
  end
  total == data
rescue
  false
end

# ---- test types ----

tests = {
  'short' => proc do
    tgt = find_free_port
    httpd_dir = Dir.mktmpdir
    httpd = Process.spawn('python3', '-m', 'http.server', tgt.to_s,
                          '-d', httpd_dir, %i[out err] => File::NULL)
    wait_port_listen(tgt)
    with_tunnel(tgt) do |cli_port|
      ok = short_http(cli_port, SHORT_COUNT)
      pct = ok * 100 / [SHORT_COUNT, 1].max
      log "  short=#{ok}/#{SHORT_COUNT} (#{pct}%)"
      next pct >= TUNNEL_MIN_PCT
    end
  ensure
    stop_procs(httpd) if httpd
    FileUtils.rm_rf(httpd_dir) if httpd_dir
  end,

  'long' => proc do
    tgt = find_free_port
    ls, thr = start_echo_server(tgt)
    with_tunnel(tgt) do |cli_port|
      ok = long_echo(cli_port, LONG_COUNT, LONG_SIZE)
      pct = ok * 100 / [LONG_COUNT, 1].max
      log "  long=#{ok}/#{LONG_COUNT} (#{pct}%)"
      next pct >= TUNNEL_MIN_PCT
    end
  ensure
    ls.close rescue nil; thr.kill rescue nil
  end,

  'blocking' => proc do
    tgt = find_free_port
    ls, thr = start_echo_server(tgt)
    with_tunnel(tgt) do |cli_port|
      ok = blocking_echo(cli_port)
      log "  blocking=#{ok ? 'OK' : 'FAIL'}"
      next ok
    end
  ensure
    ls.close rescue nil; thr.kill rescue nil
  end,

  'bidi' => proc do
    tgt = find_free_port
    ok_count = 0
    LONG_COUNT.times do |i|
      # Each bidi iteration creates its own connect/accept pair through the tunnel
      with_tunnel(tgt) do |cli_port|
        result = bidi_once(cli_port, tgt, BIDI_SIZE)
        ok_count += result
        log "  bidi iter #{i}: #{result > 0 ? 'OK' : 'FAIL'}"
      end
    end
    pct = ok_count * 100 / [LONG_COUNT, 1].max
    log "  bidi=#{ok_count}/#{LONG_COUNT} (#{pct}%)"
    next pct >= TUNNEL_MIN_PCT
  end,

  'blocking_bidi' => proc do
    tgt = find_free_port
    ls, thr = start_echo_server(tgt)
    with_tunnel(tgt) do |cli_port|
      ok = blocking_bidi_once(cli_port)
      log "  blocking_bidi=#{ok ? 'OK' : 'FAIL'}"
      next ok
    end
  ensure
    ls.close rescue nil; thr.kill rescue nil
  end,
}

# ---- main ----

all_ok = true
options[:test_types].each do |name|
  fn = tests[name]
  unless fn
    log "Unknown test type: #{name}"
    all_ok = false
    next
  end
  begin
    ok = fn.call
    all_ok = false unless ok
  rescue => e
    log "  #{name} exception: #{e}"
    all_ok = false
  end
end

killall
exit all_ok ? 0 : 1
