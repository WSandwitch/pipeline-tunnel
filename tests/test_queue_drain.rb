#!/usr/bin/env ruby
# frozen_string_literal: true

$stdout.sync = true

# Tests queue drain / crash recovery:
# - Client disconnected while data in flight
# - Under load, tunnel client killed mid-stream
# - Server must survive and clean up

require 'optparse'
require 'socket'
require 'timeout'

HOST = '127.0.0.1'
PASS = 'testpass'

options = {
  build_dir: nil,
  mod_dir: nil,
  config: 'copy',
  threads: 1,
  count: 5,
}

op = OptionParser.new do |o|
  o.banner = "Usage: #{$PROGRAM_NAME} -S <build_dir> -M <mod_dir> -C <config> [options]"
  o.on('-S', '--server-dir DIR', 'Build dir') { |v| options[:build_dir] = v }
  o.on('-M', '--module-dir DIR', 'Module .so dir') { |v| options[:mod_dir] = v }
  o.on('-C', '--config CONFIG', 'Chain config') { |v| options[:config] = v }
  o.on('-t', '--threads N', Integer, 'Worker threads') { |v| options[:threads] = v }
  o.on('-n', '--count N', Integer, 'Iterations') { |v| options[:count] = v }
def find_bin(dir, name)
  [File.join(dir, name), File.join(dir, 'server', name), File.join(dir, 'client', name)].find { |f| File.exist?(f) }
end

op.parse(ARGV)

SERVER = options[:build_dir] ? find_bin(options[:build_dir], 'ppltunnel-server') : nil
CLIENT = options[:build_dir] ? find_bin(options[:build_dir], 'ppltunnel-client') : nil
MPATH = options[:mod_dir]
unless SERVER && CLIENT && MPATH
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
  system('killall', '-9', 'ppltunnel-server', 'ppltunnel-client', %i[out err] => File::NULL)
end

def thread_args(n)
  n == 0 ? ['-t'] : ['-t', n.to_s]
end

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
  sleep 0.1
  [ls, thr]
end

$options = options

# ---- Main ----

success = 0
failure = 0

options[:count].times do |i|
  svr = nil
  cli = nil
  echo_ls = nil
  echo_thr = nil
  ok = false
  begin
    tgt = find_free_port
    echo_ls, echo_thr = start_echo(tgt)

    svr_port = find_free_port
    cli_port = find_free_port

    svr = Process.spawn(SERVER, "-l#{HOST}:#{svr_port}", "-A#{PASS}",
                        "-M#{MPATH}", *thread_args($options[:threads]),
                        %i[out err] => File::NULL)
    wait_port_listen(svr_port)

    chain = ";#{$options[:config]}"
    cli = Process.spawn(CLIENT, "-L#{HOST}:#{cli_port}:#{HOST}:#{tgt}",
                        "-M#{MPATH}",
                        "#{HOST}:#{svr_port},#{PASS}#{chain}",
                        *thread_args($options[:threads]),
                        %i[out err] => File::NULL)
    wait_port_listen(cli_port)

    # Send data through tunnel — start a sender thread
    data = 'Z' * 2_000_000
    sender = Thread.new do
      begin
        s = Socket.new(:INET, :STREAM)
        s.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVTIMEO, [5, 0].pack('l_2'))
        s.connect(Addrinfo.tcp(HOST, cli_port))
        s.send(data, 0)
        s.close
      rescue
      end
    end

    # Also start a receiver
    receiver = Thread.new do
      begin
        s = Socket.new(:INET, :STREAM)
        s.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVTIMEO, [5, 0].pack('l_2'))
        s.connect(Addrinfo.tcp(HOST, cli_port))
        total = +''
        while (d = s.recv(65536))
          break if d.empty?
          total << d
        end
        s.close
        total
      rescue
        +''
      end
    end

    sleep 0.3

    # Kill the client tunnel process while data is in flight
    if cli
      Process.kill('KILL', cli) rescue nil
      Process.wait(cli) rescue nil
      cli = nil
    end

    # Wait briefly, then check server still alive
    sleep 0.5

    # Check if server is still running
    svr_alive = false
    begin
      svr_alive = (Process.waitpid2(svr, Process::WNOHANG) rescue nil).nil?
    rescue
    end

    if svr_alive
      success += 1
      ok = true
    else
      failure += 1
      puts "  iter #{i}: SERVER DIED"
    end

    sender.kill rescue nil
    receiver.kill rescue nil
  rescue => e
    failure += 1
    puts "  iter #{i}: #{e}"
  ensure
    echo_ls.close rescue nil
    echo_thr.kill rescue nil
    [svr, cli].compact.each do |pid|
      Process.kill('KILL', pid) rescue nil
      Process.wait(pid) rescue nil
    end
    killall
  end
end

total = success + failure
puts "#{success}/#{total} passed"
exit success == total ? 0 : 1
