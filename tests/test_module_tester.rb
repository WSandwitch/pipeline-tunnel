#!/usr/bin/env ruby
# frozen_string_literal: true

$stdout.sync = true

require 'optparse'
require 'socket'
require 'securerandom'
require 'timeout'
require 'tempfile'

HOST = '127.0.0.1'
PASS = 'testpass'
DEFAULT_SIZES = [100, 1000, 10_000, 65_536]

options = {
  build_dir: nil,
  mod_dir: nil,
  config: nil,
  quiet: false,
  sizes: DEFAULT_SIZES,
}

op = OptionParser.new do |o|
  o.banner = "Usage: #{$PROGRAM_NAME} -S <build_dir> -M <mod_dir> [options] [sizes...]"
  o.on('-S', '--server-dir DIR', 'Path to build dir') { |v| options[:build_dir] = v }
  o.on('-M', '--module-dir DIR', 'Path to .so modules dir') { |v| options[:mod_dir] = v }
  o.on('-C', '--config CONFIG', 'Test specific module config (default: all)') { |v| options[:config] = v }
  o.on('-q', '--quiet', 'Suppress output') { options[:quiet] = true }
end
rest = op.parse(ARGV)
options[:sizes] = rest.map(&:to_i) unless rest.empty?

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

def log(s)
  puts s unless $options[:quiet]
end

def discover_modules
  r = IO.popen([SERVER, '--module-list', "-M#{MPATH}"], err: [:child, :out], &:read)
  r.each_line.filter_map { |l| l.strip.split[0] if l.start_with?('  ') }
end

def find_free_port(low = 31_000, high = 34_000)
  50.times do
    port = rand(low..high)
    begin
      s = Socket.new(:INET, :STREAM)
      s.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
      s.bind(Addrinfo.tcp('0.0.0.0', port))
      s.close
      return port
    rescue Errno::EADDRINUSE
    end
  end
  raise 'no free port'
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

def test_module_roundtrip(config_str, size)
  tgt_port = find_free_port
  svr_port = find_free_port
  cli_port = find_free_port

  svr_log = Tempfile.new(%w[ppltunnel-server- .log])
  svr = Process.spawn(SERVER, "-l#{HOST}:#{svr_port}", "-A#{PASS}",
                      "-M#{MPATH}", '-H60',
                      out: svr_log, err: [:child, :out])
  alive_check(svr, 'ppltunnel-server', svr_log)
  wait_port_or_die(svr, svr_port, svr_log)

  cli_log = Tempfile.new(%w[ppltunnel-client- .log])
  cli = Process.spawn(CLIENT, "-L#{HOST}:#{cli_port}:#{HOST}:#{tgt_port}",
                      "-M#{MPATH}", '-H60',
                      "#{HOST}:#{svr_port},#{PASS};#{config_str}",
                      out: cli_log, err: [:child, :out])
  alive_check(cli, 'ppltunnel-client', cli_log)
  wait_port_or_die(cli, cli_port, cli_log)

  data = SecureRandom.random_bytes(size)

  ls = Socket.new(:INET, :STREAM)
  ls.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 1)
  ls.bind(Addrinfo.tcp(HOST, tgt_port))
  ls.listen(1)

  cconn = Socket.new(:INET, :STREAM)
  cconn.connect(Addrinfo.tcp(HOST, cli_port))

  tconn, = ls.accept
  ls.close

  # Send through tunnel
  cconn.send(data, 0)

  # Receive on target side
  total = +''
  while total.bytesize < data.bytesize
    d = tconn.recv(65536)
    break if d.empty?
    total << d
  end

  cconn.close
  tconn.close

  [cli, svr].each do |pid|
    Process.kill('TERM', pid) rescue nil
  end
  Timeout.timeout(3) do
    [cli, svr].each { |pid| Process.wait(pid) rescue nil }
  end
rescue Timeout::Error
  [cli, svr].each { |pid| Process.kill('KILL', pid) rescue nil }
rescue => e
  [cli, svr].each { |pid| Process.kill('KILL', pid) rescue nil } rescue nil
  raise e
end

$options = options

unless SERVER && CLIENT && MPATH
  puts op.help
  exit 1
end

all_ok = true

# 1. Test module list
begin
  mods = discover_modules
  log "Modules: #{mods.join(', ')}"
  if mods.empty?
    log "FAIL: no modules discovered"
    all_ok = false
  end
rescue => e
  log "FAIL: module discovery error: #{e}"
  all_ok = false
end

# 2. Filter modules
if options[:config]
  test_modules = options[:config].split(',').map(&:strip)
else
  test_modules = mods
end

# 3. Round-trip test per module
test_modules.each do |mod_name|
  mods = discover_modules
  unless mods.include?(mod_name)
    log "FAIL: module '#{mod_name}' not in discovered list"
    all_ok = false
    next
  end

  options[:sizes].each do |size|
    begin
      ok = test_module_roundtrip(mod_name, size)
      log "  #{mod_name} size=#{size}: #{ok ? 'PASS' : 'FAIL'}"
      all_ok = false unless ok
    rescue => e
      log "  #{mod_name} size=#{size}: FAIL (#{e})"
      all_ok = false
    end
  end
end

# 4. Test invalid module
begin
  svr_port = find_free_port
  svr_log = Tempfile.new(%w[ppltunnel-server- .log])
  svr = Process.spawn(SERVER, "-l#{HOST}:#{svr_port}", "-A#{PASS}",
                      "-M#{MPATH}", out: svr_log, err: [:child, :out])
  wait_port_listen(svr_port)
  Process.kill('TERM', svr) rescue nil
  Process.wait(svr) rescue nil

  cli_port = find_free_port
  cli_log = Tempfile.new(%w[ppltunnel-client- .log])
  cli = Process.spawn(CLIENT, "-L#{HOST}:#{cli_port}:#{HOST}:31000",
                      "-M#{MPATH}",
                      "#{HOST}:#{svr_port},#{PASS};nonexistent_module",
                      out: cli_log, err: [:child, :out])
  Process.wait(cli)
  if $?.exitstatus != 0
    log "  invalid_module: PASS (exit=#{$?.exitstatus})"
  else
    log "  invalid_module: FAIL (should have exited non-zero)"
    all_ok = false
  end
rescue => e
  log "  invalid_module: FAIL (#{e})"
  all_ok = false
end

killall
exit all_ok ? 0 : 1
