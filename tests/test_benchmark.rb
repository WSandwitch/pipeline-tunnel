#!/usr/bin/env ruby
# frozen_string_literal: true

$stdout.sync = true
$stderr.sync = true

require 'optparse'
require 'socket'
require 'timeout'

HOST = '127.0.0.1'
PASS = 'testpass'

options = {
  build_dir: nil,
  mod_dir: nil,
  config: nil,
  threads: 1,
  duration: 30,
  direction: 'forward',
  parallel: 1,
  clients: 1,
  quiet: false,
  verbose: false,
}

op = OptionParser.new do |o|
  o.banner = "Usage: #{$PROGRAM_NAME} -S <build_dir> -M <mod_dir> -C <config> [options]"
  o.on('-S', '--server-dir DIR', 'Path to build dir') { |v| options[:build_dir] = v }
  o.on('-M', '--module-dir DIR', 'Path to .so modules dir') { |v| options[:mod_dir] = v }
  o.on('-C', '--config CONFIG', 'Chain config string') { |v| options[:config] = v }
  o.on('-t', '--threads N', Integer, 'Worker thread count (0=auto)') { |v| options[:threads] = v }
  o.on('-d N', '--duration N', Integer, 'Test duration in seconds') { |v| options[:duration] = v }
  o.on('--direction DIR', %w[forward reverse bidir], "forward|reverse|bidir") { |v| options[:direction] = v }
  o.on('-P', '--parallel N', Integer, 'iperf3 parallel streams') { |v| options[:parallel] = v }
  o.on('-n', '--clients N', Integer, 'Concurrent iperf3 processes') { |v| options[:clients] = v }
  o.on('-q', '--quiet', 'Suppress iperf3 output') { options[:quiet] = true }
  o.on('-v', '--verbose', 'Show output from all spawned processes') { options[:verbose] = true }
end
def find_bin(dir, name)
  [File.join(dir, name), File.join(dir, 'server', name), File.join(dir, 'client', name)].find { |f| File.exist?(f) }
end

op.parse(ARGV)

SERVER = options[:build_dir] ? find_bin(options[:build_dir], 'ppltunnel-server') : nil
CLIENT = options[:build_dir] ? find_bin(options[:build_dir], 'ppltunnel-client') : nil
MPATH = options[:mod_dir]

unless SERVER && CLIENT && MPATH && options[:config]
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
  raise 'no free port found'
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

def null_redirect
  $options[:verbose] ? STDERR : File::NULL
end

def spawn_verbosely(*args)
  $stderr.puts "  + #{args.map { |a| a.to_s.include?(' ') ? "'#{a}'" : a }.join(' ')}" if $options[:verbose]
  Process.spawn(*args)
end

def killall
  system('killall', '-9', 'ppltunnel-server', 'ppltunnel-client', 'iperf3', %i[out err] => File::NULL)
end

def thread_args(n)
  n == 0 ? ['-t'] : ['-t', n.to_s]
end

def start_tunnel(svr_port, cli_port, tgt_port)
  redir = null_redirect
  svr = spawn_verbosely(SERVER, "-l#{HOST}:#{svr_port}", "-A#{PASS}",
                        "-M#{MPATH}", *thread_args($options[:threads]),
                        %i[out err] => redir)
  wait_port_listen(svr_port)
  chain = ";#{$options[:config]}"
  cli = spawn_verbosely(CLIENT, "-L#{HOST}:#{cli_port}:#{HOST}:#{tgt_port}",
                        "-M#{MPATH}",
                        "#{HOST}:#{svr_port},#{PASS}#{chain}",
                        *thread_args($options[:threads]),
                        %i[out err] => redir)
  wait_port_listen(cli_port)
  [svr, cli]
end

def stop_procs(*pids)
  pids.compact.each { |pid| Process.kill('TERM', pid) rescue nil }
  Timeout.timeout(3) { pids.compact.each { |pid| Process.wait(pid) rescue nil } }
rescue Timeout::Error
  pids.compact.each { |pid| Process.kill('KILL', pid) rescue nil }
end

def parse_iperf_bitrate(output)
  rates = []
  output.each_line do |line|
    next unless line =~ /(\d+\.?\d*)\s*(G|M|K)bits\/sec/
    val = Regexp.last_match(1).to_f
    unit = Regexp.last_match(2)
    case unit
    when 'G' then val *= 1000
    when 'K' then val /= 1000
    end
    rates << val
  end
  rates
end

$options = options

# ---- main ----

all_rates = []
all_outputs = []

servers = []
tunnels = []

begin
  killall
  options[:clients].times do |i|
    tgt = find_free_port
    redir = null_redirect
    iperf_pid = spawn_verbosely('iperf3', '-s', '-D', '-p', tgt.to_s,
                                %i[out err] => redir)
    wait_port_listen(tgt)
    servers << { tgt_port: tgt, pid: iperf_pid }

    svr_port = find_free_port
    cli_port = find_free_port
    svr, cli = start_tunnel(svr_port, cli_port, tgt)
    tunnels << { cli_port: cli_port, svr_pid: svr, cli_pid: cli }
  end

  $stderr.puts "[#{options[:config]}] Starting #{options[:direction]} " \
       "(#{options[:clients]} clients, P=#{options[:parallel]}, #{options[:duration]}s)..."

  mutex = Mutex.new
  thread_results = []
  thread_errors = []
  threads = tunnels.map.with_index do |t, i|
    Thread.new do
      port = t[:cli_port]
      args = ['iperf3', '-c', HOST, '-p', port.to_s,
              '-t', options[:duration].to_s, '-P', options[:parallel].to_s]
      case options[:direction]
      when 'reverse' then args << '-R'
      when 'bidir' then args << '--bidir'
      end
      mutex.synchronize { $stderr.puts "  client #{i + 1} starting on port #{port}..." }
      lines = []
      begin
        IO.popen(args, err: [:child, :out]) do |io|
          io.each_line do |line|
            lines << line
            mutex.synchronize { $stderr.print "  [#{i + 1}] #{line}" unless options[:quiet] }
          end
        end
        output = lines.join
        rates = parse_iperf_bitrate(output)
        mutex.synchronize { thread_results << { output: output, rates: rates } }
      rescue => e
        mutex.synchronize { thread_errors << e }
      end
      mutex.synchronize { $stderr.puts "  client #{i + 1} done." }
    end
  end

  test_timeout = [(options[:duration] || 30) + 10, 15].max
  timed_out = false
  begin
    Timeout.timeout(test_timeout) { threads.each(&:join) }
  rescue Timeout::Error
    timed_out = true
    $stderr.puts "  TIMEOUT after #{test_timeout}s, cleaning up..."
    tunnels.each { |t| stop_procs(t[:cli_pid], t[:svr_pid]) }
    killall
    threads.each(&:join)
  end

  unless thread_errors.empty?
    $stderr.puts "  WARNING: #{thread_errors.length} thread(s) raised errors"
  end

  results = thread_results
  results.each do |r|
    all_outputs << r[:output]
    all_rates.concat(r[:rates])
  end

  max_rate = all_rates.max || 0
  total_rate = all_rates.sum
  avg_rate = all_rates.empty? ? 0 : total_rate / all_rates.length
  ok = max_rate > 0 && !timed_out

  dir_label = options[:direction]
  puts "-" * 40
  puts "[#{options[:config]}] #{dir_label}: #{'%.0f' % max_rate} Mbps peak, #{'%.0f' % avg_rate} Mbps avg" \
       "  (#{options[:clients]} clients, P=#{options[:parallel]}, t=#{options[:duration]})"
  puts ok ? 'PASS' : 'FAIL'
ensure
  tunnels.each { |t| stop_procs(t[:cli_pid], t[:svr_pid]) }
  killall
end

exit 0
