#!/usr/bin/env ruby
# frozen_string_literal: true

$stdout.sync = true
$stderr.sync = true
SAVED_LOGS = []
KEEP_LOGS = ENV['KEEP_LOGS'] == '1'
if KEEP_LOGS
  require 'fileutils'
  SAVE_DIR = File.join('/tmp', "saved_logs_#{Time.now.to_i}_#{rand(1000)}")
  FileUtils.mkdir_p(SAVE_DIR)
end

require 'optparse'
require 'socket'
require 'timeout'
require 'tempfile'
require 'fileutils'

HOST = '127.0.0.1'
PASS = 'testpass'

options = {
  build_dir: nil,
  mod_dir: nil,
  config: nil,
  client_threads: 1,
  server_threads: 1,
  duration: 30,
  direction: 'forward',
  parallel: 1,
  clients: 1,
  quiet: false,
  verbose: false,
  save_logs: false,
}

op = OptionParser.new do |o|
  o.banner = "Usage: #{$PROGRAM_NAME} -S <build_dir> -M <mod_dir> -C <config> [options]"
  o.on('-S', '--server-dir DIR', 'Path to build dir') { |v| options[:build_dir] = v }
  o.on('-M', '--module-dir DIR', 'Path to .so modules dir') { |v| options[:mod_dir] = v }
  o.on('-C', '--config CONFIG', 'Chain config string') { |v| options[:config] = v }
  o.on('-c', '--client-threads N', Integer, 'Client worker thread count') { |v| options[:client_threads] = v }
  o.on('-s', '--server-threads N', Integer, 'Server worker thread count') { |v| options[:server_threads] = v }
  o.on('-d N', '--duration N', Integer, 'Test duration in seconds') { |v| options[:duration] = v }
  o.on('--direction DIR', %w[forward reverse bidir], "forward|reverse|bidir") { |v| options[:direction] = v }
  o.on('-P', '--parallel N', Integer, 'iperf3 parallel streams') { |v| options[:parallel] = v }
  o.on('-n', '--clients N', Integer, 'Concurrent iperf3 processes') { |v| options[:clients] = v }
  o.on('-q', '--quiet', 'Suppress iperf3 output') { options[:quiet] = true }
  o.on('-v', '--verbose', 'Show output from all spawned processes') { options[:verbose] = true }
  o.on('--save-logs', 'Always save tunnel logs to /tmp/bidir_diag/') { options[:save_logs] = true }
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

# stdbuf forces line-buffered output from iperf3 even when stdout is a pipe
HAVE_STDBUF = system('which stdbuf >/dev/null 2>&1')

def iperf3_args(*a)
  HAVE_STDBUF ? ['stdbuf', '-oL', 'iperf3', *a] : ['iperf3', *a]
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

def spawn_verbosely(*args)
  $stderr.puts "  + #{args.map { |a| a.to_s.include?(' ') ? "'#{a}'" : a }.join(' ')}" if $options[:verbose]
  Process.spawn(*args)
end

def log_setup(msg)
  $stderr.puts "  #{msg}" unless $options[:quiet]
end

def killall
  system('killall', '-9', 'ppltunnel-server', 'ppltunnel-client', 'iperf3', %i[out err] => File::NULL)
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
    return if out.include?(":#{port}")
    sleep 0.05
  end
  _, status = Process.waitpid2(pid, Process::WNOHANG)
  extra = status ? "(died: #{status.inspect})" : "(still running, port #{port} not listening)"
  err = read_log(log)
  msg = "port #{port} not ready after #{timeout}s #{extra}"
  msg += "\n#{err}" unless err.empty?
  raise msg
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
  log_setup "start_tunnel: spawning server on #{svr_port}..."
  svr_log = Tempfile.new(%w[ppltunnel-server- .log])
  svr = spawn_verbosely(SERVER, "-l#{HOST}:#{svr_port}", "-A#{PASS}",
                        "-M#{MPATH}", '-H60',
                        *server_thread_args,
                        out: svr_log, err: [:child, :out])
  alive_check(svr, 'ppltunnel-server', svr_log)
  log_setup "start_tunnel: waiting for server port #{svr_port}..."
  wait_port_or_die(svr, svr_port, svr_log)
  log_setup "start_tunnel: server ready"

  chain = $options[:config]&.start_with?(';') ? $options[:config] : ";#{$options[:config]}"
  log_setup "start_tunnel: spawning client (chain='#{chain}')..."
  cli_log = Tempfile.new(%w[ppltunnel-client- .log])
  cli = spawn_verbosely(CLIENT, "-L#{HOST}:#{cli_port}:#{HOST}:#{tgt_port}",
                        "-M#{MPATH}", '-H60',
                        "#{HOST}:#{svr_port},#{PASS}#{chain}",
                        *client_thread_args,
                        out: cli_log, err: [:child, :out])
  alive_check(cli, 'ppltunnel-client', cli_log)
  log_setup "start_tunnel: waiting for client port #{cli_port}..."
  wait_port_or_die(cli, cli_port, cli_log)
  log_setup "start_tunnel: client ready"

  [svr, cli, svr_log, cli_log]
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

def run_one_test(options)
  all_rates = []
  all_outputs = []
  ok = false

  servers = []
  tunnels = []

  begin
    killall
    options[:clients].times do |i|
      begin
        log_setup "setup client #{i + 1}: finding ports..."
        tgt = find_free_port
        svr_port = find_free_port
        cli_port = find_free_port

        log_setup "setup client #{i + 1}: starting iperf3 server on #{tgt}..."
        iperf_log = Tempfile.new(%w[iperf3-server- .log])
        iperf_pid = spawn_verbosely('iperf3', '-s', '-D', '-p', tgt.to_s,
                                    out: iperf_log, err: [:child, :out])
        wait_port_listen(tgt)
        servers << { tgt_port: tgt, pid: iperf_pid, log: iperf_log }

        log_setup "setup client #{i + 1}: starting tunnel svr=#{svr_port} cli=#{cli_port} -> tgt=#{tgt}..."
        svr, cli, svr_log, cli_log = start_tunnel(svr_port, cli_port, tgt)
        log_setup "setup client #{i + 1}: tunnel ready (svr=#{svr} cli=#{cli})"
        tunnels << { cli_port: cli_port, svr_pid: svr, cli_pid: cli, svr_log: svr_log, cli_log: cli_log }
      rescue => e
        $stderr.puts "  SETUP ERROR (client #{i + 1}): #{e.message}"
        servers.each { |s| stop_procs(s[:pid]) }
        tunnels.each { |t| stop_procs(t[:cli_pid], t[:svr_pid]) }
        killall
        raise
      end
    end

    log_setup "[#{options[:config]}] Starting #{options[:direction]} " \
         "(#{options[:clients]} clients, P=#{options[:parallel]}, #{options[:duration]}s)..."

    mutex = Mutex.new
    thread_results = []
    thread_errors = []
    threads = tunnels.map.with_index do |t, i|
      Thread.new do
        port = t[:cli_port]
        args = iperf3_args('-c', HOST, '-p', port.to_s,
                           '-t', options[:duration].to_s, '-P', options[:parallel].to_s)
        case options[:direction]
        when 'reverse' then args << '-R'
        when 'bidir' then args << '--bidir'
        end
        mutex.synchronize { log_setup "client #{i + 1} starting on port #{port}..." }
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
        mutex.synchronize { log_setup "client #{i + 1} done." }
      end
    end

    test_timeout = [(options[:duration] || 30) + 15, 15].max
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
      $stderr.puts "  WARNING: #{thread_errors.length} thread(s) raised errors:"
      thread_errors.each { |e| $stderr.puts "    #{e.class}: #{e.message}" }
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
    return { ok: ok, max_rate: max_rate, avg_rate: avg_rate }
  ensure
    tunnels.each { |t| stop_procs(t[:cli_pid], t[:svr_pid]) }
    killall
    if !ok || options[:save_logs]
      diag_dir = "/tmp/bidir_diag"
      FileUtils.mkdir_p(diag_dir)
      ts = Time.now.strftime("%Y%m%d_%H%M%S")
      servers.each do |s|
        log = read_log(s[:log])
        unless log.empty?
          $stderr.puts "  # iperf3-server #{s[:tgt_port]} log:\n#{log.each_line.map { |l| "  # #{l}" }.join}"
          File.write(File.join(diag_dir, "#{ts}_iperf3_server_#{s[:tgt_port]}.log"), log)
        end
      end
      tunnels.each do |t|
        [t[:svr_log], t[:cli_log]].compact.each do |log|
          data = read_log(log)
          unless data.empty?
            base = File.basename(log.path)
            $stderr.puts "  # #{base}:\n#{data.each_line.map { |l| "  # #{l}" }.join}"
            File.write(File.join(diag_dir, "#{ts}_#{base}"), data)
          end
        end
      end
      $stderr.puts "  # Logs saved to #{diag_dir}/"
    end
  end
end

result = run_one_test(options)

exit result && result[:ok] ? 0 : 1
