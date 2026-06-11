#!/usr/bin/env ruby
# frozen_string_literal: true

$stdout.sync = true

require 'optparse'

TESTS_DIR = File.dirname(File.absolute_path(__FILE__))
MODULE_CONF_DIR = File.join(TESTS_DIR, 'module_conf')
TESTS_CFG = File.join(TESTS_DIR, 'tests.cfg.list')

options = {
  build_dir: nil,
  mod_dir: nil,
  config: nil,
  workers: [1, 2, 3, 4, 8, 0],
  verbose: false,
  quiet: false,
  stop_on_fail: false,
  list_modules: false,
  list_configs: false,
}

op = OptionParser.new do |o|
  o.banner = "Usage: #{$PROGRAM_NAME} -S <build_dir> -M <mod_dir> [options] <command> [-- <extra>...]"

  o.on('-S', '--server-dir DIR', 'Path to build dir with ppltunnel-server/client') { |v| options[:build_dir] = File.absolute_path(v) }
  o.on('-M', '--module-dir DIR', 'Path to .so modules dir') { |v| options[:mod_dir] = File.absolute_path(v) }
  o.on('-C', '--config CONFIG', 'Only run configs matching this module/config') { |v| options[:config] = v }
  o.on('--workers LIST', 'Worker counts (comma-separated, 0=auto)') { |v| options[:workers] = v.split(',').map(&:to_i) }
  o.on('-v', '--verbose', 'Print each command before running') { options[:verbose] = true }
  o.on('-q', '--quiet', 'Only print summary') { options[:quiet] = true }
  o.on('--stop-on-fail', 'Stop on first failure') { options[:stop_on_fail] = true }
  o.on('--list-modules', 'List modules and exit') { options[:list_modules] = true }
  o.on('--list-configs', 'List configs and exit') { options[:list_configs] = true }
end

# Split args at '--'
dash_idx = ARGV.index('--')
if dash_idx
  cmd_extra = ARGV[(dash_idx + 1)..]
  ARGV.slice!(dash_idx..-1)
else
  cmd_extra = []
end

# Parse options (leftovers are the command)
rest = []
loop do
  begin
    leftovers = op.parse(ARGV)
    rest.concat(leftovers)
    break
  rescue OptionParser::InvalidOption => e
    opt = e.args.first
    rest << opt if opt&.start_with?('-')
    idx = ARGV.index(opt)
    ARGV.delete_at(idx) if idx
  end
end

cmd_parts = rest

if options[:build_dir].nil? || options[:mod_dir].nil?
  puts op.help
  exit 1
end

candidates = [
  ->(d) { File.join(d, 'server', 'ppltunnel-server') },
  ->(d) { File.join(d, 'client', 'ppltunnel-client') },
  ->(d) { File.join(d, 'ppltunnel-server') },
  ->(d) { File.join(d, 'ppltunnel-client') },
]
server_bin = candidates.map { |fn| fn.call(options[:build_dir]) }.find { |f| File.exist?(f) }
client_bin = candidates.map { |fn| fn.call(options[:build_dir]) }.find { |f| File.exist?(f) }

unless server_bin && client_bin
  puts "Error: server or client not found in #{options[:build_dir]}"
  exit 1
end

# Discover modules
module_names = []
begin
  IO.popen([server_bin, '--module-list', "-M#{options[:mod_dir]}"], err: [:child, :out]) do |io|
    io.each_line do |line|
      next unless line.start_with?('  ')
      name = line.strip.split[0]
      module_names << name if name
    end
  end
rescue => e
  $stderr.puts "Error discovering modules: #{e}"
  exit 1
end

if options[:list_modules]
  module_names.each { |m| puts m }
  exit 0
end

# Build config list
configs = []

module_names.each do |m|
  cfg_file = File.join(MODULE_CONF_DIR, "#{m}.cfg.list")
  if File.exist?(cfg_file)
    lines = File.readlines(cfg_file, chomp: true).map(&:strip).reject { |l| l.empty? || l.start_with?('#') }
    if lines.empty?
      configs << m
    else
      lines.each { |l| configs << "#{m}|#{l}" }
    end
  else
    configs << m
  end
end

# Chain configs from tests.cfg.list
if File.exist?(TESTS_CFG)
  File.readlines(TESTS_CFG, chomp: true).map(&:strip).reject { |l| l.empty? || l.start_with?('#') }.each do |l|
    configs << l
  end
end

# Filter by config if -C was given
if options[:config]
  filter = options[:config]
  if filter.include?('|') || filter.include?(';')
    configs.select! { |c| c == filter }
  else
    configs.select! { |c| c == filter || c.start_with?("#{filter}|") }
  end
end

if options[:list_configs]
  configs.each { |c| puts c }
  exit 0
end

if cmd_parts.empty?
  puts "Error: no command specified"
  puts op.help
  exit 1
end

total = 0
passed = 0

failed_configs = []

configs.each do |cfg|
  options[:workers].each do |w|
    total += 1
    wt = w == 0 ? '0' : w.to_s
    cmd = cmd_parts.dup
    # if command is a relative path, resolve it relative to TESTS_DIR
    cmd[0] = File.join(TESTS_DIR, cmd[0]) unless cmd[0].start_with?('/')
    # prepend ruby if script is not executable
    cmd.unshift('ruby') unless File.executable?(cmd[0])
    cmd.concat(cmd_extra) if cmd_extra
    cmd << '-S' << options[:build_dir] if options[:build_dir]
    cmd << '-M' << options[:mod_dir] if options[:mod_dir]
    cmd << '-C' << cfg
    cmd << '-t' << wt

    cmd_str = cmd.map { |s| s.include?(' ') || s.include?(';') || s.include?('|') || s.include?('"') ? "\"#{s}\"" : s }.join(' ')
    puts cmd_str if options[:verbose]

    unless options[:quiet]
      puts "#{cfg} t=#{wt}"
    end

    system(*cmd)
    ok = $?.exitstatus == 0
    passed += 1 if ok
    failed_configs << [cfg, w] unless ok

    if !ok && options[:stop_on_fail]
      puts "STOP-ON-FAIL"
      break
    end
  end
end

unless options[:quiet]
  puts "#{passed}/#{total} passed"
  if failed_configs.any?
    puts "Failed: #{failed_configs.map { |c, w| "#{c} t=#{w}" }.join(', ')}"
  end
end
exit passed == total ? 0 : 1
