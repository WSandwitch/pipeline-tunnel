#set -e

docker kill modtunnel-worker

bash tests/run_all_benchmark.sh -- -q -d 20 --direction forward --save_logs
bash tests/run_all_benchmark.sh -- -q -d 20 --direction reverse --save_logs
bash tests/run_all_benchmark.sh -- -q -d 20 --direction bidir --save_logs
bash tests/run_all_benchmark.sh -- -q -d 20 -P 2 --direction forward --save_logs
bash tests/run_all_benchmark.sh -- -q -d 20 -P 2 --direction reverse --save_logs
bash tests/run_all_benchmark.sh -- -q -d 20 -P 2 --direction bidir --save_logs
bash tests/run_all_benchmark.sh -- -q -d 20 -n 2 --direction forward --save_logs
bash tests/run_all_benchmark.sh -- -q -d 20 -n 2 --direction reverse --save_logs
bash tests/run_all_benchmark.sh -- -q -d 20 -n 2 --direction bidir --save_logs
