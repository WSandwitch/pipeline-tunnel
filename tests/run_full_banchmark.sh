set -e

docker kill modtunnel-worker || echo container not found

export LOGS_DIR=/app/logs/arm64  

bash tests/run_all_benchmark.sh --  -d 15 --direction forward --save_logs
bash tests/run_all_benchmark.sh --  -d 15 --direction reverse --save_logs
bash tests/run_all_benchmark.sh --  -d 15 --direction bidir --save_logs

bash tests/run_all_benchmark.sh --  -d 15 -P 2 --direction forward --save_logs
bash tests/run_all_benchmark.sh --  -d 15 -P 2 --direction reverse --save_logs
bash tests/run_all_benchmark.sh --  -d 15 -P 2 --direction bidir --save_logs

exit 0
bash tests/run_all_benchmark.sh --  -d 15 -n 2 --direction forward --save_logs
bash tests/run_all_benchmark.sh --  -d 15 -n 2 --direction reverse --save_logs
bash tests/run_all_benchmark.sh --  -d 15 -n 2 --direction bidir --save_logs
