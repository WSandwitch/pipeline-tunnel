set -e

bash tests/run_all_benchmark.sh -- -q -d 20 --direction forward
bash tests/run_all_benchmark.sh -- -q -d 20 --direction reverse
bash tests/run_all_benchmark.sh -- -q -d 20 --direction bidir
bash tests/run_all_benchmark.sh -- -q -d 20 -P 2 --direction forward
bash tests/run_all_benchmark.sh -- -q -d 20 -P 2 --direction reverse
bash tests/run_all_benchmark.sh -- -q -d 20 -P 2 --direction bidir
bash tests/run_all_benchmark.sh -- -q -d 20 -n 2 --direction forward
bash tests/run_all_benchmark.sh -- -q -d 20 -n 2 --direction reverse
bash tests/run_all_benchmark.sh -- -q -d 20 -n 2 --direction bidir
