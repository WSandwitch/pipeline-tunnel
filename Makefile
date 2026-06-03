BUILD_DIR ?= build

all:
	cmake -B $(BUILD_DIR) && cmake --build $(BUILD_DIR)

pack:
	cmake -B $(BUILD_DIR) && cmake --build $(BUILD_DIR) --target pack

clean:
	cmake --build $(BUILD_DIR) --target clean

rebuild: clean pack

.PHONY: all pack clean rebuild
