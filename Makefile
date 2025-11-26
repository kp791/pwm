# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c11 -O2
CFLAGS += -fstack-protector-strong -fPIE
DEBUG_FLAGS = -g -O0 -fsanitize=address -fno-omit-frame-pointer
INCLUDES = -Iinclude
LDFLAGS = -pie -Wl,-z,relro,-z,now
LIBS = -lsodium -ljansson -lcmocka

# Directories
SRC_DIR = src
INC_DIR = include
TEST_DIR = tests
BUILD_DIR = build
BIN_DIR = bin

# Source files
SRCS = $(SRC_DIR)/crypto.c $(SRC_DIR)/database.c $(SRC_DIR)/entry.c $(SRC_DIR)/cli.c
MAIN_SRC = $(SRC_DIR)/pwm.c
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
MAIN_OBJ = $(BUILD_DIR)/pwm.o

# Test files
TEST_SRCS = $(wildcard $(TEST_DIR)/test_*.c)
TEST_BINS = $(TEST_SRCS:$(TEST_DIR)/%.c=$(BIN_DIR)/%)

# Main executable
TARGET = $(BIN_DIR)/pwm

# Default target
all: $(TARGET)

# Create directories
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Compile source files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Link main executable
$(TARGET): $(OBJS) $(MAIN_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LIBS)
	@echo "Built: $(TARGET)"

# Compile test executables
$(BIN_DIR)/test_%: $(TEST_DIR)/test_%.c $(OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(DEBUG_FLAGS) $(INCLUDES) $^ -o $@ $(LIBS)
	@echo "Built test: $@"

# Build all tests
tests: $(TEST_BINS)

# Run all tests
test: tests
	@echo "Running all tests..."
	@for test in $(TEST_BINS); do \
		echo "\n========================================"; \
		echo "Running $$test"; \
		echo "========================================"; \
		$$test || exit 1; \
	done
	@echo "\n========================================"
	@echo "All tests passed!"
	@echo "========================================"

# Run tests with Valgrind (memory leak detection)
valgrind: tests
	@echo "Running tests with Valgrind..."
	@for test in $(TEST_BINS); do \
		echo "\nRunning $$test with Valgrind..."; \
		valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes \
		         --error-exitcode=1 $$test || exit 1; \
	done
	@echo "\nAll tests passed with no memory leaks!"

# Debug build
debug: CFLAGS += $(DEBUG_FLAGS)
debug: clean $(TARGET)
	@echo "Debug build complete"

# Install (optional)
install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/pwm
	@echo "Installed to /usr/local/bin/pwm"

# Uninstall
uninstall:
	rm -f /usr/local/bin/pwm
	@echo "Uninstalled from /usr/local/bin/pwm"

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)
	rm -f .test_*.db .pwm.db *.tmp.*
	@echo "Cleaned build artifacts"

# Help target
help:
	@echo "Password Manager - Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build main executable (default)"
	@echo "  tests     - Build all test executables"
	@echo "  test      - Build and run all tests"
	@echo "  valgrind  - Run tests with Valgrind memory checker"
	@echo "  debug     - Build with debug symbols and AddressSanitizer"
	@echo "  install   - Install to /usr/local/bin"
	@echo "  uninstall - Remove from /usr/local/bin"
	@echo "  clean     - Remove all build artifacts"
	@echo "  help      - Show this help message"
	@echo ""
	@echo "Examples:"
	@echo "  make              # Build main program"
	@echo "  make test         # Run all tests"
	@echo "  make debug        # Debug build"
	@echo "  make valgrind     # Check for memory leaks"

# Phony targets
.PHONY: all tests test valgrind debug install uninstall clean help

# Dependency tracking
-include $(OBJS:.o=.d)
-include $(MAIN_OBJ:.o=.d)

# Generate dependencies
$(BUILD_DIR)/%.d: $(SRC_DIR)/%.c | $(BUILD_DIR)
	@$(CC) $(CFLAGS) $(INCLUDES) -MM -MT $(BUILD_DIR)/$*.o $< > $@

