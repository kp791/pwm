# PWM - Secure Password Manager

A modern, command-line password manager written in C with strong cryptographic features.

## Features

- **Strong Encryption**: XChaCha20-Poly1305 authenticated encryption
- **Secure Key Derivation**: Argon2id password hashing
- **Atomic Operations**: Crash-safe database updates using fsync+rename
- **Memory Protection**: Secure memory allocation with mlock and automatic zeroing
- **Input Validation**: Comprehensive validation preventing control characters and injection attacks
- **File Security**: Enforced 0600 permissions on database files
- **Password Generation**: Cryptographically secure random password/username generation

## Security Design

- **Encryption**: XChaCha20-Poly1305 (AEAD) with 256-bit keys
- **Key Derivation**: Argon2id with 64MB memory, 4 iterations
- **Authentication**: Poly1305 MAC detects tampering
- **Random Generation**: Uses system CSPRNG (`/dev/urandom` via libsodium)
- **Memory Safety**: All sensitive data locked in memory and zeroed after use
- **No Network**: Zero network exposure by design

## Dependencies

### Fedora
sudo dnf install libsodium-devel jansson-devel libcmocka-devel gcc make

### Ubuntu/Debian
sudo apt install libsodium-dev libjansson-dev libcmocka-dev build-essential

### macOS
brew install libsodium jansson cmocka

## Building

### Standard build
make

### Run all tests
make test

### Debug build with AddressSanitizer
make debug

### Check for memory leaks
make valgrind

### Install system-wide
sudo make install

## Usage

### Initialize Database
pwm init

### Add Entries
#### Add entry with manual password
pwm add gmail.com user@example.com

#### Generate secure password
pwm add github.com myusername -gp

#### Generate both username and password
pwm add website.com -gu -gp

#### Add with comment
pwm add service.com user -gp -c "2FA enabled"

#### Custom password length with symbols
pwm add site.com user -gp -l 32 -s

### List Entries
pwm ls

### Retrieve Entry

#### By index
pwm get 0

#### By domain
pwm get gmail.com

#### By domain and username
pwm get gmail.com:user@example.com

### Remove Entry

#### By index
pwm rm 0

#### By domain
pwm rm github.com

#### By domain and username
pwm rm gmail.com:user@example.com

### Change Master Password
pwm change-password

## Environment Variables

- `PWM_DB_PATH`: Custom database file location (default: `.pwm.db`)

## Project Structure

pwm/
├── include/ # Header files
│ ├── common.h
│ ├── crypto.h
│ ├── database.h
│ ├── entry.h
│ └── cli.h
├── src/ # Implementation files
│ ├── pwm.c
│ ├── crypto.c
│ ├── database.c
│ ├── entry.c
│ └── cli.c
├── tests/ # Test suite
│ ├── test_crypto.c
│ ├── test_entry.c
│ ├── test_database.c
│ ├── test_cli.c
│ └── test_integration.c
├── Makefile
└── README.md

## Testing

The project includes comprehensive unit and integration tests:

### Run all tests
make test

### Run specific test
./bin/test_crypto

### Memory leak detection
make valgrind


### All tests use CMocka framework and cover:
- Unit tests for every function
- Edge cases and error conditions
- Integration tests for complete workflows
- Memory safety validation

## Security Considerations

### Best Practices
1. Use strong master password (minimum 8 characters, recommend 16+)
2. Keep database file secure with proper filesystem permissions
3. Never commit database file to version control
4. Regularly backup encrypted database
5. Use password generation features for maximum entropy

## Contributing

When contributing:
1. All code must pass `make test` with no failures
2. Run `make valgrind` to check for memory leaks
3. Follow existing code style and conventions
4. Add tests for new functionality
5. Update documentation as needed

