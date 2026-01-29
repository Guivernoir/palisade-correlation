#!/bin/bash
# Build verification script for palisade-correlation

set -e

echo "╔════════════════════════════════════════════════════════╗"
echo "║     PALISADE-CORRELATION BUILD VERIFICATION           ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

check_step() {
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓${NC} $1"
    else
        echo -e "${RED}✗${NC} $1"
        exit 1
    fi
}

# Step 1: Check Rust toolchain
echo "1. Checking Rust toolchain..."
rustc --version > /dev/null 2>&1
check_step "Rust compiler found"

cargo --version > /dev/null 2>&1
check_step "Cargo found"
echo ""

# Step 2: Clean build
echo "2. Clean build..."
cargo clean
check_step "Clean successful"

cargo build
check_step "Build successful"
echo ""

# Step 3: Run tests
echo "3. Running test suite..."
cargo test --lib
check_step "Unit tests passed"

cargo test --test integration
check_step "Integration tests passed"

cargo test
check_step "All tests passed"
echo ""

# Step 4: Check formatting
echo "4. Checking code formatting..."
cargo fmt -- --check
check_step "Code formatting OK"
echo ""

# Step 5: Run clippy
echo "5. Running clippy..."
cargo clippy -- -D warnings
check_step "No clippy warnings"
echo ""

# Step 6: Build documentation
echo "6. Building documentation..."
cargo doc --no-deps
check_step "Documentation built"
echo ""

# Step 7: Run examples
echo "7. Running examples..."
cargo run --example basic_usage > /dev/null
check_step "basic_usage example runs"

cargo run --example full_integration > /dev/null
check_step "full_integration example runs"
echo ""

# Step 8: Check dependencies
echo "8. Checking dependencies..."
cargo tree > /dev/null
check_step "Dependency tree OK"

# Check for published crates
if cargo search palisade-errors | grep -q "palisade-errors"; then
    check_step "palisade-errors available on crates.io"
else
    echo -e "${YELLOW}⚠${NC}  palisade-errors not yet on crates.io"
fi

if cargo search palisade-config | grep -q "palisade-config"; then
    check_step "palisade-config available on crates.io"
else
    echo -e "${YELLOW}⚠${NC}  palisade-config not yet on crates.io"
fi
echo ""

# Step 9: Package check
echo "9. Package verification..."
cargo package --allow-dirty
check_step "Package creation OK"
echo ""

echo "╔════════════════════════════════════════════════════════╗"
echo "║     ALL CHECKS PASSED                                  ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""
echo "Ready for:"
echo "  • Publishing to crates.io: cargo publish"
echo "  • Documentation deployment: cargo doc && docs upload"
echo "  • Version tagging: git tag v0.1.0"
echo ""