#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
#  NerdMiner v4.1.0 - xCoin MetalDAG Edition
#  Native MetalDAG build for Apple Silicon Macs
#
#  Copyright (c) 2025 David Otero / Distributed Ledger Technologies
#  www.distributedledgertechnologies.com
# ═══════════════════════════════════════════════════════════════════════════════

echo ""
echo "╔══════════════════════════════════════════════════════════════════════════╗"
echo "║          NerdMiner v4.1.0 - xCoin MetalDAG Edition                   ║"
echo "║              Native Apple Silicon Build                                 ║"
echo "╚══════════════════════════════════════════════════════════════════════════╝"
echo ""

# Check for Swift
if ! command -v swiftc &> /dev/null; then
    echo "❌ Swift compiler not found!"
    echo "   Please install Xcode Command Line Tools:"
    echo "   xcode-select --install"
    exit 1
fi

echo "[BUILD] Compiling main.swift + MetalDAG with Metal GPU support..."
swiftc -O -o NerdMiner main.swift Login.swift StatsServer.swift MetalDAGEngine.swift MetalDAGShader.swift -framework Metal -framework CoreGraphics 2>&1

if [ $? -eq 0 ]; then
    echo "[BUILD] ✅ NerdMiner built successfully!"
    chmod +x NerdMiner
    ln -sf NerdMiner MacMetalCLI   # compatibility name for existing scripts
    echo ""
    echo "═══════════════════════════════════════════════════════════════════════════"
    echo "BUILD COMPLETE!"
    echo "═══════════════════════════════════════════════════════════════════════════"
    echo ""
    echo "Usage:"
    echo "  ./NerdMiner <xcoin_address> [--pool host:port] [--worker name] [--stats-port N | --no-stats]"
    echo ""
    echo "Examples:"
    echo "  # Mine xCoin testnet through the local MetalDAG pool"
    echo "  ./NerdMiner txa1rz... --pool 127.0.0.1:3333 --worker cli"
    echo ""
    echo "  Testnet addresses begin with txa1r; mainnet addresses use the xCoin HRP."
    echo "  Telemetry is off by default. Set NERDMINER_TELEMETRY=1 to opt in."
    echo ""
else
    echo "[BUILD] ❌ Build failed!"
    exit 1
fi
