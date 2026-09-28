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
    echo "  ./NerdMiner <xpa1r-address> [--pool host:port] [--worker name] [--base <unixtime>] [--stats-port N | --no-stats]"
    echo ""
    echo "Examples:"
    echo "  # Mine mainnet on the public solo pool (--base is the mainnet genesis time)"
    echo "  ./NerdMiner xpa1r... --pool pool.xcoinminer.com:3335 --base 1790380800 --worker rig1"
    echo ""
    echo "  Mainnet payout addresses begin with xpa1r (witness v3); testnet A (txa1r) is retired."
    echo "  Telemetry is off by default. Set NERDMINER_TELEMETRY=1 to opt in."
    echo ""
else
    echo "[BUILD] ❌ Build failed!"
    exit 1
fi
