// swift-tools-version:5.9
// Xcode / SwiftPM convenience wrapper so the CLI opens and builds in Xcode.
// (build.sh is still the canonical build; this just exposes the same sources.)
import PackageDescription

let package = Package(
    name: "NerdMiner",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(
            name: "NerdMiner",
            path: ".",
            exclude: ["build.sh", "README.md", "LICENSE"],
            sources: ["main.swift", "Login.swift", "StatsServer.swift", "MetalDAGEngine.swift", "MetalDAGShader.swift"],
            linkerSettings: [
                .linkedFramework("Metal"),
                .linkedFramework("CoreGraphics")
            ]
        )
    ]
)
