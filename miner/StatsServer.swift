// ═══════════════════════════════════════════════════════════════════════════════
//  NerdMiner v4.1.0 — companion stats server
//
//  A tiny HTTP/1.1 server bound to 127.0.0.1 ONLY (never 0.0.0.0). The
//  "NerdMiner MD" browser extension polls it for live miner stats:
//
//      GET /stats    JSON snapshot of the mining loop
//      GET /events   text/event-stream: `event: stats` every 2 s,
//                    `event: block` the moment blocks_found increases
//      GET /health   {"ok":true,"version":"4.1.0"}
//      OPTIONS *     204 + CORS preflight
//
//  The NerdMiner MD extension is admitted by its request mark (X-NerdMiner-MD header
//  or an extension Origin, neither of which a web page can present; see authorized()).
//  Every other client carries `Authorization: Bearer <token>` or `?token=<token>`.
//  The token is a random 32-hex string generated on first run and kept at
//  ~/Library/Application Support/NerdMiner/companion-token (mode 0600).
//
//  Threading: the accept loop runs on its own DispatchQueue and each connection
//  on its own Thread. The mining loop never blocks on the server — it just
//  copies its numbers into `MinerStats.shared` once a second (lock-protected
//  value snapshot); the server only ever reads that snapshot.
//
//  Dependency-free: Foundation + Darwin sockets. No SIGPIPE risk for the miner:
//  every socket the server opens carries SO_NOSIGPIPE (no process-wide change).
// ═══════════════════════════════════════════════════════════════════════════════

import Foundation
import Darwin

let nerdMinerVersion = "4.1.0"   // the ONE version string: /stats, /health, mining.subscribe, --version, banners and login all read it
let statsDefaultPort: UInt16 = 47475

// ============================================================
// MARK: - Snapshot shared between the mining loop and the server
// ============================================================

struct MinerStatsSnapshot {
    var running: Bool = false
    var address: String = ""
    var worker: String = ""
    var pool: String = ""              // "host:port"
    var network: String = "mainnet"    // "mainnet" | "testnet"
    var mode: String = "solo"          // "solo" | "shared"
    var gpu: String = ""
    var chip: String = ""
    var hashrateHps: Double = 0
    var totalHashes: UInt64 = 0
    var uptimeS: Int = 0
    var sharesFound: UInt64 = 0
    var accepted: UInt64 = 0
    var rejected: UInt64 = 0
    var blocksFound: UInt64 = 0
    var lastBlockHeight: Int? = nil
    var difficulty: Double = 1
    var bestShareBits: Int = 0
    var dagEpoch: UInt64 = 0
    var dagBytes: UInt64 = 0
    var dagTrafficGBs: Double = 0
    var systemMemoryBytes: UInt64 = 0
    var lastEvent: String = ""

    /// JSON document for /stats and the SSE frames. Keys are emitted in a fixed
    /// order so the output is stable for humans reading it with curl.
    func toJSON() -> String {
        var f: [(String, String)] = []
        f.append(("version", jsonString(nerdMinerVersion)))
        f.append(("running", running ? "true" : "false"))
        f.append(("address", jsonString(address)))
        f.append(("worker", jsonString(worker)))
        f.append(("pool", jsonString(pool)))
        f.append(("network", jsonString(network)))
        f.append(("mode", jsonString(mode)))
        f.append(("gpu", jsonString(gpu)))
        f.append(("chip", jsonString(chip)))
        f.append(("hashrate_hps", jsonNumber(hashrateHps)))
        f.append(("hashrate_pretty", jsonString(formatHashrate(hashrateHps))))
        f.append(("total_hashes", String(totalHashes)))
        f.append(("uptime_s", String(uptimeS)))
        f.append(("shares_found", String(sharesFound)))
        f.append(("accepted", String(accepted)))
        f.append(("rejected", String(rejected)))
        f.append(("blocks_found", String(blocksFound)))
        f.append(("last_block_height", lastBlockHeight.map(String.init) ?? "null"))
        f.append(("difficulty", jsonNumber(difficulty)))
        f.append(("best_share_bits", String(bestShareBits)))
        f.append(("dag_epoch", String(dagEpoch)))
        f.append(("dag_bytes", String(dagBytes)))
        f.append(("dag_traffic_gbs", jsonNumber(dagTrafficGBs)))
        f.append(("system_memory_bytes", String(systemMemoryBytes)))
        f.append(("last_event", jsonString(lastEvent)))
        f.append(("ts", String(Int(Date().timeIntervalSince1970))))
        return "{" + f.map { "\(jsonString($0.0)):\($0.1)" }.joined(separator: ",") + "}"
    }
}

/// Process-wide stats mailbox. Writers (the mining loop) call `update`;
/// readers (the HTTP server) take a value copy via `snapshot`.
final class MinerStats {
    static let shared = MinerStats()
    private let lock = NSLock()
    private var snap = MinerStatsSnapshot()

    var snapshot: MinerStatsSnapshot {
        lock.lock(); defer { lock.unlock() }
        return snap
    }

    func update(_ body: (inout MinerStatsSnapshot) -> Void) {
        lock.lock(); defer { lock.unlock() }
        body(&snap)
    }
}

// ============================================================
// MARK: - JSON helpers (no Foundation JSONSerialization needed)
// ============================================================

func jsonString(_ s: String) -> String {
    var out = "\""
    for c in s.unicodeScalars {
        switch c {
        case "\"": out += "\\\""
        case "\\": out += "\\\\"
        case "\n": out += "\\n"
        case "\r": out += "\\r"
        case "\t": out += "\\t"
        default:
            if c.value < 0x20 { out += String(format: "\\u%04x", c.value) }
            else { out.unicodeScalars.append(c) }
        }
    }
    return out + "\""
}

func jsonNumber(_ d: Double) -> String {
    guard d.isFinite else { return "0" }
    if d == d.rounded(), abs(d) < 1e15 { return String(Int64(d)) }
    return String(d)   // shortest round-trip repr, always valid JSON (e.g. 0.001, 1e-05)
}

func sysctlString(_ name: String) -> String {
    var size = 0
    guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 0 else { return "" }
    var buf = [CChar](repeating: 0, count: size)
    guard sysctlbyname(name, &buf, &size, nil, 0) == 0 else { return "" }
    return String(cString: buf)
}

/// "Apple M3 Pro" when the kernel exposes it, else the architecture string.
func chipDescription() -> String {
    let brand = sysctlString("machdep.cpu.brand_string").trimmingCharacters(in: .whitespaces)
    return brand.isEmpty ? "Apple Silicon / \(machineArchitecture())" : brand
}

// ============================================================
// MARK: - Companion token
// ============================================================

enum CompanionToken {
    static let directory = NSHomeDirectory() + "/Library/Application Support/NerdMiner"
    static let path = directory + "/companion-token"
    static let displayPath = "~/Library/Application Support/NerdMiner/companion-token"

    /// Load the token, creating a fresh random one (32 hex chars, file mode 0600)
    /// on first run. Returns the token, or an error string.
    static func loadOrCreate() -> Result<String, StatsError> {
        let fm = FileManager.default
        if let data = fm.contents(atPath: path),
           let text = String(data: data, encoding: .utf8) {
            let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
            if isValid(t) {
                chmod(path, 0o600)   // heal permissions if someone loosened them
                return .success(t)
            }
            // Unreadable/corrupt token file: regenerate rather than lock the user out.
        }
        do {
            try fm.createDirectory(atPath: directory, withIntermediateDirectories: true,
                                   attributes: [.posixPermissions: 0o700])
        } catch {
            return .failure(.io("cannot create \(directory): \(error.localizedDescription)"))
        }
        var bytes = [UInt8](repeating: 0, count: 16)
        var rng = SystemRandomNumberGenerator()   // arc4random-backed, cryptographically secure on Darwin
        for i in 0..<bytes.count { bytes[i] = UInt8.random(in: 0...255, using: &rng) }
        let token = bytes.map { String(format: "%02x", $0) }.joined()
        let ok = fm.createFile(atPath: path, contents: Data((token + "\n").utf8),
                               attributes: [.posixPermissions: 0o600])
        guard ok else { return .failure(.io("cannot write \(path)")) }
        chmod(path, 0o600)
        return .success(token)
    }

    static func isValid(_ t: String) -> Bool {
        t.count == 32 && t.allSatisfy { $0.isHexDigit }
    }
}

enum StatsError: Error, CustomStringConvertible {
    case io(String)
    case socket(String)
    var description: String {
        switch self {
        case .io(let s): return s
        case .socket(let s): return s
        }
    }
}

// ============================================================
// MARK: - HTTP server
// ============================================================

final class StatsServer {
    let port: UInt16
    private let token: [UInt8]
    private var listenFD: Int32 = -1
    private let acceptQueue = DispatchQueue(label: "com.nerdminer.stats.accept")

    /// Human-readable line for the dashboard / startup banner.
    var companionLine: String {
        "Companion: 127.0.0.1:\(port) · token in \(CompanionToken.displayPath)"
    }

    init(port: UInt16, token: String) {
        self.port = port
        self.token = Array(token.utf8)
    }

    /// Bind 127.0.0.1:port and start accepting in the background.
    func start() -> StatsError? {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return .socket("socket(): \(errnoText())") }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")   // loopback only, by construction
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard rc == 0 else {
            let e = errnoText(); close(fd)
            return .socket("bind 127.0.0.1:\(port): \(e)")
        }
        guard listen(fd, 16) == 0 else {
            let e = errnoText(); close(fd)
            return .socket("listen: \(e)")
        }
        listenFD = fd
        acceptQueue.async { [self] in acceptLoop() }
        return nil
    }

    private func acceptLoop() {
        let loopback = inet_addr("127.0.0.1")
        while true {
            var peer = sockaddr_in()
            var len = socklen_t(MemoryLayout<sockaddr_in>.size)
            let c = withUnsafeMutablePointer(to: &peer) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { accept(listenFD, $0, &len) }
            }
            if c < 0 {
                if errno == EINTR { continue }
                Thread.sleep(forTimeInterval: 0.05)
                continue
            }
            // Belt and braces: the listener is on 127.0.0.1, but refuse any non-loopback peer anyway.
            if peer.sin_addr.s_addr != loopback { close(c); continue }
            var one: Int32 = 1
            setsockopt(c, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
            var tv = timeval(tv_sec: 5, tv_usec: 0)
            setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
            setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
            let t = Thread { [self] in handle(c) }
            t.name = "nerdminer.stats.conn"
            t.start()
        }
    }

    // MARK: request parsing

    private struct Request {
        var method: String
        var path: String
        var query: [String: String]
        var headers: [String: String]   // lowercased names
    }

    private func readRequest(_ fd: Int32) -> Request? {
        var buf = [UInt8]()
        var chunk = [UInt8](repeating: 0, count: 4096)
        var headerEnd: Int? = nil
        while headerEnd == nil, buf.count < 65536 {
            let n = chunk.withUnsafeMutableBytes { recv(fd, $0.baseAddress, 4096, 0) }
            if n <= 0 { if n < 0 && errno == EINTR { continue }; return nil }
            buf.append(contentsOf: chunk[0..<n])
            headerEnd = findHeaderEnd(buf)
        }
        guard let end = headerEnd, let head = String(bytes: buf[0..<end], encoding: .utf8) else { return nil }
        let lines = head.components(separatedBy: "\r\n")
        guard let reqLine = lines.first else { return nil }
        let parts = reqLine.split(separator: " ", omittingEmptySubsequences: true)
        guard parts.count >= 2 else { return nil }
        let method = String(parts[0]).uppercased()
        let target = String(parts[1])
        var path = target
        var query: [String: String] = [:]
        if let q = target.firstIndex(of: "?") {
            path = String(target[..<q])
            for pair in target[target.index(after: q)...].split(separator: "&") {
                let kv = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
                let k = String(kv[0]).removingPercentEncoding ?? String(kv[0])
                let v = kv.count > 1 ? (String(kv[1]).removingPercentEncoding ?? String(kv[1])) : ""
                query[k] = v
            }
        }
        var headers: [String: String] = [:]
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = line[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            headers[name] = value
        }
        return Request(method: method, path: path, query: query, headers: headers)
    }

    private func findHeaderEnd(_ b: [UInt8]) -> Int? {
        guard b.count >= 4 else { return nil }
        var i = 0
        while i + 3 < b.count {
            if b[i] == 13, b[i+1] == 10, b[i+2] == 13, b[i+3] == 10 { return i }
            i += 1
        }
        return nil
    }

    private func authorized(_ r: Request) -> Bool {
        // The NerdMiner MD extension needs no token. A browser extension with host
        // permission for 127.0.0.1 sends its request straight; a web page cannot: its
        // request would carry a custom header only after a CORS preflight, and the
        // preflight below allows Authorization and Content-Type alone, so a page can
        // never present X-NerdMiner-MD. The Origin a browser stamps on an extension's
        // request (chrome-extension://, moz-extension://, safari-web-extension://) is
        // a second mark a page cannot forge. The server is read-only (GET/HEAD), and
        // a local program that wants to read the stats could read the token file
        // anyway, so nothing is given up. Scripts and curl keep using the token.
        if r.headers["x-nerdminer-md"] != nil { return true }
        if let origin = r.headers["origin"]?.lowercased(),
           origin.hasPrefix("chrome-extension://") || origin.hasPrefix("moz-extension://") || origin.hasPrefix("safari-web-extension://") {
            return true
        }
        if let auth = r.headers["authorization"] {
            let parts = auth.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
            if parts.count == 2, parts[0].lowercased() == "bearer",
               constantTimeEqual(Array(parts[1].trimmingCharacters(in: .whitespaces).utf8), token) {
                return true
            }
        }
        if let q = r.query["token"], constantTimeEqual(Array(q.utf8), token) { return true }
        return false
    }

    private func constantTimeEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<a.count { diff |= a[i] ^ b[i] }
        return diff == 0
    }

    // MARK: responses

    private let corsHeaders = [
        "Access-Control-Allow-Origin: *",
        "Access-Control-Allow-Headers: Authorization, Content-Type",   // never X-NerdMiner-MD: that is the extension's mark
        "Access-Control-Allow-Methods: GET, HEAD, OPTIONS",
        "Cache-Control: no-store",
    ]

    @discardableResult
    private func sendAll(_ fd: Int32, _ s: String) -> Bool {
        let bytes = Array(s.utf8)
        var off = 0
        while off < bytes.count {
            let n = bytes.withUnsafeBufferPointer { send(fd, $0.baseAddress! + off, bytes.count - off, 0) }
            if n <= 0 { if n < 0 && errno == EINTR { continue }; return false }
            off += n
        }
        return true
    }

    private func respond(_ fd: Int32, status: Int, reason: String, body: String?,
                         contentType: String = "application/json; charset=utf-8") {
        var head = "HTTP/1.1 \(status) \(reason)\r\n"
        head += "Server: NerdMiner/\(nerdMinerVersion)\r\n"
        head += corsHeaders.joined(separator: "\r\n") + "\r\n"
        head += "Connection: close\r\n"
        if let body = body {
            head += "Content-Type: \(contentType)\r\n"
            head += "Content-Length: \(body.utf8.count)\r\n\r\n"
            sendAll(fd, head + body)
        } else {
            head += "Content-Length: 0\r\n\r\n"
            sendAll(fd, head)
        }
    }

    private func handle(_ fd: Int32) {
        defer { close(fd) }
        guard let req = readRequest(fd) else { return }

        if req.method == "OPTIONS" {
            respond(fd, status: 204, reason: "No Content", body: nil)
            return
        }
        guard authorized(req) else {
            respond(fd, status: 401, reason: "Unauthorized", body: "{\"error\":\"unauthorized\"}")
            return
        }
        guard req.method == "GET" || req.method == "HEAD" else {
            respond(fd, status: 405, reason: "Method Not Allowed", body: "{\"error\":\"method not allowed\"}")
            return
        }
        switch req.path {
        case "/stats":
            respond(fd, status: 200, reason: "OK", body: MinerStats.shared.snapshot.toJSON())
        case "/health":
            respond(fd, status: 200, reason: "OK", body: "{\"ok\":true,\"version\":\(jsonString(nerdMinerVersion))}")
        case "/events":
            if req.method == "HEAD" { respond(fd, status: 200, reason: "OK", body: nil); return }
            streamEvents(fd)
        default:
            respond(fd, status: 404, reason: "Not Found", body: "{\"error\":\"not found\"}")
        }
    }

    // MARK: server-sent events

    private func streamEvents(_ fd: Int32) {
        var head = "HTTP/1.1 200 OK\r\n"
        head += "Server: NerdMiner/\(nerdMinerVersion)\r\n"
        head += corsHeaders.joined(separator: "\r\n") + "\r\n"
        head += "Content-Type: text/event-stream; charset=utf-8\r\n"
        head += "Connection: keep-alive\r\n"
        head += "X-Accel-Buffering: no\r\n\r\n"
        guard sendAll(fd, head + "retry: 2000\n\n") else { return }

        // Writes are blocking with SO_SNDTIMEO=5 s, so a wedged client cannot hold
        // the thread forever; a closed one fails the send and we return.
        var lastBlocks = MinerStats.shared.snapshot.blocksFound
        var nextStats = Date()
        while true {
            let snap = MinerStats.shared.snapshot
            if snap.blocksFound > lastBlocks {
                lastBlocks = snap.blocksFound
                guard sendAll(fd, "event: block\ndata: \(snap.toJSON())\n\n") else { return }
            }
            let now = Date()
            if now >= nextStats {
                guard sendAll(fd, "event: stats\ndata: \(snap.toJSON())\n\n") else { return }
                nextStats = now.addingTimeInterval(2)
            }
            if peerClosed(fd) { return }
            Thread.sleep(forTimeInterval: 0.25)
        }
    }

    /// Non-blocking peek: 0 bytes means the client hung up.
    private func peerClosed(_ fd: Int32) -> Bool {
        var b: UInt8 = 0
        let n = recv(fd, &b, 1, MSG_PEEK | MSG_DONTWAIT)
        if n == 0 { return true }
        if n < 0 { return !(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) }
        return false
    }

    private func errnoText() -> String { String(cString: strerror(errno)) }
}

// ============================================================
// MARK: - Startup helper used by main() and the demo
// ============================================================

/// Load/create the token, print it once, bind the server. Returns the running
/// server or nil (with the reason already printed). Never throws, never exits:
/// a companion failure must not stop mining.
func startCompanionServer(port: UInt16) -> StatsServer? {
    let token: String
    switch CompanionToken.loadOrCreate() {
    case .success(let t): token = t
    case .failure(let e):
        print("[-] Companion stats disabled: \(e)")
        return nil
    }
    print("Companion token: \(token) (for scripts and curl; the NerdMiner MD extension needs none)")
    fflush(stdout)   // make it land even when stdout is a pipe/file
    let server = StatsServer(port: port, token: token)
    if let err = server.start() {
        print("[-] Companion stats disabled: \(err) (use --stats-port N or --no-stats)")
        return nil
    }
    print("[+] Companion stats: http://127.0.0.1:\(port)/stats  (token file: \(CompanionToken.displayPath))")
    return server
}

// ============================================================
// MARK: - `__statsdemo` — exercise the server without touching the GPU
// ============================================================

/// Hidden subcommand: `NerdMiner __statsdemo [--stats-port N]`. Serves fake,
/// slowly changing numbers so the endpoint can be tested with curl while a real
/// miner owns the GPU. Blocks forever (Ctrl+C / kill to stop).
func statsDemoMain(_ argv: [String]) {
    var port = statsDefaultPort
    var i = 0
    while i < argv.count {
        if argv[i] == "--stats-port", i + 1 < argv.count, let p = UInt16(argv[i + 1]), p > 0 {
            port = p; i += 2
        } else { i += 1 }
    }
    let start = Date()
    MinerStats.shared.update { s in
        s.running = true
        s.address = "xpa1zdemo0000000000000000000000000000000000000000000demo"
        s.worker = "demo"
        s.pool = "127.0.0.1:3333"
        s.network = "mainnet"
        s.mode = "solo"
        s.gpu = "Demo GPU (no Metal device opened)"
        s.chip = chipDescription()
        s.difficulty = 0.001
        s.dagEpoch = 0
        s.dagBytes = 4_294_967_296
        s.systemMemoryBytes = systemMemoryBytes()
        s.lastEvent = "Demo mode — numbers are fake"
    }
    guard let server = startCompanionServer(port: port) else { exit(1) }
    print("[demo] serving fake stats on 127.0.0.1:\(server.port); a fake block lands every 7 s. Ctrl+C to stop.")
    var tick: UInt64 = 0
    while true {
        Thread.sleep(forTimeInterval: 1.0)
        tick += 1
        let hr = 8_000_000.0 + 400_000.0 * sin(Double(tick) / 5.0)
        MinerStats.shared.update { s in
            s.hashrateHps = hr
            s.totalHashes += UInt64(hr)
            s.uptimeS = Int(Date().timeIntervalSince(start))
            s.dagTrafficGBs = hr * 8192.0 / 1_000_000_000.0
            if tick % 3 == 0 { s.sharesFound += 1; s.accepted += 1; s.lastEvent = "Share accepted by pool (demo)" }
            if tick % 7 == 0 {
                s.blocksFound += 1
                s.lastBlockHeight = 1000 + Int(s.blocksFound)
                s.lastEvent = "BLOCK \(s.lastBlockHeight!) confirmed (demo)"
            }
            s.bestShareBits = max(s.bestShareBits, Int(tick % 40))
        }
    }
}
