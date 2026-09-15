//
//  Login.swift — NerdMiner login (version: nerdMinerVersion in StatsServer.swift)
//  `nerdminer login [<challenge-id>] [--server URL] [--wallet PATH] [--index N] [--no-open]`
//
//  Sign in with your xCoin identity (xid1…). The miner never touches a key: it
//  asks the xCoin wallet CLI (which handles passphrase / NTAG card unlock) to
//  sign a MineDifferent challenge with the wallet's ML-DSA-65 key, then posts the
//  identity + public key + signature to the forum. The forum verifies the
//  signature (FIPS 204) and that the identity is bech32m("xid", SHA-256(pubkey)).
//  The identity is a forum handle only: no version byte, no chain HRP, so no node
//  ever accepts it as an address and nothing can be paid to it. The same key's
//  address forms (witness v3 xpa1r…/txa1r…, legacy witness v2 xpa1z…) are what
//  older wallets presented here; the forum derives every form from the pubkey.
//  One wallet unlock per login: the wallet fills its own identity into the
//  message, and NerdMiner sends exactly the string the wallet signed.
//
import Foundation

let NerdMinerLoginVersion = nerdMinerVersion   // one version for the whole binary (StatsServer.swift)
let defaultLoginServer = "https://minedifferent.com"
let loginPrefix = "MineDifferent login v1"

private struct LoginError: Error, CustomStringConvertible { let description: String; init(_ s: String) { description = s } }

/// Locate the wallet CLI launcher. Order: $XCOIN_WALLET_CLI, ./wallet/xcoin-wallet-cli next to this binary,
/// the v4 package dir, then the canonical install at ~/x-Coin/wallet-cli.
private func walletCLIPath() -> String? {
    let env = ProcessInfo.processInfo.environment
    var candidates: [String] = []
    if let p = env["XCOIN_WALLET_CLI"] { candidates.append(p) }
    let exe = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath().deletingLastPathComponent()
    candidates.append(exe.appendingPathComponent("wallet/xcoin-wallet-cli").path)
    candidates.append(NSString(string: "~/x-Coin/nerdminer-v4/wallet/xcoin-wallet-cli").expandingTildeInPath)
    candidates.append(NSString(string: "~/x-Coin/wallet-cli/xcoin-wallet-cli").expandingTildeInPath)
    for c in candidates where FileManager.default.isExecutableFile(atPath: c) { return c }
    return nil
}

private func http(_ method: String, _ url: URL, json: [String: Any]? = nil, timeout: TimeInterval = 20) throws -> (Int, [String: Any]) {
    var req = URLRequest(url: url)
    req.httpMethod = method
    req.timeoutInterval = timeout
    req.setValue("NerdMiner/\(NerdMinerLoginVersion) login", forHTTPHeaderField: "User-Agent")
    if let j = json {
        req.httpBody = try JSONSerialization.data(withJSONObject: j)
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
    }
    let sem = DispatchSemaphore(value: 0)
    var out: (Int, [String: Any]) = (0, [:]); var err: Error?
    URLSession.shared.dataTask(with: req) { data, resp, e in
        defer { sem.signal() }
        if let e = e { err = e; return }
        let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
        let obj = (data.flatMap { try? JSONSerialization.jsonObject(with: $0) } as? [String: Any]) ?? [:]
        out = (code, obj)
    }.resume()
    sem.wait()
    if let e = err { throw LoginError("network: \(e.localizedDescription)") }
    return out
}


/// Read one line from the terminal itself with echo off. Returns nil when there
/// is no terminal — never falls back to stdin, because stdin may be a pipe and a
/// pipe must not be able to answer a passphrase prompt.
private func promptOnTTY(_ prompt: String) -> String? {
    guard let raw = getpass(prompt) else { return nil }
    return String(cString: raw)
}

/// Run the wallet CLI once. When `passphrase` is non-nil it is written to the
/// child's stdin, which the caller pairs with --passphrase-fd 0.
/// Returns (exit status, stdout + stderr combined).
private func runWallet(_ args: [String], passphrase: String?) throws -> (Int32, String) {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    p.arguments = args
    let outPipe = Pipe(), errPipe = Pipe()
    p.standardOutput = outPipe
    p.standardError = errPipe
    let inPipe = Pipe()
    if passphrase != nil { p.standardInput = inPipe } else { p.standardInput = FileHandle.standardInput }
    try p.run()
    if let pw = passphrase {
        inPipe.fileHandleForWriting.write(Data((pw + "\n").utf8))
        try? inPipe.fileHandleForWriting.close()
    }
    let out = outPipe.fileHandleForReading.readDataToEndOfFile()
    let err = errPipe.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    // Card prompts and errors went to our stderr before; keep them visible.
    if !err.isEmpty { FileHandle.standardError.write(err) }
    return (p.terminationStatus, String(decoding: out, as: UTF8.self) + String(decoding: err, as: UTF8.self))
}

/// Ask the wallet CLI to sign `template` (with `{address}` replaced by whatever the wallet
/// signs as: the xid1… identity on current wallets, an address form on older ones).
/// Returns (signedAs, pubkeyHex, sigHex, signedMessage). `signedAs` is taken verbatim
/// from the wallet's "address" field and is never re-derived or prefix-checked here.
private func walletSign(template: String, wallet: String?, index: Int) throws -> (String, String, String, String) {
    guard let cli = walletCLIPath() else {
        throw LoginError("xcoin-wallet-cli not found. Set XCOIN_WALLET_CLI=/path/to/xcoin-wallet-cli or install the wallet next to NerdMiner in ./wallet/")
    }
    var args = [cli]
    if let w = wallet { args += ["--file", w] }          // top-level option: must precede the subcommand
    args += ["signmessage", "--template", template, "--index", String(index)]

    // Run the wallet once with no passphrase supplied. A wallet that needs no
    // typed secret — no passphrase, or a name-locked card wallet — succeeds here
    // and the user is never asked anything.
    var (status, text) = try runWallet(args, passphrase: nil)

    // If it could not get a passphrase, ask HERE and pipe it down.
    //
    // This is the fix for the hang. The wallet CLI runs in its own process group,
    // so when it tried to read the terminal itself macOS sent it SIGTTIN and
    // suspended it — forever, with no error, because a background process may not
    // steal the foreground's keystrokes. NerdMiner IS the foreground process, so
    // it may read the terminal safely. It prompts, then hands the secret to the
    // wallet over stdin as --passphrase-fd 0, so the wallet never touches the
    // terminal at all. The secret never appears in argv, in the environment, in
    // ps output or in shell history.
    if status != 0 && text.contains("no terminal available to ask for the passphrase") {
        guard let pw = promptOnTTY("Wallet passphrase: ") else {
            throw LoginError("wallet is passphrase-protected and no terminal is available. "
                           + "Run this from a terminal, or unlock the wallet another way.")
        }
        // --passphrase-fd is a top-level wallet option: it must precede the subcommand.
        var withFd = args
        withFd.insert(contentsOf: ["--passphrase-fd", "0"], at: 1)
        (status, text) = try runWallet(withFd, passphrase: pw)
    }
    guard status == 0 else { throw LoginError("wallet signing failed (exit \(status))") }
    guard let line = text.split(separator: "\n").map(String.init).last(where: { $0.trimmingCharacters(in: .whitespaces).hasPrefix("{") }),
          let obj = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any],
          let addr = obj["address"] as? String, let pk = obj["pubkey"] as? String, let sig = obj["sig"] as? String,
          let msgHex = obj["message_hex"] as? String else {
        throw LoginError("wallet returned no signature JSON")
    }
    var bytes = [UInt8](); var idx = msgHex.startIndex
    while idx < msgHex.endIndex { let nx = msgHex.index(idx, offsetBy: 2); bytes.append(UInt8(msgHex[idx..<nx], radix: 16) ?? 0); idx = nx }
    return (addr, pk, sig, String(decoding: bytes, as: UTF8.self))
}

func loginMain(_ argv: [String]) {
    var server = defaultLoginServer, wallet: String? = nil, index = 101, challenge: String? = nil, openBrowser = true
    var i = 0
    while i < argv.count {
        let a = argv[i]
        switch a {
        case "--server": if i + 1 < argv.count { server = argv[i + 1]; i += 1 }
        case "--wallet", "--file": if i + 1 < argv.count { wallet = argv[i + 1]; i += 1 }
        case "--index": if i + 1 < argv.count { index = Int(argv[i + 1]) ?? 101; i += 1 }
        case "--no-open": openBrowser = false
        case "-h", "--help":
            print("""
            nerdminer login [<challenge-id>] [--server URL] [--wallet PATH] [--index N] [--no-open]

              Sign in to \(defaultLoginServer) with your xCoin identity (xid1…). Your key never leaves this Mac:
              the wallet CLI signs a short challenge with ML-DSA-65 and NerdMiner posts the signature.
              The identity is bech32m("xid", SHA-256(pubkey)): a forum handle, not a payout address.

              <challenge-id>   the id shown on the site's /login page. Omit it and NerdMiner makes its own
                               challenge and prints a one-time login link instead.
              --wallet PATH    wallet file (.mmm or legacy wallet.seed); default = the wallet CLI's default
              --index N        key index (default 101, the forum identity convention)
              --server URL     forum origin (default \(defaultLoginServer))
              --no-open        print the login link instead of opening it

              Example:  NerdMiner login --index 101
            """)
            return
        default:
            if !a.hasPrefix("-"), challenge == nil { challenge = a }
        }
        i += 1
    }
    server = server.hasSuffix("/") ? String(server.dropLast()) : server
    do {
        print("⛏  NerdMiner \(NerdMinerLoginVersion) · sign in with your xCoin identity (xid1…)")
        // 1. challenge
        var id: String, expires: Int
        if let c = challenge {
            let (code, obj) = try http("GET", URL(string: "\(server)/api/challenge/\(c)")!)
            guard code == 200, let e = obj["expires"] as? Int else { throw LoginError("challenge \(c) not found on \(server) (\(code))") }
            if (obj["solved"] as? Bool) == true { throw LoginError("that challenge was already used; reload the login page") }
            id = c; expires = e
        } else {
            let (code, obj) = try http("POST", URL(string: "\(server)/api/challenge/new")!, json: [:])
            guard code == 200, let cid = obj["id"] as? String, let e = obj["expires"] as? Int else { throw LoginError("could not create a challenge on \(server) (\(code))") }
            id = cid; expires = e
        }
        guard expires > Int(Date().timeIntervalSince1970) else { throw LoginError("challenge expired; reload the login page") }
        print("   challenge \(id) · server \(server)")
        // 2. one wallet unlock: the wallet fills {address} in with its identity and signs.
        //    The line stays "address:" on the wire (MineDifferent login v1); its value is
        //    the xid1… identity on current wallets.
        let template = "\(loginPrefix)\nchallenge: \(id)\naddress: {address}\nexpires: \(expires)"
        let (signedAs, pk, sig, signed) = try walletSign(template: template, wallet: wallet, index: index)
        let expected = template.replacingOccurrences(of: "{address}", with: signedAs)
        guard signed == expected else { throw LoginError("wallet signed an unexpected message") }
        let form = signedAs.lowercased().hasPrefix("xid1") ? "identity" : "address (older wallet; the forum still derives it from the pubkey)"
        print("   signed as \(signedAs)  · \(form)  (pubkey \(pk.count / 2) B, sig \(sig.count / 2) B)")
        // 3. submit exactly the string the wallet signed; the forum re-derives it from the pubkey.
        let (code, obj) = try http("POST", URL(string: "\(server)/api/challenge/\(id)/solve")!, json: ["address": signedAs, "pubkey": pk, "sig": sig], timeout: 30)
        guard code == 200, (obj["ok"] as? Bool) == true, let link = obj["login_url"] as? String else {
            throw LoginError("server rejected the signature (\(code)): \(obj["error"] ?? "unknown")")
        }
        let role = (obj["role"] as? String) ?? "miner"
        if let b = obj["badges"] as? [String: Any] { print("   verified ✓  role \(role)  blocks \(b["blocks"] ?? 0)  shares \(b["shares"] ?? 0)") }
        if challenge != nil {
            print("   done — the login page in your browser signs in by itself.")
        } else {
            print("   one-time login link:\n   \(link)")
            if openBrowser {
                let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/open"); p.arguments = [link]; try? p.run()
            }
        }
    } catch {
        FileHandle.standardError.write("✗ login failed: \(error)\n".data(using: .utf8)!)
        exit(1)
    }
}
