import Foundation
import Security

if #available(macOS 15.0, *) {
    guard CommandLine.arguments.count == 3 else {
        print("usage: apple-import.swift PASSWORD P12_PATH")
        exit(2)
    }

    let password = CommandLine.arguments[1]
    let opts = [kSecImportExportPassphrase as String: password, kSecImportToMemoryOnly as String: true] as CFDictionary

    let path = CommandLine.arguments[2]
    let name = URL(fileURLWithPath: path).lastPathComponent
    guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
        print("\(name): READ_FAIL")
        exit(1)
    }

    var imported: CFArray?
    let status = SecPKCS12Import(data as CFData, opts, &imported)

    guard status == errSecSuccess, let rows = imported as? [[String: Any]], let row = rows.first,
          let rawIdentity = row[kSecImportItemIdentity as String],
          CFGetTypeID(rawIdentity as CFTypeRef) == SecIdentityGetTypeID() else {
        print("\(name): IMPORT_FAIL OSStatus=\(status)")
        exit(1)
    }

    let identity = rawIdentity as! SecIdentity
    var certRef: SecCertificate?
    var keyRef: SecKey?
    let cstatus = SecIdentityCopyCertificate(identity, &certRef)
    let kstatus = SecIdentityCopyPrivateKey(identity, &keyRef)

    guard cstatus == errSecSuccess, kstatus == errSecSuccess, let cert = certRef, let key = keyRef,
          let pubkey = SecCertificateCopyKey(cert) else {
        print("\(name): IDENTITY_FAIL cert=\(cstatus) key=\(kstatus)")
        exit(1)
    }

    let message = Data("in-memory PKCS12 import probe".utf8)
    let alg: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256
    var error: Unmanaged<CFError>?

    guard let sig = SecKeyCreateSignature(key, alg, message as CFData, &error) else {
        print("\(name): SIGN_FAIL \(String(describing: error))")
        exit(1)
    }

    let valid = SecKeyVerifySignature(pubkey, alg, message as CFData, sig, &error)

    print("\(name): IMPORT_OK identity=yes privateKey=yes signVerify=\(valid ? "ok" : "fail")")
    exit(valid ? 0 : 1)
} else {
    print("STOP: memory-only import unavailable")
    exit(2)
}
