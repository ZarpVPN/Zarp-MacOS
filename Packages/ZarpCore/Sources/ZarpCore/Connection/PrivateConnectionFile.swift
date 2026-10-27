import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

enum PrivateConnectionFileError: Error { case location, permissions, io, size }

/// Shared restricted file operations. The owning store serializes calls. Paths
/// are app construction data, never privileged IPC input.
struct PrivateConnectionFile {
    let url: URL
    let maxBytes: Int

    func load() throws -> Data? {
        guard let directory = try openDirectory(create: false) else { return nil }
        defer { _ = close(directory) }
        let fd = openat(directory, url.lastPathComponent, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        if fd < 0 {
            if errno == ENOENT { return nil }
            throw PrivateConnectionFileError.location
        }
        defer { _ = close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, (Int(info.st_mode) & Int(S_IFMT)) == Int(S_IFREG), info.st_uid == geteuid() else {
            throw PrivateConnectionFileError.location
        }
        guard Int(info.st_mode) & 0o077 == 0 else { throw PrivateConnectionFileError.permissions }
        guard info.st_size >= 0, info.st_size <= maxBytes else { throw PrivateConnectionFileError.size }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 16_384)
        while true {
            let count = buffer.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
            if count == 0 { break }
            if count < 0 {
                if errno == EINTR { continue }
                throw PrivateConnectionFileError.io
            }
            guard data.count + count <= maxBytes else { throw PrivateConnectionFileError.size }
            data.append(contentsOf: buffer.prefix(count))
        }
        return data
    }

    func save(_ data: Data) throws {
        guard data.count <= maxBytes else { throw PrivateConnectionFileError.size }
        guard let directory = try openDirectory(create: true) else { throw PrivateConnectionFileError.location }
        defer { _ = close(directory) }
        let temporary = ".zarp-connection-\(UUID().uuidString).tmp"
        let fd = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw PrivateConnectionFileError.io }
        defer { _ = close(fd); _ = unlinkat(directory, temporary, 0) }
        guard fchmod(fd, 0o600) == 0 else { throw PrivateConnectionFileError.permissions }
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw PrivateConnectionFileError.io }
                offset += count
            }
        }
        guard fsync(fd) == 0 else { throw PrivateConnectionFileError.io }
        var existing = stat()
        if fstatat(directory, url.lastPathComponent, &existing, AT_SYMLINK_NOFOLLOW) == 0 {
            guard (Int(existing.st_mode) & Int(S_IFMT)) == Int(S_IFREG), existing.st_uid == geteuid() else {
                throw PrivateConnectionFileError.location
            }
        } else if errno != ENOENT { throw PrivateConnectionFileError.io }
        guard renameat(directory, temporary, directory, url.lastPathComponent) == 0, fsync(directory) == 0 else {
            throw PrivateConnectionFileError.io
        }
    }

    func delete() throws {
        guard let directory = try openDirectory(create: false) else { return }
        defer { _ = close(directory) }
        var info = stat()
        if fstatat(directory, url.lastPathComponent, &info, AT_SYMLINK_NOFOLLOW) != 0 {
            if errno == ENOENT { return }
            throw PrivateConnectionFileError.io
        }
        guard (Int(info.st_mode) & Int(S_IFMT)) == Int(S_IFREG), info.st_uid == geteuid() else {
            throw PrivateConnectionFileError.location
        }
        guard Int(info.st_mode) & 0o077 == 0 else { throw PrivateConnectionFileError.permissions }
        guard unlinkat(directory, url.lastPathComponent, 0) == 0, fsync(directory) == 0 else {
            throw PrivateConnectionFileError.io
        }
    }

    private func openDirectory(create: Bool) throws -> Int32? {
        guard url.isFileURL, !url.lastPathComponent.isEmpty, url.lastPathComponent != ".", url.lastPathComponent != ".." else {
            throw PrivateConnectionFileError.location
        }
        let parent = url.deletingLastPathComponent()
        if create {
            do {
                try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true,
                                                       attributes: [.posixPermissions: 0o700])
            } catch { throw PrivateConnectionFileError.io }
        }
        let fd = open(parent.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        if fd < 0 {
            if !create && errno == ENOENT { return nil }
            throw PrivateConnectionFileError.location
        }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_uid == geteuid(), Int(info.st_mode) & 0o077 == 0 else {
            _ = close(fd)
            throw PrivateConnectionFileError.permissions
        }
        return fd
    }
}
