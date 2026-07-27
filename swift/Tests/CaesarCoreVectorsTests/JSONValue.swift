/// Минимальное типизированное представление `protocol/vectors.json`.
///
/// `JSONSerialization` отдаёт `Any`, и раннер на нём читался бы как цепочка
/// `as?` с `!` на конце: опечатка в имени поля превращалась бы в падение без
/// объяснения, какое поле и в каком случае. Здесь каждый доступ либо возвращает
/// значение, либо бросает ошибку с путём до него.
import Foundation

enum JSONValue {
    case string(String)
    case number(NSNumber)
    case bool(Bool)
    case array([JSONValue])
    case object([String: JSONValue])
    case null

    init(_ raw: Any) {
        switch raw {
        case let value as [Any]:
            self = .array(value.map(JSONValue.init))
        case let value as [String: Any]:
            self = .object(value.mapValues(JSONValue.init))
        case let value as String:
            self = .string(value)
        case let value as NSNumber:
            // `JSONSerialization` заворачивает и числа, и булевы в `NSNumber`:
            // без этой проверки `deriveSafe: false` неотличим от `0`, а весь
            // смысл флага в том, что «нет флага» — ошибка, а не «не надо».
            self = CFGetTypeID(value) == CFBooleanGetTypeID()
                ? .bool(value.boolValue)
                : .number(value)
        default:
            self = .null
        }
    }
}

struct VectorError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

extension JSONValue {
    /// Строковое представление для сравнений с тем, что вернуло ядро.
    var described: String {
        switch self {
        case let .string(value): return value
        case let .number(value): return value.stringValue
        case let .bool(value): return String(value)
        case .array, .object: return "<composite>"
        case .null: return "null"
        }
    }

    var keys: [String] {
        guard case let .object(fields) = self else { return [] }
        return Array(fields.keys)
    }

    func child(_ key: String) throws -> JSONValue {
        guard case let .object(fields) = self else {
            throw VectorError("\(key): parent is not an object")
        }
        guard let value = fields[key] else {
            throw VectorError("\(key): missing")
        }
        return value
    }

    /// Спускается по пути. Один вызов на секцию — путь целиком едет в ошибку.
    func section(_ path: String...) throws -> JSONValue {
        var node = self
        for step in path {
            node = try node.child(step)
        }
        guard case .object = node else {
            throw VectorError("\(path.joined(separator: ".")) is not an object")
        }
        return node
    }

    /// Непустой массив случаев: пустая секция ничего не ловит.
    func cases(_ path: String...) throws -> [JSONValue] {
        var node = self
        for step in path {
            node = try node.child(step)
        }
        guard case let .array(items) = node, !items.isEmpty else {
            throw VectorError("\(path.joined(separator: ".")) is not a non-empty array")
        }
        return items
    }

    func text(_ key: String) throws -> String {
        guard case let .string(value) = try child(key) else {
            throw VectorError("field \(key) is not a string")
        }
        return value
    }

    func num(_ key: String) throws -> Int {
        guard case let .number(value) = try child(key) else {
            throw VectorError("field \(key) is not a number")
        }
        return value.intValue
    }

    func flag(_ key: String) throws -> Bool {
        guard case let .bool(value) = try child(key) else {
            throw VectorError("field \(key) is not a boolean")
        }
        return value
    }

    func has(_ key: String) -> Bool {
        guard case let .object(fields) = self else { return false }
        return fields[key] != nil
    }

    /// Байтовое поле файла. Регистр проверяется, а не нормализуется: файл,
    /// наполовину переехавший в верхний регистр, разошёлся бы с раннером на Rust
    /// молча, потому что `hex::decode` принимает оба.
    func bytes(_ key: String) throws -> Data {
        try unhex(text(key), what: key)
    }
}

func unhex(_ value: String, what: String) throws -> Data {
    let isLowerHex = { (c: Character) in ("0"..."9").contains(c) || ("a"..."f").contains(c) }
    guard value.count % 2 == 0, value.allSatisfy(isLowerHex) else {
        throw VectorError("\(what) is not lowercase hex of even length: \(value.prefix(32))")
    }
    var out = Data(capacity: value.count / 2)
    var index = value.startIndex
    while index < value.endIndex {
        let next = value.index(index, offsetBy: 2)
        guard let byte = UInt8(value[index..<next], radix: 16) else {
            throw VectorError("\(what) is not hex")
        }
        out.append(byte)
        index = next
    }
    return out
}

func hex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}
