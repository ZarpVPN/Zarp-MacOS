import Foundation

/// Catalog applicability tags. These are not measurements of ISP effectiveness.
public enum StrategyCountry: String, CaseIterable, Codable, Hashable, Sendable {
    case ru, ir, cn
}

public enum StrategyFilter {
    public static func countries(_ value: String) -> Set<StrategyCountry> {
        Set(value.lowercased().split(separator: ",").compactMap {
            StrategyCountry(rawValue: $0.trimmingCharacters(in: .whitespaces))
        })
    }

    public static func normalize(_ value: String) -> String {
        let selected = countries(value)
        let codes = StrategyCountry.allCases.filter { selected.contains($0) }.map(\.rawValue)
        return codes.isEmpty ? "all" : codes.joined(separator: ",")
    }

    public static func toggle(_ value: String, country: StrategyCountry) -> String {
        var selected = countries(value)
        if !selected.insert(country).inserted { selected.remove(country) }
        return normalize(selected.map(\.rawValue).joined(separator: ","))
    }

    public static func matches(_ strategy: Strategy, value: String) -> Bool {
        let selected = countries(value)
        return selected.isEmpty || (strategy.requiresDesync && !strategy.countries.isDisjoint(with: selected))
    }
}
