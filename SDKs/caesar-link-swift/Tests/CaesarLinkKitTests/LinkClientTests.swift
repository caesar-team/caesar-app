import XCTest

@testable import CaesarLinkKit

/// The upload form is the one place where this kit has to match the server's parser exactly.
/// It shipped untested and promptly got `views` wrong, so it is pinned down here.
final class LinkClientTests: XCTestCase {
    private func fields(views: Int?) -> [String: String] {
        let built = LinkClient.formFields(meta: #"{"iv":"AAA"}"#, ttlSeconds: 3_600, views: views)
        return Dictionary(uniqueKeysWithValues: built.map { ($0.name, $0.value) })
    }

    /// Unlimited views is expressed by **omitting** the field. The server maps a missing
    /// value to `null` (unlimited) but rejects an empty string with
    /// "views must be a positive integer" — sending `views=""` was a real 400 in the app.
    func testUnlimitedViewsOmitsTheField() {
        let form = fields(views: nil)
        XCTAssertNil(form["views"])
        XCTAssertEqual(form["ttl"], "3600")
        XCTAssertEqual(form["meta"], #"{"iv":"AAA"}"#)
    }

    func testBurnAfterReadingSendsOne() {
        XCTAssertEqual(fields(views: 1)["views"], "1")
    }

    func testExplicitCountIsSentVerbatim() {
        // The server parses with String(parsed) == raw, so no padding or "+7" forms.
        XCTAssertEqual(fields(views: 7)["views"], "7")
    }

    func testFieldOrderIsStable() {
        let names = LinkClient.formFields(meta: "{}", ttlSeconds: 60, views: 2).map(\.name)
        XCTAssertEqual(names, ["meta", "ttl", "views"])
    }
}
