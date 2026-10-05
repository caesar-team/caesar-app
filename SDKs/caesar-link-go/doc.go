// Package caesarlink is a Go client for Caesar Link, a zero-knowledge secret-sharing
// service (https://link.bshk.app).
//
// Everything is encrypted locally with AES-256-GCM. The server stores ciphertext and a
// public IV — never the plaintext, file names or the key. The key travels in the URL
// #fragment, which is never sent to a server.
//
//	c := caesarlink.NewClient(caesarlink.DefaultBaseURL)
//	created, err := c.Create(ctx, caesarlink.TextPayload("s3cret"), caesarlink.CreateOptions{
//		TTL:   time.Hour,
//		Views: 1, // burn after reading
//	})
//	// created.URL → https://link.bshk.app/s/<id>#k.<key>
//
//	payload, err := c.Open(ctx, created.URL, "")
//
// Wire-compatible with the TypeScript (@caesar/link-sdk) and Swift (CaesarLinkKit) SDKs,
// proven by the shared golden vectors in packages/link-sdk/vectors. The wire format is
// specified in SDKs/caesar-link-swift/PROTOCOL.md.
package caesarlink
