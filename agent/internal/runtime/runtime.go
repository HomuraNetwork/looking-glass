package runtime

// Version is the human-facing, semver-style agent version, used in logs and
// `--version` only. It is not a reliable build identity (one semver can cover
// many commits; this constant is not bumped on every change).
const Version = "0.3.0"

// BuildID identifies this exact agent build, normally the short git commit it
// was built from. It is injected at build time via
//
//	-ldflags "-X hlg/internal/runtime.BuildID=<id>"
//
// A node reports it so the controller can tell whether the node runs the same
// build it currently distributes (a differing BuildID means an upgrade is
// available). It stays "unknown" for a plain `go build`/`go run`.
var BuildID = "unknown"

var Capabilities = []string{
	"generate204",
	"download",
	"ping",
	"mtr",
	"traceroute",
	"nexttrace",
	"iperf3",
}
