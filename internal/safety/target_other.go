//go:build !linux

package safety

// ResolveTarget reports an unknown destination on platforms this release
// does not target. Unknown fails closed, so a mutation cannot proceed by
// default on an unsupported platform.
func ResolveTarget(dir string) Target {
	return Target{Dir: dir, Detail: "destination inspection is not supported on this platform"}
}
