package catalog

// HotReadPaths are read by every process through NSS, the dynamic loader, TLS or the time
// zone code. A read watch on them, or on a directory that holds them, fills a
// disk within minutes. Rule 119005 drops the same reads on the manager.
var HotReadPaths = []string{
	"/etc/passwd",
	"/etc/group",
	"/etc/nsswitch.conf",
	"/etc/hosts",
	"/etc/host.conf",
	"/etc/resolv.conf",
	"/etc/gai.conf",
	"/etc/services",
	"/etc/protocols",
	"/etc/shells",
	"/etc/login.defs",
	"/etc/localtime",
	"/etc/ld.so.cache",
	"/etc/ld.so.conf",
	"/etc/ld.so.conf.d",
	"/etc/ssl/certs",
	"/etc/ca-certificates",
	"/etc/pki/ca-trust",
	"/usr",
	"/lib",
	"/lib64",
}
