# Runtime loader dependency verification

The company package verifier supports the exact x86-64 loader SONAME
`ld-linux-x86-64.so.2` in a signed runc dependency inventory. The current
libpathrs build references the loader's versioned `__tls_get_addr` symbol;
the retained linker map and distribution linker script explain that dependency.

This does not change the required interpreter, which remains
`/lib64/ld-linux-x86-64.so.2`, or the private library search path,
`/usr/lib64/doxentriq-runtime`. The binary's complete dependency set must match
the independently authenticated package inventory. An omitted loader, alternate
loader, path in place of a SONAME, changed interpreter or changed search path
is refused. The private libseccomp library must still depend only on libc.
Neither verification nor package staging executes the inspected binaries.

On November 8, 2026, the updated verifier checked the actual compiled runc and
libseccomp bytes successfully; the previous verifier rejected the pair. Seven
data checks covered that transition and altered expectations. A further 54
Linux tests passed without skips across ELF parsing, protected package readback
and private RPM producer staging. Those tests used inert fixture binaries and
synthetic OS command responses.

The current runc candidate requires symbols through `GLIBC_2.38`. These results
do not establish compatibility with Debian 12 or Rocky Linux 9, qualify execution
on Rocky Linux 10.2, or approve a release. Each supported OS still needs an
exact qualified package profile and behavior tests. Installation, signatures,
security coverage and reboot recovery remain separate release requirements.
