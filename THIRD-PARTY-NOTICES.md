# Third-party notices

Strata itself is MIT-licensed (see [`LICENSE`](LICENSE)). It includes the following third-party software.

## libyara 4.5.8

- Source: <https://github.com/VirusTotal/yara> (release v4.5.8), vendored in [`Vendor/yara`](Vendor/yara) by [`scripts/vendor-yara.sh`](scripts/vendor-yara.sh), which pins the tarball by SHA-256.
- Used for: running Apple's XProtect YARA rules against app binaries and launch items.
- License: BSD-3-Clause. The full text below is identical to [`Vendor/yara/COPYING`](Vendor/yara/COPYING).

```
Copyright (c) 2007-2016. The YARA Authors. All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## TLSH (C port bundled inside libyara)

- Location: [`Vendor/yara/libyara/tlshc`](Vendor/yara/libyara/tlshc) (`tlsh.c`, `tlsh_impl.c`, `tlsh_util.c` and headers), used by libyara's `elf` module (telfhash).
- License: the libyara 4.5.8 release carries no separate TLSH license or notice file, and the TLSH sources have no license headers of their own. No separate license file ships in the libyara 4.5.8 release for the TLSH C port; see upstream TLSH (<https://github.com/trendmicro/tlsh>) for its own terms.
