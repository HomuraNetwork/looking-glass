# Third-Party Notices

HLG's original code is licensed under the MIT License in [LICENSE](LICENSE).
The following third-party code and independent programs retain their upstream
licenses.

## shadcn/ui

Frontend components in `controller/frontend/src/components/ui/` are derived
from [shadcn/ui](https://github.com/shadcn-ui/ui). Its full license follows.

MIT License

Copyright (c) 2023 shadcn

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Build dependencies and release artifacts

npm and Go dependencies are resolved during the build; their sources are not
vendored in this repository. Builds collect their upstream license and notice
texts automatically:

- The frontend/Controller distribution provides `THIRD_PARTY_LICENSES.txt`,
  served at `/THIRD_PARTY_LICENSES.txt`.
- The Agent embeds HLG's MIT license, Go's runtime notices, and the notices for
  linked Go dependencies. Run `hlg-agent licenses` to read them.
- HLG's independently distributed iPerf3 binaries include the complete
  `LICENSE` from the same pinned source archive used to compile them. That text
  is included in the Controller's `THIRD_PARTY_LICENSES.txt`. The dependency
  manifest and binary download headers identify this accompanying material.

The static iPerf3 builds use Debian-provided glibc without HLG modifications.
The generated distribution notices include the C runtime's copyright and
license texts, plus the actual package versions and corresponding source
locations for each architecture.

## NextTrace

HLG optionally downloads and executes
[NextTrace](https://github.com/nxtrace/NTrace-core) as an independent external
program, directly from its upstream releases. HLG does not incorporate or
redistribute its executable. NextTrace is separately licensed by its upstream
project; HLG's MIT license does not apply to it.
