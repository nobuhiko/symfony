# Symfony 2.7 components with security fixes, for EC-CUBE 3.0.x

[![tests](https://github.com/umiushi-lab/symfony/actions/workflows/tests.yml/badge.svg?branch=eccube3%2F2.7)](https://github.com/umiushi-lab/symfony/actions/workflows/tests.yml) [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/umiushi-lab/symfony/badge)](https://scorecard.dev/viewer/?uri=github.com/umiushi-lab/symfony)

EC-CUBE 3.0.18 requires Symfony `>=2.7,<2.8`. Symfony 2.7 reached its end of life in 2019. This package carries eleven components at 2.7.52 with the security fixes published since then backported.

## Fixed

| Component | Advisories |
|---|---|
| http-foundation | CVE-2025-64500, CVE-2026-135801 (2.7.52-p2: a bypass of the CVE-2025-64500 fix), CVE-2024-50345, CVE-2019-18888, CVE-2026-118514, GHSA-5mx8-mwrp-5693 |
| http-kernel | CVE-2022-24894, CVE-2019-18887 |
| routing | CVE-2026-45065, CVE-2026-48784 |
| validator | CVE-2024-50343, CVE-2026-123125 |
| yaml | CVE-2026-45133, CVE-2026-109413, CVE-2026-45304, CVE-2026-45305, CVE-2026-123792 |
| serializer | CVE-2026-118515 |
| twig-bridge | CVE-2023-46734 |
| dom-crawler | CVE-2026-45071 |
| config | CVE-2026-123824 |
| process | CVE-2024-51736, CVE-2026-24739 (Windows only; not exercised, the test environment is Linux) |

Not applicable to 2.7 (the code does not exist): CVE-2026-45077 (monolog-bridge has no `server:log` command or handler), CVE-2026-121623 (serializer has no `DataUriNormalizer`). monolog-bridge is included unchanged so that the whole set comes from one place.

Where this differs from upstream:

- yaml: the 2.7 parser copies nested blocks at each nesting level. Instead of the upstream in-place reader, the summed size of the open nested blocks is bounded (about 16 MB), on top of the upstream limits on nesting depth and aliases.
- http-kernel: `UriSigner` compares in constant time without requiring `symfony/polyfill-php56`.
- serializer: 2.7 has no `DataUriNormalizer`; the object normalizers refuse to build `SplFileInfo` objects.

The other Symfony 2.7 components EC-CUBE uses (form, security, console and so on) have no applicable advisory and stay on the official packages.

## Install

Requires Composer 2. In the shop's project root:

```
composer require umiushi-lab/symfony:^2.7.52
```

The package `replace`s the eleven `symfony/*` packages, so Composer removes the original and every other package keeps working against the same version.
EC-CUBE 3.0.18's own `composer.json` lists `mikey179/vfsStream` in `require-dev`; Composer 2 only accepts it in lowercase (`mikey179/vfsstream`), so fix that line first.

## What this is, and is not

- The base is exactly the version EC-CUBE 3.0.18 ships. Nothing is upgraded; only security fixes are added, each as its own commit on the `eccube3/2.7` branch.
- Each fix whose weakness could be reproduced on the base version was checked with a script that uses the weakness before the fix and fails to use it after, on PHP 5.6, 7.1 and 7.3. A few could not be reproduced there (Windows-only code, and cases the old code happened not to reach); those are ported as hardening. PHP 5.3 to 5.5 were not run (the changes avoid syntax newer than 5.3).
- This is not an official release of the upstream project and is not supported by its maintainers. Upstream: https://github.com/symfony/symfony
- EC-CUBE 3 と、その部品の古い系列には、もう公式の修正が出ません。3.0.18 が使っているバージョンのまま、上流の修正だけを移したものです。保守: うみうしラボ
