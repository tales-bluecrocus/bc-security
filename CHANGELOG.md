# [](https://github.com/tales-bluecrocus/bc-security/compare/v2.2.2...v) (2026-03-30)


### Bug Fixes

* use button click instead of form.submit() for reCAPTCHA re-submission ([e0dedac](https://github.com/tales-bluecrocus/bc-security/commit/e0dedaccaee93e3eec09b3ba4b9e0903db15b404))

## [2.2.2](https://github.com/tales-bluecrocus/bc-security/compare/v2.2.1...v2.2.2) (2026-03-26)


### Bug Fixes

* handle blocked_keywords as array or string in sanitize_settings ([6cc29ff](https://github.com/tales-bluecrocus/bc-security/commit/6cc29ff5c3b86dfd97d9f1d79c33cfb789fee56b))

## [2.2.1](https://github.com/tales-bluecrocus/bc-security/compare/v2.2.0...v2.2.1) (2026-03-26)


### Bug Fixes

* guard sanitize_settings against null input ([fc6625b](https://github.com/tales-bluecrocus/bc-security/commit/fc6625b7685fa405b9e8c7aaac4ef1d29a5cb65c))

# [2.2.0](https://github.com/tales-bluecrocus/bc-security/compare/v2.1.1...v2.2.0) (2026-03-26)


### Features

* add CAPTCHA settings section to admin page ([773eefa](https://github.com/tales-bluecrocus/bc-security/commit/773eefa1cf7903c4f9c65b876d9cf7875a199658))
* add CaptchaProvider class with reCAPTCHA v3 and Turnstile support ([47e8001](https://github.com/tales-bluecrocus/bc-security/commit/47e80014e2dc2dc7097c5426a7de3dfc7c8d3bdc))
* add optional CAPTCHA verification to login authentication ([44273b4](https://github.com/tales-bluecrocus/bc-security/commit/44273b498093da2fa65abbc99ca17933373b4ddb))
* block non-existent username login attempts immediately ([c13642d](https://github.com/tales-bluecrocus/bc-security/commit/c13642dcb4e0a2c861d74ee3720dc7c8fb8f7123))
* integrate CAPTCHA verification into SpamFilter validation flow ([e57f425](https://github.com/tales-bluecrocus/bc-security/commit/e57f425890241b035f9b5d368055d2ff7de80c40))
* wire CaptchaProvider into bootstrap and update documentation ([dfe0642](https://github.com/tales-bluecrocus/bc-security/commit/dfe0642107db7448085a060b14f673072853ac05))

## [2.1.1](https://github.com/tales-bluecrocus/bc-security/compare/v2.1.0...v2.1.1) (2026-03-26)


### Features

* expand default blocked keywords to 140+ spam patterns ([7fb0b49](https://github.com/tales-bluecrocus/bc-security/commit/7fb0b49983ff87d481fc243427199ca5efba84dd))

# [2.1.0](https://github.com/tales-bluecrocus/bc-security/compare/v2.0.1...v2.1.0) (2026-03-26)


### Features

* add AdminPage class with settings and logs tabs ([e22deb2](https://github.com/tales-bluecrocus/bc-security/commit/e22deb2962fdd9d5eca3f855fe05613bf55038c6))
* add Database class for bc_form_logs table migration ([2ecca96](https://github.com/tales-bluecrocus/bc-security/commit/2ecca96fca32f46cdf593760f53c2c5386a109a7))
* add FormLogger class for form submission logging ([9cc5821](https://github.com/tales-bluecrocus/bc-security/commit/9cc58219409be9318f8b681af06ec53dd1d129cb))
* add LogsTable class for admin log display ([bd72313](https://github.com/tales-bluecrocus/bc-security/commit/bd72313be9b0265983f6d65519388d539f28b362))
* add SpamFilter class with honeypot and keyword filtering ([16c0b81](https://github.com/tales-bluecrocus/bc-security/commit/16c0b81bf34169586de15a6a340ed798e67bd32b))
* wire spam protection into bootstrap ([0fa32d8](https://github.com/tales-bluecrocus/bc-security/commit/0fa32d85376c05b5201e0d1ae65eaeb9f889059a))

## [2.0.1](https://github.com/tales-bluecrocus/bc-security/compare/81f80fc8f7a600b70d8704122e9a05f0a7fe615b...v2.0.1) (2026-03-25)


### Features

* add BruteForce class for login rate limiting ([27552db](https://github.com/tales-bluecrocus/bc-security/commit/27552dbf5f66894762ca401e2d1ad9a68fd903ba))
* add CHANGELOG.md check to create-release.sh ([01345ac](https://github.com/tales-bluecrocus/bc-security/commit/01345acc848011ba0cabd27bd505d019d5e31ad6))
* add Composer PSR-4 autoload config ([81f80fc](https://github.com/tales-bluecrocus/bc-security/commit/81f80fc8f7a600b70d8704122e9a05f0a7fe615b))
* add IpResolver class for client IP detection ([9234c0f](https://github.com/tales-bluecrocus/bc-security/commit/9234c0f123d0a79c03c3f7862de2be97bdef5494))
* add release flow with GitHub Actions and auto-update ([44c8aa4](https://github.com/tales-bluecrocus/bc-security/commit/44c8aa44ca4b490c5b7d80d80895b7b25783d491))
* add UserEnumeration class for user discovery protection ([8394cee](https://github.com/tales-bluecrocus/bc-security/commit/8394ceeaa4cf0871eaa2d8f9d665af709090bd8d))
