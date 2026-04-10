# sing-box-extended

Sing-box with extended features.

## Разработка в форке ne-tort (AWG / sing-box)

Исходники в этом каталоге — **часть репозитория [`ne-tort/hiddify-core`](https://github.com/ne-tort/hiddify-core)** (`replace github.com/sagernet/sing-box => ./hiddify-sing-box` в корневом `go.mod`). Правки **AmneziaWG** (`transport/awg`, `protocol/awg`, `option`, DNS и т.д.) вносятся **здесь**, затем коммит и push в **hiddify-core**. Клиент [`ne-tort/hiddify-app`](https://github.com/ne-tort/hiddify-app) подтягивает ядро **сабмодулем** `hiddify-core` — отдельная папка `sing-box-amnezia` для правок ядра **не нужна** (там при желании только Docker-стенд). Сборка с AWG: теги сборки включают `with_awg` (см. `Makefile` в корне hiddify-core).

## Features

* Amnezia 1.5
* WARP
* Tunneling
* Mieru
* XHTTP
* SDNS (DNSCrypt)
* Extended Wireguard options
* Unified delay

## Examples

https://github.com/shtorm-7/sing-box-extended/tree/extended/examples

## License

```
Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

In addition, no derivative work may use the name or imply association
with this application without prior consent.
```
