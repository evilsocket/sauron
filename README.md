Sauron is a minimalistic cross-platform malware scanner with non-blocking realtime filesystem monitoring using YARA rules, written in Rust.

## Building

```sh
cargo build --release
```

## Running

Assuming you have your YARA rules in `./yara-rules` (you can find [plenty](https://github.com/elastic/protections-artifacts) of [free rules](https://github.com/Yara-Rules/rules) online):

```sh
sudo ./target/release/sauron --rules ./yara-rules
```

![screenshot](https://i.imgur.com/Dw5N9RR.png)

## License

This project is made with ♥  by [@evilsocket](https://twitter.com/evilsocket) and it is released under the GPL3 license.