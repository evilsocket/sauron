Sauron is a minimalistic cross-platform malware scanner with non-blocking realtime filesystem monitoring using YARA rules, written in Rust.

## Building

```sh
cargo build --release
```

### Dependencies

Your system must have `libssl-dev` installed. For Ubuntu-derivatives this can be installed via `sudo apt install libssl-dev`. 

## Running 

Assuming you have your YARA rules in `./yara-rules` (you can find [plenty](https://github.com/elastic/protections-artifacts) of [free rules](https://github.com/Yara-Rules/rules) online):

```sh
sudo ./target/release/sauron --rules ./yara-rules
```

![screenshot](https://i.imgur.com/Dw5N9RR.png)

## Single Scan

Alternatively you can perform a one-time recursive scan of the specified folder using the `--scan` argument:

```sh
sudo ./target/release/sauron --rules ./yara-rules --scan --root /path/to/scan
```

You can specify which file extensions to scan (all by default) with the `--ext` argument:

```sh
sudo ./target/release/sauron \
    --rules ./yara-rules \
    --scan \
    --root /path/to/scan \
    --ext exe \
    --ext elf \
    --ext doc \
    --ext docx
```

## License

This project is made with ♥  by [@evilsocket](https://twitter.com/evilsocket) and it is released under the GPL3 license.
