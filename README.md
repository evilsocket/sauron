Sauron is a minimalistic, YARA based malware scanner with realtime filesystem monitoring written in Rust.

## Features

* Realtime scan of created and modified files supporting Linux `inotify`, macOS `FSEvents`, Windows `ReadDirectoryChanges` and polling for other platforms.
* YARA engine complete support.
* Single scan mode to scan a folder, report results and exit.
* Parallel scanning using a configurable thread pool.
* Log, text and JSON reporting.

### Known Limitations

Due to the filesystem monitoring mechanism, Sauron is extremely lightweight and non invasive as more sophisticated AV solutions, however this comes with the following limitations:

* Scanning files with an exclusive lock by other processes will likely fail with a `Permission Denied` error.
* Malicious files creation and execution won't be blocked but just reported.
* [Fileless malware](https://en.wikipedia.org/wiki/Fileless_malware) won't be detected.
* Detected files won't be linked to originating processes.

## Building

```sh
cargo build --release
```

### Dependencies

Your system must have `libssl-dev` installed. For Ubuntu-derivatives this can be installed via `sudo apt install libssl-dev`. 

## Running 

Assuming you have your YARA rules in `./yara-rules` (you can find [plenty of free rules](https://github.com/InQuest/awesome-yara) online):

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

## Reporting

Various options are available for reporting:

* `--report-clean` will also report clean files.
* `--report-errors` explicitly report errors (reported as debug logs by default).
* `--report-output <FILENAME>` will write scan reports to a file.
* `--report-json` if `--report-output` is passed, write as JSON instead of text.

## Other options

Run `sauron --help` for the complete list of options. 

## License

This project is made with ♥  by [@evilsocket](https://twitter.com/evilsocket) and it is released under the GPL3 license.
