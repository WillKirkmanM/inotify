use clap::Parser;
use std::num::NonZeroU64;
use std::path::PathBuf;
use std::process::ExitCode;

const EVENT_BITS: [(&str, u32); 12] = [
    ("IN_ACCESS", 0x0001),
    ("IN_MODIFY", 0x0002),
    ("IN_ATTRIB", 0x0004),
    ("IN_CLOSE_WRITE", 0x0008),
    ("IN_CLOSE_NOWRITE", 0x0010),
    ("IN_OPEN", 0x0020),
    ("IN_MOVED_FROM", 0x0040),
    ("IN_MOVED_TO", 0x0080),
    ("IN_CREATE", 0x0100),
    ("IN_DELETE", 0x0200),
    ("IN_DELETE_SELF", 0x0400),
    ("IN_MOVE_SELF", 0x0800),
];

#[derive(Parser)]
#[command(
    version,
    about = "Stream Linux file and directory change events",
    after_help = "All watches are installed before events are processed. Directory watches cover\
                  \nimmediate children without recursion. Watches follow inodes, including activity\
                  \nthrough other hard links; replacing a pathname does not reattach its watch.\
                  \nPaths sharing an inode share a watch and use the first supplied path in output.\
                  \n\
                  \nRecords contain tab-separated PATH, FLAGS, COOKIE and an optional CHILD, with\
                  \nno header. Flags are joined with '|'; cookies are decimal and retained in kernel\
                  \norder. Move pairs need not be adjacent or both present. Fields use ASCII byte\
                  \nescapes: \\\\, \\t, \\n, \\r and \\xNN for other control or non-ASCII bytes.\
                  \nEach record is flushed. Queue overflow uses '-' as its path and is fatal.\
                  \nIN_UNMOUNT and IN_IGNORED are always reported; losing every watch is fatal.\
                  \n\
                  \nThe kernel may coalesce identical unread events, so records cannot reliably\
                  \ncount filesystem operations. Limits count kernel records, including watch\
                  \nremoval and unmount events, and elapsed monitoring time after watch installation."
)]
struct Arguments {
    #[arg(required = true, num_args = 1.., value_name = "PATH", help = "Files or directories to watch")]
    paths: Vec<PathBuf>,

    #[arg(
        long,
        value_name = "NAMES",
        default_value = "IN_ACCESS,IN_MODIFY,IN_ATTRIB,IN_CLOSE_WRITE,IN_CLOSE_NOWRITE,IN_OPEN,IN_MOVED_FROM,IN_MOVED_TO,IN_CREATE,IN_DELETE,IN_DELETE_SELF,IN_MOVE_SELF",
        value_parser = parse_events,
        help = "Comma-separated individual IN_ALL_EVENTS names (all twelve by default)"
    )]
    events: u32,

    #[arg(
        long,
        value_name = "MILLISECONDS",
        help = "Stop after a positive monitoring duration, even without events"
    )]
    duration_ms: Option<NonZeroU64>,

    #[arg(
        long,
        value_name = "COUNT",
        help = "Stop after a positive number of kernel event records"
    )]
    max_events: Option<NonZeroU64>,
}

fn parse_events(value: &str) -> Result<u32, String> {
    let mut mask = 0;
    for name in value.split(',').map(str::trim) {
        if name.is_empty() {
            return Err("event selections must not be empty".into());
        }
        let bit = EVENT_BITS
            .iter()
            .find(|(candidate, _)| *candidate == name)
            .ok_or_else(|| {
                format!(
                    "unknown event '{}'; use individual names from --help",
                    escape(name.as_bytes())
                )
            })?
            .1;
        mask |= bit;
    }
    Ok(mask)
}

fn escape(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut escaped = String::new();
    for &byte in bytes {
        match byte {
            b'\\' => escaped.push_str("\\\\"),
            b'\t' => escaped.push_str("\\t"),
            b'\n' => escaped.push_str("\\n"),
            b'\r' => escaped.push_str("\\r"),
            b' '..=b'~' => escaped.push(char::from(byte)),
            _ => {
                escaped.push_str("\\x");
                escaped.push(char::from(HEX[usize::from(byte >> 4)]));
                escaped.push(char::from(HEX[usize::from(byte & 15)]));
            }
        }
    }
    escaped
}

#[cfg(any(target_os = "linux", test))]
mod stream {
    use super::{EVENT_BITS, NonZeroU64, escape};
    use std::collections::BTreeMap;
    use std::io::Write;
    use std::time::Duration;

    pub const IN_UNMOUNT: u32 = 0x2000;
    pub const IN_Q_OVERFLOW: u32 = 0x4000;
    pub const IN_IGNORED: u32 = 0x8000;
    const EXTRA_BITS: [(&str, u32); 4] = [
        ("IN_UNMOUNT", IN_UNMOUNT),
        ("IN_Q_OVERFLOW", IN_Q_OVERFLOW),
        ("IN_IGNORED", IN_IGNORED),
        ("IN_ISDIR", 0x4000_0000),
    ];

    #[derive(Debug, PartialEq)]
    pub struct Event<'a> {
        pub wd: i32,
        pub mask: u32,
        pub cookie: u32,
        pub name: Option<&'a [u8]>,
    }

    pub fn decode(bytes: &[u8]) -> Result<(Event<'_>, &[u8]), String> {
        let header = bytes.get(..16).ok_or("truncated inotify event header")?;
        let word = |offset| {
            u32::from_ne_bytes([
                header[offset],
                header[offset + 1],
                header[offset + 2],
                header[offset + 3],
            ])
        };
        let length = usize::try_from(word(12)).map_err(|_| "inotify name length is too large")?;
        let end = 16usize
            .checked_add(length)
            .ok_or("inotify name length overflow")?;
        let field = bytes.get(16..end).ok_or("truncated inotify event name")?;
        let name = if field.is_empty() {
            None
        } else {
            let end = field
                .iter()
                .position(|&byte| byte == 0)
                .ok_or("unterminated inotify event name")?;
            Some(&field[..end])
        };
        Ok((
            Event {
                wd: word(0) as i32,
                mask: word(4),
                cookie: word(8),
                name,
            },
            &bytes[end..],
        ))
    }

    fn flags(mask: u32) -> String {
        let mut names = Vec::new();
        let mut remaining = mask;
        for &(name, bit) in EVENT_BITS.iter().chain(EXTRA_BITS.iter()) {
            if mask & bit != 0 {
                names.push(name.to_owned());
                remaining &= !bit;
            }
        }
        if remaining != 0 || names.is_empty() {
            names.push(format!("0x{remaining:08x}"));
        }
        names.join("|")
    }

    pub fn poll_timeout(limit: Option<Duration>, elapsed: Duration) -> Option<i32> {
        let Some(limit) = limit else { return Some(-1) };
        let remaining = limit.checked_sub(elapsed)?;
        if remaining.is_zero() {
            return None;
        }
        Some(
            remaining
                .as_nanos()
                .div_ceil(1_000_000)
                .min(i32::MAX as u128) as i32,
        )
    }

    pub struct Stream {
        pub watches: BTreeMap<i32, String>,
        pub max_events: Option<NonZeroU64>,
        pub count: u64,
    }

    impl Stream {
        pub fn emit(&mut self, event: Event<'_>, output: &mut impl Write) -> Result<bool, String> {
            let overflow = event.mask & IN_Q_OVERFLOW != 0;
            let path = if overflow {
                "-"
            } else {
                self.watches
                    .get(&event.wd)
                    .ok_or_else(|| format!("event for unknown watch descriptor {}", event.wd))?
            };
            let flags = flags(event.mask);
            let record = if let Some(name) = event.name {
                writeln!(
                    output,
                    "{path}\t{flags}\t{}\t{}",
                    event.cookie,
                    escape(name)
                )
            } else {
                writeln!(output, "{path}\t{flags}\t{}", event.cookie)
            };
            record
                .and_then(|()| output.flush())
                .map_err(|error| format!("cannot write event: {error}"))?;
            if overflow {
                return Err("inotify event queue overflowed; events were lost".into());
            }
            if event.mask & IN_IGNORED != 0 {
                self.watches.remove(&event.wd);
                if self.watches.is_empty() {
                    return Err("all watches were removed".into());
                }
            }
            self.count = self.count.saturating_add(1);
            Ok(self
                .max_events
                .is_some_and(|limit| self.count >= limit.get()))
        }
    }
}

#[cfg(target_os = "linux")]
fn run(arguments: Arguments) -> Result<(), String> {
    linux::run(arguments)
}

#[cfg(not(target_os = "linux"))]
fn run(_arguments: Arguments) -> Result<(), String> {
    Err("inotify is only supported on Linux".into())
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{Arguments, escape, stream};
    use std::collections::BTreeMap;
    use std::ffi::{CString, c_char, c_int, c_short, c_ulong};
    use std::fs::File;
    use std::io::{self, ErrorKind, Read};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::time::{Duration, Instant};

    const IN_NONBLOCK: c_int = if cfg!(any(
        target_arch = "mips",
        target_arch = "mips64",
        target_arch = "mips32r6",
        target_arch = "mips64r6"
    )) {
        0x0080
    } else if cfg!(any(target_arch = "sparc", target_arch = "sparc64")) {
        0x4000
    } else {
        0x0800
    };
    const IN_CLOEXEC: c_int = if cfg!(any(target_arch = "sparc", target_arch = "sparc64")) {
        0x400000
    } else {
        0x080000
    };
    const POLLIN: c_short = 0x0001;
    const POLLERR: c_short = 0x0008;
    const POLLHUP: c_short = 0x0010;
    const POLLNVAL: c_short = 0x0020;

    #[repr(C)]
    struct PollFd {
        fd: c_int,
        events: c_short,
        revents: c_short,
    }

    unsafe extern "C" {
        fn inotify_init1(flags: c_int) -> c_int;
        fn inotify_add_watch(fd: c_int, pathname: *const c_char, mask: u32) -> c_int;
        fn poll(fds: *mut PollFd, nfds: c_ulong, timeout: c_int) -> c_int;
    }

    fn open() -> Result<File, String> {
        loop {
            let descriptor = unsafe { inotify_init1(IN_NONBLOCK | IN_CLOEXEC) };
            if descriptor >= 0 {
                return Ok(File::from(unsafe { OwnedFd::from_raw_fd(descriptor) }));
            }
            let error = io::Error::last_os_error();
            if error.kind() != ErrorKind::Interrupted {
                return Err(format!("inotify_init1 failed: {error}"));
            }
        }
    }

    pub fn run(arguments: Arguments) -> Result<(), String> {
        let mut file = open()?;
        let mut watches = BTreeMap::new();
        for path in &arguments.paths {
            let bytes = path.as_os_str().as_bytes();
            let label = escape(bytes);
            let pathname = CString::new(bytes)
                .map_err(|_| format!("watch path '{label}' contains a NUL byte"))?;
            let descriptor = loop {
                let descriptor = unsafe {
                    inotify_add_watch(file.as_raw_fd(), pathname.as_ptr(), arguments.events)
                };
                if descriptor >= 0 {
                    break descriptor;
                }
                let error = io::Error::last_os_error();
                if error.kind() != ErrorKind::Interrupted {
                    return Err(format!(
                        "cannot watch '{label}': inotify_add_watch failed: {error}"
                    ));
                }
            };
            watches.entry(descriptor).or_insert(label);
        }
        let mut stream = stream::Stream {
            watches,
            max_events: arguments.max_events,
            count: 0,
        };
        let duration = arguments
            .duration_ms
            .map(|value| Duration::from_millis(value.get()));
        let started = Instant::now();
        let stdout = io::stdout();
        let mut output = stdout.lock();
        let mut buffer = [0; 65_536];
        loop {
            let Some(timeout) = stream::poll_timeout(duration, started.elapsed()) else {
                return Ok(());
            };
            let mut descriptor = PollFd {
                fd: file.as_raw_fd(),
                events: POLLIN,
                revents: 0,
            };
            let ready = unsafe { poll(&mut descriptor, 1, timeout) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == ErrorKind::Interrupted {
                    continue;
                }
                return Err(format!("poll failed: {error}"));
            }
            if ready == 0 {
                continue;
            }
            if descriptor.revents & (POLLERR | POLLHUP | POLLNVAL) != 0
                || descriptor.revents & POLLIN == 0
            {
                return Err(format!(
                    "poll returned invalid descriptor state 0x{:04x}",
                    descriptor.revents
                ));
            }
            if stream::poll_timeout(duration, started.elapsed()).is_none() {
                return Ok(());
            }
            let length = match file.read(&mut buffer) {
                Ok(0) => return Err("inotify read returned an unexpected end of file".into()),
                Ok(length) => length,
                Err(error)
                    if matches!(error.kind(), ErrorKind::Interrupted | ErrorKind::WouldBlock) =>
                {
                    continue;
                }
                Err(error) => return Err(format!("inotify read failed: {error}")),
            };
            let mut remaining = &buffer[..length];
            while !remaining.is_empty() {
                if stream::poll_timeout(duration, started.elapsed()).is_none() {
                    return Ok(());
                }
                let (event, rest) = stream::decode(remaining)?;
                if stream.emit(event, &mut output)? {
                    return Ok(());
                }
                remaining = rest;
            }
        }
    }
}

fn main() -> ExitCode {
    match run(Arguments::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("inotify: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::stream::{
        Event, IN_IGNORED, IN_Q_OVERFLOW, IN_UNMOUNT, Stream, decode, poll_timeout,
    };
    use super::*;
    use std::collections::BTreeMap;
    use std::io::{self, Write};
    use std::time::Duration;

    fn record(wd: i32, mask: u32, cookie: u32, name: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(wd.to_ne_bytes());
        bytes.extend(mask.to_ne_bytes());
        bytes.extend(cookie.to_ne_bytes());
        bytes.extend((name.len() as u32).to_ne_bytes());
        bytes.extend(name);
        bytes
    }

    fn stream(max_events: Option<u64>) -> Stream {
        Stream {
            watches: BTreeMap::from([(1, "watched".into()), (2, "other".into())]),
            max_events: max_events.map(|value| NonZeroU64::new(value).unwrap()),
            count: 0,
        }
    }

    #[derive(Default)]
    struct Output {
        bytes: Vec<u8>,
        flushes: usize,
    }

    impl Write for Output {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.bytes.extend(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }

    #[test]
    fn event_selection_accepts_individual_bits_and_rejects_empty_or_unknown_names() {
        assert_eq!(
            Arguments::try_parse_from(["inotify", "file"])
                .unwrap()
                .events,
            0x0fff
        );
        assert_eq!(
            parse_events("IN_MODIFY, IN_MOVED_FROM,IN_MODIFY"),
            Ok(0x0042)
        );
        for names in [
            "",
            " ",
            ",",
            "IN_MODIFY,",
            "IN_MODIFY,,IN_OPEN",
            "IN_UNKNOWN",
            "IN_ALL_EVENTS",
            "IN_CLOSE",
        ] {
            assert!(parse_events(names).is_err(), "accepted {names:?}");
        }
        assert!(Arguments::try_parse_from(["inotify", "--events", "IN_UNKNOWN", "file"]).is_err());
    }

    #[test]
    fn paths_and_positive_limits_are_required() {
        assert!(Arguments::try_parse_from(["inotify"]).is_err());
        for option in ["--duration-ms", "--max-events"] {
            for invalid in ["0", "-1", "18446744073709551616", "text"] {
                assert!(Arguments::try_parse_from(["inotify", option, invalid, "file"]).is_err());
            }
            assert!(
                Arguments::try_parse_from(["inotify", option, "1", "file", "directory"]).is_ok()
            );
        }
    }

    #[test]
    fn fields_escape_record_delimiters_backslashes_and_arbitrary_bytes() {
        assert_eq!(
            escape(b"a\tb\nc\r\\\0\x1b\x7f\x80\xff"),
            "a\\tb\\nc\\r\\\\\\x00\\x1b\\x7f\\x80\\xff"
        );
        assert_eq!(escape("café".as_bytes()), "caf\\xc3\\xa9");
    }

    #[test]
    fn decoder_honours_padded_names_and_preserves_separated_move_cookies() {
        let mut bytes = record(1, 0x0040, 987, b"old\0\0\0\0\0");
        bytes.extend(record(2, 0x0002, 0, b""));
        bytes.extend(record(1, 0x0080, 987, b"new\t\xff\0\0\0"));
        let mut remaining = bytes.as_slice();
        let mut stream = stream(Some(3));
        let mut output = Output::default();
        for index in 0..3 {
            let (event, rest) = decode(remaining).unwrap();
            assert_eq!(stream.emit(event, &mut output).unwrap(), index == 2);
            remaining = rest;
        }
        assert!(remaining.is_empty());
        assert_eq!(output.flushes, 3);
        assert_eq!(output.bytes, b"watched\tIN_MOVED_FROM\t987\told\nother\tIN_MODIFY\t0\nwatched\tIN_MOVED_TO\t987\tnew\\t\\xff\n");
    }

    #[test]
    fn decoder_rejects_truncated_or_unterminated_records() {
        let valid = record(1, 0x0100, 0, b"name\0\0\0\0");
        for length in 0..valid.len() {
            assert!(decode(&valid[..length]).is_err(), "accepted {length} bytes");
        }
        assert!(decode(&record(1, 0x0100, 0, b"name")).is_err());
        let mut oversized = valid;
        oversized[12..16].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert!(decode(&oversized).is_err());
        let bytes = record(-1, IN_Q_OVERFLOW, 0, b"");
        assert_eq!(decode(&bytes).unwrap().0.wd, -1);
    }

    #[test]
    fn lifecycle_records_are_flushed_and_losing_the_final_watch_is_fatal() {
        let mut stream = stream(None);
        let mut output = Output::default();
        for (wd, mask) in [(1, IN_UNMOUNT), (1, IN_IGNORED)] {
            assert!(
                !stream
                    .emit(
                        Event {
                            wd,
                            mask,
                            cookie: 0,
                            name: None
                        },
                        &mut output
                    )
                    .unwrap()
            );
        }
        assert_eq!(stream.watches.len(), 1);
        stream.max_events = NonZeroU64::new(3);
        let error = stream
            .emit(
                Event {
                    wd: 2,
                    mask: IN_IGNORED,
                    cookie: 0,
                    name: None,
                },
                &mut output,
            )
            .unwrap_err();
        assert_eq!(error, "all watches were removed");
        assert_eq!(output.flushes, 3);
        assert_eq!(
            output.bytes,
            b"watched\tIN_UNMOUNT\t0\nwatched\tIN_IGNORED\t0\nother\tIN_IGNORED\t0\n"
        );
    }

    #[test]
    fn overflow_is_reported_before_failure_even_at_the_event_limit() {
        let mut stream = stream(Some(1));
        let mut output = Output::default();
        let error = stream
            .emit(
                Event {
                    wd: -1,
                    mask: IN_Q_OVERFLOW,
                    cookie: 0,
                    name: None,
                },
                &mut output,
            )
            .unwrap_err();
        assert!(error.contains("overflowed"));
        assert_eq!(output.bytes, b"-\tIN_Q_OVERFLOW\t0\n");
        assert_eq!(output.flushes, 1);
    }

    #[test]
    fn output_errors_and_unknown_watches_are_fatal() {
        struct BrokenOutput;
        impl Write for BrokenOutput {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed output"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut stream = stream(None);
        let event = Event {
            wd: 1,
            mask: 0x0002,
            cookie: 0,
            name: None,
        };
        assert!(
            stream
                .emit(event, &mut BrokenOutput)
                .unwrap_err()
                .contains("cannot write event")
        );
        let event = Event {
            wd: 99,
            mask: 0x0002,
            cookie: 0,
            name: None,
        };
        assert!(
            stream
                .emit(event, &mut Vec::new())
                .unwrap_err()
                .contains("unknown watch descriptor 99")
        );
    }

    #[test]
    fn poll_deadlines_round_up_and_expire_without_events() {
        assert_eq!(poll_timeout(None, Duration::MAX), Some(-1));
        let limit = Some(Duration::from_millis(25));
        assert_eq!(poll_timeout(limit, Duration::ZERO), Some(25));
        assert_eq!(
            poll_timeout(limit, Duration::from_nanos(24_999_999)),
            Some(1)
        );
        assert_eq!(poll_timeout(limit, Duration::from_millis(25)), None);
        assert_eq!(poll_timeout(limit, Duration::from_millis(26)), None);
        assert_eq!(
            poll_timeout(Some(Duration::MAX), Duration::ZERO),
            Some(i32::MAX)
        );
    }
}
