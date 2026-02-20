use std::io::{self, Write};

struct TermiosGuard {
    original: libc::termios,
    fd: i32,
}

impl TermiosGuard {
    fn new() -> Option<Self> {
        let fd = libc::STDIN_FILENO;
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
            return None;
        }
        let mut raw = original;
        raw.c_lflag &= !(libc::ECHO | libc::ICANON);
        raw.c_cc[libc::VMIN] = 1;
        raw.c_cc[libc::VTIME] = 0;
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
            return None;
        }
        Some(Self { original, fd })
    }
}

impl Drop for TermiosGuard {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.original);
        }
    }
}

pub fn get_pin() -> usize {
    const MAX_UINT64_STR: &str = "18446744073709551615";
    const MAX_PIN_LENGTH: usize = 20;

    print!("\nPIN: ");
    io::stdout().flush().unwrap_or(());

    let mut input = String::new();
    let _guard = TermiosGuard::new();

    let mut buf = [0u8; 1];
    while input.len() < MAX_PIN_LENGTH {
        let bytes_read = unsafe {
            libc::read(
                libc::STDIN_FILENO,
                buf.as_mut_ptr() as *mut libc::c_void,
                1,
            )
        };
        if bytes_read <= 0 {
            continue;
        }
        let ch = buf[0];
        if ch >= b'0' && ch <= b'9' {
            input.push(ch as char);
            print!("*");
            io::stdout().flush().unwrap_or(());
        } else if (ch == 8 || ch == 127) && !input.is_empty() {
            print!("\x08 \x08");
            io::stdout().flush().unwrap_or(());
            input.pop();
        } else if ch == b'\n' {
            break;
        }
    }

    println!();
    io::stdout().flush().unwrap_or(());

    if input.is_empty() || (input.len() == MAX_PIN_LENGTH && input.as_str() > MAX_UINT64_STR) {
        return 0;
    }

    input.parse::<usize>().unwrap_or(0)
}
