//! veer-process-keeper: the worker binary run with this argv[0] keeps one
//! execution of a process a plugin manages (process.start), such as sing-box.
//!
//! The daemon starts one keeper per process, puts it in the process's
//! resource cgroup and sends "start" over the unix socket inherited as fd 3.
//! The keeper starts the program in its own process group with SIGKILL as
//! its parent-death signal, forwards its output and reports its exit. For a
//! hot restart the daemon sends "detach": the keeper listens on an abstract
//! socket and, once the daemon's connection closes, waits for a successor
//! that runs as the same user and presents the token, then sends it what it
//! missed. If the daemon goes away without a handoff, or no successor comes
//! in time, the keeper kills the program.
//!
//! The daemon's side is internal/app/plugin_process_keeper*.go. The protocol
//! is the one the Go keeper (veer --plugin-process-keeper) spoke, so a daemon
//! adopts keepers of either kind across a hot restart.
//!
//! One thread and poll(2): the parent-death signal follows the thread that
//! forked the program, and nothing here needs more.

use std::collections::VecDeque;
use std::ffi::{c_void, OsStr};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::keeper_proto::{self as proto, Event, Lines, OutputLog, Request};

/// The argv[0] that selects the keeper.
pub const ARGV0: &str = "veer-process-keeper";
const PROCESS_NAME: &[u8] = b"veer-keeper\0";
const CONTROL_FD: RawFd = 3;
const START_TIMEOUT: Duration = Duration::from_secs(10);
const FLUSH_TIMEOUT: Duration = Duration::from_secs(2);
const ATTACH_TIMEOUT: Duration = Duration::from_secs(5);
/// After the program exits, output still in its pipes is read for this long
/// (descendants may hold them open), as exec.Cmd.WaitDelay did.
const WAIT_DELAY: Duration = Duration::from_millis(100);
/// Output waiting for a slow daemon is dropped beyond these bounds, never
/// held: a stalled daemon must not stall the program. The keeper's own log
/// still has it for a successor.
const OUTPUT_QUEUE: usize = 1024;
const OUTPUT_QUEUE_BYTES: usize = 8 << 20;
/// Connections waiting to present an attach token at once.
const MAX_CANDIDATES: usize = 8;
const READ_CHUNK: usize = 32 << 10;
const LISTEN_BACKLOG: i32 = 16;

pub fn invoked() -> bool {
    std::env::args_os().next().is_some_and(|arg0| Path::new(&arg0).file_name() == Some(OsStr::new(ARGV0)))
}

pub fn run() -> i32 {
    unsafe {
        libc::prctl(libc::PR_SET_NAME, PROCESS_NAME.as_ptr() as libc::c_ulong, 0, 0, 0);
    }
    // The control socket must not reach the program, nor anything else the
    // keeper inherited: the program gets its three pipes only.
    if set_flags(CONTROL_FD).is_err() {
        return 2;
    }
    close_inherited_on_exec();
    let mut link = Link::new(unsafe { OwnedFd::from_raw_fd(CONTROL_FD) }, Vec::new());
    let Some(start) = await_start(&mut link) else {
        return 1;
    };
    let sigchld = match sigchld_fd() {
        Ok(fd) => fd,
        Err(err) => {
            link.queue(Event { error: &format!("process keeper: {}", describe(&err)), ..Event::new("error") }.line(), false);
            flush(Some(link));
            return 0;
        }
    };
    let core = match Core::spawn(&start) {
        Ok(core) => core,
        Err(err) => {
            let message = format!("start {}: {}", start.command, describe(&err));
            link.queue(Event { error: &message, ..Event::new("error") }.line(), false);
            flush(Some(link));
            return 0;
        }
    };
    link.queue(Event { pid: core.pid as i64, started_at: core.started_at, ..Event::new("started") }.line(), false);
    let mut keeper = Keeper {
        link: Some(link),
        core,
        sigchld,
        stdout_log: OutputLog::default(),
        stderr_log: OutputLog::default(),
        listener: None,
        token: String::new(),
        adopt_wait: Duration::ZERO,
        adopt_deadline: None,
        candidates: Vec::new(),
        stopping: false,
        stop_deadline: None,
        abandoned: false,
        exit: false,
    };
    keeper.serve();
    flush(keeper.link.take());
    0
}

/// Reads the start request, which must come first and in time.
fn await_start(link: &mut Link) -> Option<Request> {
    let deadline = Instant::now() + START_TIMEOUT;
    loop {
        match link.next_request() {
            Ok(Some(request)) => return (request.op == "start").then_some(request),
            Ok(None) => {}
            Err(()) => return None,
        }
        let now = Instant::now();
        if now >= deadline {
            return None;
        }
        let mut fds = [libc::pollfd { fd: link.fd.as_raw_fd(), events: libc::POLLIN, revents: 0 }];
        poll(&mut fds, Some(deadline - now));
        if fds[0].revents != 0 && !link.read_some(usize::MAX) {
            // Requests that arrived before the close still count.
            return match link.next_request() {
                Ok(Some(request)) if request.op == "start" => Some(request),
                _ => None,
            };
        }
    }
}

/// One daemon connection: requests in, events out.
struct Link {
    fd: OwnedFd,
    lines: Lines,
    out: VecDeque<Vec<u8>>,
    // Bytes of out.front() already sent, and bytes queued in out.
    written: usize,
    queued: usize,
    // The keeper stops reading after "stop", as the Go keeper did.
    reading: bool,
}

impl Link {
    fn new(fd: OwnedFd, rest: Vec<u8>) -> Link {
        let mut lines = Lines::new(proto::MESSAGE_LIMIT);
        lines.push(&rest);
        Link { fd, lines, out: VecDeque::new(), written: 0, queued: 0, reading: true }
    }

    /// Queues an event line. Output (droppable) is dropped while the daemon
    /// is behind; control events always wait their turn.
    fn queue(&mut self, line: Vec<u8>, droppable: bool) {
        if droppable && (self.out.len() >= OUTPUT_QUEUE || self.queued + line.len() > OUTPUT_QUEUE_BYTES) {
            return;
        }
        self.queued += line.len();
        self.out.push_back(line);
    }

    /// Sends what the socket takes without blocking.
    fn write_some(&mut self) -> io::Result<()> {
        while let Some(front) = self.out.front() {
            let length = front.len();
            match send_fd(self.fd.as_raw_fd(), &front[self.written..]) {
                Ok(n) => {
                    self.written += n;
                    if self.written == length {
                        self.out.pop_front();
                        self.queued -= length;
                        self.written = 0;
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }

    /// Reads up to chunks reads of what has arrived. Returns false once the
    /// peer closed the connection or it failed.
    fn read_some(&mut self, chunks: usize) -> bool {
        let mut buffer = [0u8; READ_CHUNK];
        for _ in 0..chunks {
            match read_fd(self.fd.as_raw_fd(), &mut buffer) {
                Ok(0) => return false,
                Ok(n) => self.lines.push(&buffer[..n]),
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return true,
                Err(_) => return false,
            }
        }
        true
    }

    /// The next complete request; Err for one that is not a request of this
    /// protocol, which ends the connection.
    fn next_request(&mut self) -> Result<Option<Request>, ()> {
        match self.lines.next_line() {
            Ok(Some(line)) => proto::parse_request(&line).map(Some).ok_or(()),
            Ok(None) => Ok(None),
            Err(_) => Err(()),
        }
    }
}

/// Sends what is queued before the keeper exits, for at most FLUSH_TIMEOUT.
fn flush(link: Option<Link>) {
    let Some(mut link) = link else {
        return;
    };
    let deadline = Instant::now() + FLUSH_TIMEOUT;
    while link.write_some().is_ok() && !link.out.is_empty() {
        let now = Instant::now();
        if now >= deadline {
            return;
        }
        let mut fds = [libc::pollfd { fd: link.fd.as_raw_fd(), events: libc::POLLOUT, revents: 0 }];
        poll(&mut fds, Some(deadline - now));
    }
}

/// The program and its pipes.
struct Core {
    child: Child,
    pid: i32,
    started_at: i64,
    stdin: Option<OwnedFd>,
    stdin_data: Vec<u8>,
    stdin_written: usize,
    stdout: Option<OwnedFd>,
    stderr: Option<OwnedFd>,
    // -1 until the program exits, and when a signal ended it.
    code: i64,
    exited_at: Option<Instant>,
    // The exit is final: the pipes are closed and the group was killed.
    done: bool,
}

impl Core {
    fn spawn(start: &Request) -> io::Result<Core> {
        let mut command = Command::new(&start.command);
        command.args(&start.args);
        // No environment means the keeper's own, as exec.Cmd did.
        if !start.env.is_empty() {
            command.env_clear();
            for entry in &start.env {
                if let Some((key, value)) = entry.split_once('=') {
                    if !key.is_empty() {
                        command.env(key, value);
                    }
                }
            }
        }
        if !start.dir.is_empty() {
            command.current_dir(&start.dir);
        }
        command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).process_group(0);
        let keeper = std::process::id() as libc::pid_t;
        unsafe {
            command.pre_exec(move || {
                // The program starts with default signal handling, as systemd
                // gives a service: nothing blocked (the keeper blocks SIGCHLD
                // for signalfd) and nothing ignored (Rust ignores SIGPIPE, and
                // whoever started the daemon may have ignored more).
                let mut set: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut set);
                libc::sigprocmask(libc::SIG_SETMASK, &set, std::ptr::null_mut());
                for signal in 1..=64 {
                    if signal != libc::SIGKILL && signal != libc::SIGSTOP {
                        libc::signal(signal, libc::SIG_DFL);
                    }
                }
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong, 0, 0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                // The keeper may have died before the signal was armed.
                if libc::getppid() != keeper {
                    libc::kill(libc::getpid(), libc::SIGKILL);
                }
                Ok(())
            });
        }
        let mut child = command.spawn()?;
        let started_at = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as i64);
        let pid = child.id() as i32;
        let stdin = child.stdin.take().map(OwnedFd::from);
        let stdout = child.stdout.take().map(OwnedFd::from);
        let stderr = child.stderr.take().map(OwnedFd::from);
        for fd in [&stdin, &stdout, &stderr].into_iter().flatten() {
            set_flags(fd.as_raw_fd())?;
        }
        let stdin_data = start.stdin.as_bytes().to_vec();
        Ok(Core {
            child,
            pid,
            started_at,
            // Empty input closes the pipe at once: the program reads EOF.
            stdin: if stdin_data.is_empty() { None } else { stdin },
            stdin_data,
            stdin_written: 0,
            stdout,
            stderr,
            code: -1,
            exited_at: None,
            done: false,
        })
    }

    /// Signals the program's process group while it may still exist.
    fn signal_group(&self, signal: libc::c_int) {
        if !self.done && self.pid > 0 {
            unsafe {
                libc::kill(-self.pid, signal);
            }
        }
    }
}

/// A connection to the handoff socket that has not shown its token yet.
struct Candidate {
    fd: OwnedFd,
    lines: Lines,
    deadline: Instant,
}

#[derive(Clone, Copy)]
enum Source {
    Sigchld,
    Stdout,
    Stderr,
    Stdin,
    Link,
    Listener,
    Candidate(usize),
}

struct Keeper {
    link: Option<Link>,
    core: Core,
    sigchld: OwnedFd,
    stdout_log: OutputLog,
    stderr_log: OutputLog,
    // Armed by "detach": the abstract socket a successor connects to.
    listener: Option<OwnedFd>,
    token: String,
    adopt_wait: Duration,
    adopt_deadline: Option<Instant>,
    candidates: Vec<Candidate>,
    // "stop" arrived: the program is being terminated and the keeper exits
    // once it is gone.
    stopping: bool,
    stop_deadline: Option<Instant>,
    // Nobody will take the program over: it is being killed.
    abandoned: bool,
    exit: bool,
}

impl Keeper {
    fn serve(&mut self) {
        let mut fds: Vec<libc::pollfd> = Vec::new();
        let mut sources: Vec<Source> = Vec::new();
        while !self.exit {
            if let Some(link) = &mut self.link {
                if link.write_some().is_err() {
                    self.link_lost();
                }
            }
            self.expire(Instant::now());
            if self.exit {
                break;
            }
            fds.clear();
            sources.clear();
            let mut add = |fd: RawFd, events: libc::c_short, source: Source| {
                fds.push(libc::pollfd { fd, events, revents: 0 });
                sources.push(source);
            };
            if self.core.exited_at.is_none() {
                add(self.sigchld.as_raw_fd(), libc::POLLIN, Source::Sigchld);
            }
            if let Some(fd) = &self.core.stdout {
                add(fd.as_raw_fd(), libc::POLLIN, Source::Stdout);
            }
            if let Some(fd) = &self.core.stderr {
                add(fd.as_raw_fd(), libc::POLLIN, Source::Stderr);
            }
            if let Some(fd) = &self.core.stdin {
                add(fd.as_raw_fd(), libc::POLLOUT, Source::Stdin);
            }
            if let Some(link) = &self.link {
                let mut events = 0;
                if link.reading {
                    events |= libc::POLLIN;
                }
                if !link.out.is_empty() {
                    events |= libc::POLLOUT;
                }
                add(link.fd.as_raw_fd(), events, Source::Link);
            }
            if let Some(listener) = &self.listener {
                // A successor is admitted only once the daemon has let go.
                if self.link.is_none() {
                    add(listener.as_raw_fd(), libc::POLLIN, Source::Listener);
                }
            }
            for (index, candidate) in self.candidates.iter().enumerate() {
                add(candidate.fd.as_raw_fd(), libc::POLLIN, Source::Candidate(index));
            }
            let timeout = self.next_deadline().map(|deadline| deadline.saturating_duration_since(Instant::now()));
            poll(&mut fds, timeout);

            let mut accepted = None;
            let mut rejected = Vec::new();
            for (pollfd, source) in fds.iter().zip(sources.iter()) {
                if pollfd.revents == 0 {
                    continue;
                }
                match *source {
                    Source::Sigchld => self.reap(),
                    Source::Stdout => self.read_output(false),
                    Source::Stderr => self.read_output(true),
                    Source::Stdin => self.write_stdin(),
                    Source::Link => self.serve_link(pollfd.revents),
                    Source::Listener => self.accept(),
                    Source::Candidate(index) => match self.check_candidate(index) {
                        Some(true) => accepted = accepted.or(Some(index)),
                        Some(false) => rejected.push(index),
                        None => {}
                    },
                }
            }
            if let Some(index) = accepted.filter(|&index| index < self.candidates.len()) {
                let candidate = self.candidates.swap_remove(index);
                self.attach(candidate);
            } else {
                // Descending, so each removal leaves the lower indices valid.
                for index in rejected.into_iter().rev() {
                    if index < self.candidates.len() {
                        self.candidates.swap_remove(index);
                    }
                }
            }
            self.finish_exit(Instant::now());
        }
    }

    fn next_deadline(&self) -> Option<Instant> {
        let mut deadlines = vec![self.stop_deadline, self.adopt_deadline];
        if !self.core.done {
            deadlines.push(self.core.exited_at.map(|at| at + WAIT_DELAY));
        }
        deadlines.extend(self.candidates.iter().map(|candidate| Some(candidate.deadline)));
        deadlines.into_iter().flatten().min()
    }

    fn expire(&mut self, now: Instant) {
        if self.stop_deadline.is_some_and(|deadline| now >= deadline) {
            self.stop_deadline = None;
            self.core.signal_group(libc::SIGKILL);
        }
        if self.adopt_deadline.is_some_and(|deadline| now >= deadline) {
            self.adopt_deadline = None;
            self.abandon();
        }
        self.candidates.retain(|candidate| now < candidate.deadline);
        self.finish_exit(now);
    }

    fn reap(&mut self) {
        let mut info = [0u8; 128 * 4];
        while read_fd(self.sigchld.as_raw_fd(), &mut info).is_ok_and(|n| n > 0) {}
        if self.core.exited_at.is_some() {
            return;
        }
        let code = match self.core.child.try_wait() {
            Ok(None) => return,
            Ok(Some(status)) => status.code().map_or(-1, i64::from),
            Err(_) => -1,
        };
        self.core.code = code;
        self.core.exited_at = Some(Instant::now());
        self.core.stdin = None;
    }

    /// Ends the exit once the pipes are drained or WAIT_DELAY has passed:
    /// closes them, kills what is left of the process group and decides
    /// whether the keeper is done.
    fn finish_exit(&mut self, now: Instant) {
        let Some(exited_at) = self.core.exited_at else {
            return;
        };
        if self.core.done {
            return;
        }
        let drained = self.core.stdout.is_none() && self.core.stderr.is_none();
        if !drained && now < exited_at + WAIT_DELAY {
            return;
        }
        self.read_output(false);
        self.read_output(true);
        self.core.stdout = None;
        self.core.stderr = None;
        // Reap descendants even if the leader exited on its own.
        self.core.signal_group(libc::SIGKILL);
        self.core.done = true;
        if self.stopping || self.link.is_some() {
            self.report_exit();
            self.exit = true;
        } else if self.abandoned || self.listener.is_none() {
            self.exit = true;
        }
        // Otherwise a successor is still coming; it hears the exit when it
        // attaches.
    }

    /// Forwards what one output pipe holds, a bounded amount per turn so a
    /// chatty program cannot starve the rest; closes the pipe at its end.
    fn read_output(&mut self, stderr: bool) {
        let mut buffer = [0u8; READ_CHUNK];
        for _ in 0..16 {
            let pipe = if stderr { &self.core.stderr } else { &self.core.stdout };
            let Some(fd) = pipe.as_ref().map(|fd| fd.as_raw_fd()) else {
                return;
            };
            match read_fd(fd, &mut buffer) {
                Ok(0) => {}
                Ok(n) => {
                    self.output(stderr, &buffer[..n]);
                    continue;
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return,
                Err(_) => {}
            }
            if stderr {
                self.core.stderr = None;
            } else {
                self.core.stdout = None;
            }
            return;
        }
    }

    fn output(&mut self, stderr: bool, data: &[u8]) {
        let (log, stream) = if stderr { (&mut self.stderr_log, "stderr") } else { (&mut self.stdout_log, "stdout") };
        log.write(data);
        if let Some(link) = &mut self.link {
            link.queue(Event { stream, data, ..Event::new("output") }.line(), true);
        }
    }

    fn write_stdin(&mut self) {
        while let Some(fd) = &self.core.stdin {
            let rest = &self.core.stdin_data[self.core.stdin_written..];
            if rest.is_empty() {
                break;
            }
            match write_fd(fd.as_raw_fd(), rest) {
                Ok(n) => self.core.stdin_written += n,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return,
                Err(_) => break,
            }
        }
        self.core.stdin = None;
        self.core.stdin_data = Vec::new();
    }

    fn serve_link(&mut self, revents: libc::c_short) {
        let Some(link) = &mut self.link else {
            return;
        };
        let mut open = true;
        if link.reading && revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            open = link.read_some(64);
        } else if revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            open = false;
        }
        // Requests that arrived before a close are still served.
        loop {
            let Some(link) = &mut self.link else {
                return;
            };
            if !link.reading {
                break;
            }
            match link.next_request() {
                Ok(Some(request)) => self.handle(request),
                Ok(None) => break,
                Err(()) => {
                    open = false;
                    break;
                }
            }
        }
        if !open {
            self.link_lost();
        }
    }

    fn handle(&mut self, request: Request) {
        match request.op.as_str() {
            "stop" => self.stop(Duration::from_millis(request.timeout_ms.max(0) as u64)),
            "detach" => self.detach(request),
            // A second start, or an op this keeper does not know, is ignored.
            _ => {}
        }
    }

    fn stop(&mut self, timeout: Duration) {
        self.stopping = true;
        if let Some(link) = &mut self.link {
            link.reading = false;
        }
        if self.core.done {
            self.report_exit();
            self.exit = true;
            return;
        }
        self.core.signal_group(libc::SIGTERM);
        self.stop_deadline = Some(Instant::now() + timeout);
    }

    fn detach(&mut self, request: Request) {
        self.listener = None;
        // A socket that cannot be bound gets no answer; the daemon gives up
        // on the handoff after a second.
        let Ok(listener) = listen_abstract(&request.name) else {
            return;
        };
        self.listener = Some(listener);
        self.token = request.token;
        self.adopt_wait = Duration::from_millis(request.timeout_ms.max(0) as u64);
        if let Some(link) = &mut self.link {
            link.queue(Event::new("detached").line(), false);
        }
    }

    fn link_lost(&mut self) {
        if self.link.take().is_none() || self.stopping {
            return;
        }
        if self.core.done {
            self.exit = true;
        } else if self.listener.is_none() {
            // The daemon vanished without a handoff: behave as a dead parent.
            self.abandon();
        } else {
            self.adopt_deadline = Some(Instant::now() + self.adopt_wait);
        }
    }

    fn abandon(&mut self) {
        self.core.signal_group(libc::SIGKILL);
        self.abandoned = true;
        self.listener = None;
        self.candidates.clear();
        if self.core.done {
            self.exit = true;
        }
    }

    fn report_exit(&mut self) {
        if let Some(link) = &mut self.link {
            link.queue(Event { code: self.core.code, ..Event::new("exited") }.line(), false);
        }
    }

    /// Admits connections from processes of this user; each then has
    /// ATTACH_TIMEOUT to present the token. Anything else in the network
    /// namespace could otherwise reach the abstract socket.
    fn accept(&mut self) {
        let Some(listener) = &self.listener else {
            return;
        };
        loop {
            let fd = unsafe {
                libc::accept4(
                    listener.as_raw_fd(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                )
            };
            if fd < 0 {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return;
            }
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            if peer_uid(fd.as_raw_fd()) != Some(unsafe { libc::geteuid() }) || self.candidates.len() >= MAX_CANDIDATES {
                continue;
            }
            self.candidates.push(Candidate {
                fd,
                lines: Lines::new(proto::ATTACH_LIMIT),
                deadline: Instant::now() + ATTACH_TIMEOUT,
            });
        }
    }

    /// Some(true) once the candidate presented the token, Some(false) when it
    /// is to be dropped, None while its request is incomplete.
    fn check_candidate(&mut self, index: usize) -> Option<bool> {
        let candidate = self.candidates.get_mut(index)?;
        let mut buffer = [0u8; proto::ATTACH_LIMIT + 1];
        let open = match read_fd(candidate.fd.as_raw_fd(), &mut buffer) {
            Ok(0) => false,
            Ok(n) => {
                candidate.lines.push(&buffer[..n]);
                true
            }
            Err(err) => err.kind() == io::ErrorKind::WouldBlock,
        };
        match candidate.lines.next_line() {
            Ok(Some(line)) => Some(proto::parse_request(&line).is_some_and(|request| {
                request.op == "attach" && proto::token_matches(&request.token, &self.token)
            })),
            Ok(None) if open => None,
            _ => Some(false),
        }
    }

    /// Switches to the successor and sends everything it missed.
    fn attach(&mut self, candidate: Candidate) {
        self.listener = None;
        self.candidates.clear();
        self.adopt_deadline = None;
        self.token.clear();
        let mut link = Link::new(candidate.fd, candidate.lines.into_rest());
        let (stdout, stdout_truncated) = self.stdout_log.snapshot();
        let (stderr, stderr_truncated) = self.stderr_log.snapshot();
        link.queue(
            Event {
                pid: self.core.pid as i64,
                started_at: self.core.started_at,
                running: !self.core.done,
                code: self.core.code,
                stdout: stdout.as_bytes(),
                stderr: stderr.as_bytes(),
                truncated: stdout_truncated || stderr_truncated,
                ..Event::new("attached")
            }
            .line(),
            false,
        );
        self.link = Some(link);
        if self.core.done {
            self.exit = true;
        }
    }
}

fn describe(err: &io::Error) -> String {
    match err.raw_os_error() {
        Some(code) => {
            let text = unsafe { std::ffi::CStr::from_ptr(libc::strerror(code)) }.to_string_lossy().into_owned();
            // Go's error text, which the daemon used to relay: lower case.
            let mut chars = text.chars();
            match chars.next() {
                Some(first) => first.to_lowercase().chain(chars).collect(),
                None => text,
            }
        }
        None => err.to_string(),
    }
}

/// Blocks SIGCHLD and returns a descriptor that reports it. Command resets
/// the signal mask in the program it starts.
fn sigchld_fd() -> io::Result<OwnedFd> {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGCHLD);
        if libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()) != 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = libc::signalfd(-1, &set, libc::SFD_NONBLOCK | libc::SFD_CLOEXEC);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(OwnedFd::from_raw_fd(fd))
    }
}

/// Marks every inherited descriptor above stderr close-on-exec.
fn close_inherited_on_exec() {
    let Ok(entries) = std::fs::read_dir("/proc/self/fd") else {
        return;
    };
    for entry in entries.flatten() {
        if let Some(fd) = entry.file_name().to_str().and_then(|name| name.parse::<RawFd>().ok()) {
            if fd > 2 {
                unsafe {
                    let flags = libc::fcntl(fd, libc::F_GETFD);
                    if flags >= 0 {
                        libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
                    }
                }
            }
        }
    }
}

/// Makes a descriptor close-on-exec and non-blocking.
fn set_flags(fd: RawFd) -> io::Result<()> {
    unsafe {
        let descriptor = libc::fcntl(fd, libc::F_GETFD);
        let status = libc::fcntl(fd, libc::F_GETFL);
        if descriptor < 0
            || status < 0
            || libc::fcntl(fd, libc::F_SETFD, descriptor | libc::FD_CLOEXEC) < 0
            || libc::fcntl(fd, libc::F_SETFL, status | libc::O_NONBLOCK) < 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn listen_abstract(name: &str) -> io::Result<OwnedFd> {
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() + 1 > address.sun_path.len() {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    // A leading NUL makes the name abstract; Go's "@name" is the same
    // address, without a trailing NUL.
    for (slot, byte) in address.sun_path[1..].iter_mut().zip(bytes) {
        *slot = *byte as libc::c_char;
    }
    let length = (std::mem::size_of::<libc::sa_family_t>() + 1 + bytes.len()) as libc::socklen_t;
    unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = OwnedFd::from_raw_fd(fd);
        if libc::bind(fd.as_raw_fd(), &address as *const libc::sockaddr_un as *const libc::sockaddr, length) != 0
            || libc::listen(fd.as_raw_fd(), LISTEN_BACKLOG) != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(fd)
    }
}

fn peer_uid(fd: RawFd) -> Option<u32> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut credentials as *mut libc::ucred as *mut c_void,
            &mut length,
        )
    };
    (result == 0).then_some(credentials.uid)
}

/// Waits for events on fds, for at most timeout (None: no limit).
fn poll(fds: &mut [libc::pollfd], timeout: Option<Duration>) {
    let millis = match timeout {
        // Round up so a deadline less than a millisecond away is not polled
        // in a busy loop.
        Some(timeout) => timeout.as_micros().div_ceil(1000).min(i32::MAX as u128) as libc::c_int,
        None => -1,
    };
    unsafe {
        libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, millis);
    }
}

fn read_fd(fd: RawFd, buffer: &mut [u8]) -> io::Result<usize> {
    loop {
        let n = unsafe { libc::read(fd, buffer.as_mut_ptr() as *mut c_void, buffer.len()) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

fn write_fd(fd: RawFd, data: &[u8]) -> io::Result<usize> {
    loop {
        let n = unsafe { libc::write(fd, data.as_ptr() as *const c_void, data.len()) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

fn send_fd(fd: RawFd, data: &[u8]) -> io::Result<usize> {
    loop {
        let n = unsafe { libc::send(fd, data.as_ptr() as *const c_void, data.len(), libc::MSG_NOSIGNAL) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}
