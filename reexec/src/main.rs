use std::{ffi::CString, path::{Path, PathBuf}};

use clap::Parser;
use nix::{fcntl::{open, OFlag}, mount::{mount, MsFlags}, sched::{clone, CloneFlags}, sys::{signal::Signal, stat::Mode, wait::wait}, unistd::{chdir, chroot, close, execvp, getgid, getuid, setsid, Gid, Uid}};
///
/// Tool for namespace isolation and execution for Renet.
/// Running an executable w/(w/o) isolated namespaces and (or) chroot.
#[derive(Parser)]
#[command(version, about, long_about)]
struct Args {
    /// The path of the executable
    path: PathBuf,

    /// The arguments of the executable
    args: Vec<String>,

    /// Change root to a target directory
    #[arg(short, long)]
    chroot: Option<PathBuf>,

    /// Isolated network namespace
    #[arg(short, long)]
    net: bool,

    /// Isolated mount namespace
    #[arg(short, long)]
    mount: bool,

    /// Isolated UTS (hostname) namespace
    #[arg(short='H', long)]
    hostname: bool,
    
    /// Isolated PID (process) namespace
    #[arg(short, long)]
    process: bool,

    /// Isolated user namespace
    #[arg(short, long)]
    user: bool,

    /// Isolated IPC namespace
    #[arg(short, long)]
    ipc: bool,

    /// Remount processes, effectively create new pid from 1.
    /// 
    /// This is only usable when mount, process namespace are isolated and the root is changed,
    /// i.e. use -m (--mount) and -p (--process) simutaneously
    #[arg(long, requires = "mount", requires = "process", requires = "chroot")]
    new_pid: bool,

    /// set user to root
    #[arg(short, long, requires = "user")]
    root: bool,

    /// Detach session
    #[arg(short, long)]
    detach: bool,
}
struct UidMap<T: std::fmt::Display> {
    pub dst: T,
    pub src: T,
    pub size: u32,
}

fn update_map<T: std::fmt::Display>(maps: &[UidMap<T>], path: impl AsRef<Path>) -> Result<(), std::io::Error> {
    let mut buf = String::new();
    for map in maps {
        buf.push_str(&format!("{} {} {}\n", map.dst, map.src, map.size));
    }
    std::fs::write(path, buf.as_bytes())
}

const STACK_SIZE: usize = 1024 * 1024; // 1 MB stack for the new process

fn main() {
    let args = Args::parse();
    let mut flags = CloneFlags::empty();
    if args.net {
        flags |= CloneFlags::CLONE_NEWNET;
    }
    if args.mount {
        flags |= CloneFlags::CLONE_NEWNS;
    }
    if args.hostname {
        flags |= CloneFlags::CLONE_NEWUTS;
    }
    if args.process {
        flags |= CloneFlags::CLONE_NEWPID;
    }
    if args.user {
        flags |= CloneFlags::CLONE_NEWUSER;
    }
    if args.ipc {
        flags |= CloneFlags::CLONE_NEWIPC;
    }
    // before unshare, set user and group ids
    let child = || {
        if args.detach {
            setsid().unwrap();
            chdir("/").unwrap();

            close(0).unwrap();
            close(1).unwrap();
            close(2).unwrap();
            let stdin = open("/dev/null", OFlag::O_RDWR, Mode::empty()).unwrap();
            nix::unistd::dup(&stdin).unwrap(); // stdout
            nix::unistd::dup(&stdin).unwrap(); // stderr
        }
        if let Some(root) = args.chroot.clone() {
            chroot(&root).unwrap();
            chdir("/").unwrap();
        }
        // If PID and mount point is isolated and chroot to another space, also mount proc to /proc, so that the container has a clear view of processes.
        if args.mount {
            if args.chroot.is_none() {
                mount(Some("none"), "/", Option::<&str>::None, MsFlags::MS_REC | MsFlags::MS_PRIVATE, Option::<&str>::None).unwrap();
            }

            mount(Some("tmpfs"), "/tmp", Some("tmpfs"), MsFlags::empty(), Option::<&str>::None).unwrap();
            mount(Some("tmpfs"), "/run", Some("tmpfs"), MsFlags::empty(), Option::<&str>::None).unwrap();
            mount(Some("sysfs"), "/sys", Some("sysfs"), MsFlags::empty(), Option::<&str>::None).unwrap();
            if args.process {
                mount(Some("proc"), "/proc", Some("proc"), MsFlags::empty(), Some("")).unwrap();
            }
        }
        let path = CString::new(args.path.to_str().unwrap()).unwrap();
        let args = std::iter::once(path.clone()).chain(args.args.iter().map(|s| CString::new(s.to_string()).unwrap())).collect::<Box<[_]>>();
        execvp(&path, &args).unwrap();
        unreachable!()
    };
    let mut child_stack = [0u8; STACK_SIZE];
    let child_pid = unsafe { clone(Box::new(child), &mut child_stack, flags, Some(Signal::SIGCHLD as i32)) }.unwrap();
    if args.detach {
        println!("{}", child_pid);
    }
    let err: Result<(), Box<dyn std::error::Error>> = (|| {
        if args.root {
            let uid_map_path = format!("/proc/{}/uid_map", child_pid);
            let uid_map = vec![UidMap { dst: Uid::from_raw(0), src: getuid(), size: 1 }];
            // Write GID map first. You must disable setgroups before this.
            match std::fs::write(format!("/proc/{}/setgroups", child_pid), "deny") {
                Ok(_) => {
                    let gid_map_path = format!("/proc/{}/gid_map", child_pid);
                    let gid_map = vec![UidMap { dst: Gid::from_raw(0), src: getgid(), size: 1 }];
                    update_map(&gid_map, &gid_map_path)?;
                },
                Err(e) => eprintln!("[Parent] ERROR disabling setgroups: {}. This is expected on some systems.", e),
            };
            update_map(&uid_map, &uid_map_path)?;
        }
        Ok(())
    })();
    if let Err(e) = &err {
        println!("{:?}", e)
    }
    if args.detach {
        return
    }
    wait().unwrap();
}
