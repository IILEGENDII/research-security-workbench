import os
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path, PureWindowsPath

from .formats import Invalid, require


def local(value):
    raw = os.fspath(value)
    p = Path(raw)
    win = PureWindowsPath(raw)
    require(
        raw
        and raw.isprintable()
        and not raw.startswith(("//", "\\\\"))
        and "://" not in raw
        and ".." not in p.parts
        and ".." not in win.parts,
        "unsafe_path",
    )
    if os.name != "nt":
        require(not win.drive and "\\" not in raw, "unsafe_path")
    else:
        require(not (win.drive and not win.is_absolute()), "unsafe_path")
        for part in win.parts:
            if part != win.anchor:
                reserved = (
                    os.path.isreserved(part)
                    if hasattr(os.path, "isreserved")
                    else PureWindowsPath(part).is_reserved()
                )
                require(
                    not reserved and ":" not in part and part.rstrip(" .") == part, "unsafe_path"
                )
    p = p.absolute()
    for entry in reversed((p, *p.parents)):
        try:
            info = entry.lstat()
        except FileNotFoundError:
            continue
        require(
            not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 1024,
            "link_not_allowed",
        )
        if entry != p:
            require(stat.S_ISDIR(info.st_mode), "unsafe_parent")
    return p


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_nlink)


def read(path, limit):
    path = local(path)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "regular_file_required")
    require(before.st_size <= limit, "size_limit")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    with os.fdopen(os.open(path, flags), "rb") as f:
        require(identity(os.fstat(f.fileno())) == identity(before), "file_changed")
        data = f.read(limit + 1)
        require(
            len(data) == before.st_size
            and identity(os.fstat(f.fileno())) == identity(before) == identity(path.lstat()),
            "file_changed",
        )
    return data


def write_new(path, data):
    path = local(path)
    fd, name = tempfile.mkstemp(prefix=".incomplete-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        # Both publication operations fail if another writer already claimed the name.
        if os.name == "nt":
            os.rename(name, path)
        else:
            os.link(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def private_dir(path):
    p = local(path)
    info = p.lstat()
    require(stat.S_ISDIR(info.st_mode), "directory_required")
    if os.name == "posix":
        require(
            info.st_uid == os.geteuid() and not info.st_mode & 0o077, "private_directory_required"
        )
    return p


def new_workspace(path):
    path = local(path)
    require(
        path != Path(path.anchor)
        and not Path.home().is_relative_to(path)
        and not Path.cwd().is_relative_to(path),
        "protected_directory",
    )
    for parent in path.parents:
        require(
            not any(os.path.lexists(parent / name) for name in (".git", "workspace.json")),
            "protected_directory",
        )
        require(
            not ((parent / "config").is_file() and (parent / "snapshots").is_dir()),
            "protected_directory",
        )
    path.mkdir(mode=0o700)
    return private_dir(path)


def children(path, limit):
    result = []
    with os.scandir(private_dir(path)) as entries:
        for entry in entries:
            if len(result) >= limit:
                raise Invalid("entry_limit")
            result.append(entry.name)
    return sorted(result)


@contextmanager
def writing(root):
    lock = root / "write.lock"
    write_new(lock, b"workbench writer\n")
    try:
        yield
    finally:
        lock.unlink()
