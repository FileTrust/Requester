"""Durable, pausable VaultMesh download process management."""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import subprocess
import threading
import time
from pathlib import Path
from .ft_update_bootstrap import child_lock_options


class TransferPaused(RuntimeError):
    pass


_lock = threading.RLock()
_active: dict[str, subprocess.Popen] = {}
_starting: set[str] = set()
_paused_transfers: set[str] = set()
_pause_requested = threading.Event()


def _jobs_dir(base_dir: str | os.PathLike) -> Path:
    root = Path(base_dir) / "transfer_jobs"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    path = root / "downloads"
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def _atomic_write(path: Path, value: dict) -> None:
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)
    try:
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError:
        pass


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _stable_peer_id(peer: str) -> str:
    value = str(peer or "").strip()
    if "/p2p/" in value:
        return value.rsplit("/p2p/", 1)[-1].strip()
    return value


def get_or_create_download_job(base_dir: str | os.PathLike, piece_root: str,
                               peer: str, output_path: str, file_id: str) -> dict:
    immutable = json.dumps({
        "pieceRoot": str(piece_root).lower(),
        "peerId": _stable_peer_id(peer),
        "outputPath": str(Path(output_path).resolve()),
        "fileId": str(file_id).lower(),
    }, sort_keys=True, separators=(",", ":"))
    job_id = hashlib.sha256(immutable.encode("utf-8")).hexdigest()
    path = _jobs_dir(base_dir) / f"{job_id}.json"
    with _lock:
        if path.is_file():
            return json.loads(path.read_text(encoding="utf-8"))
        now = _now()
        job = {
            "version": 1, "jobId": job_id, "status": "pending",
            "pieceRoot": piece_root, "peer": peer,
            "peerId": _stable_peer_id(peer),
            "outputPath": str(Path(output_path).resolve()), "fileId": file_id,
            "createdAt": now, "updatedAt": now,
        }
        _atomic_write(path, job)
        return job


def update_download_job(base_dir: str | os.PathLike, job: dict, **updates) -> dict:
    with _lock:
        merged = dict(job)
        merged.update(updates)
        merged["updatedAt"] = _now()
        _atomic_write(_jobs_dir(base_dir) / f"{merged['jobId']}.json", merged)
        job.clear()
        job.update(merged)
        return job


def pause_downloads() -> int:
    _pause_requested.set()
    with _lock:
        processes = list(_active.items())
        _paused_transfers.update(job_id for job_id, _ in processes)
    for _, process in processes:
        if process.poll() is None:
            process.terminate()
    return len(processes)


def resume_downloads() -> None:
    _pause_requested.clear()


def run_download_process(base_dir: str | os.PathLike, job: dict,
                         cmd: list[str], progress_callback=None) -> str:
    if _pause_requested.is_set():
        update_download_job(base_dir, job, status="paused")
        raise TransferPaused("download paused before admission")
    job_id = str(job["jobId"])
    deadline = time.monotonic() + 10
    while True:
        with _lock:
            already_active = job_id in _active or job_id in _starting
            if not already_active:
                _starting.add(job_id)
                break
        if time.monotonic() >= deadline:
            raise RuntimeError("this download transfer is already active")
        time.sleep(0.05)
    try:
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1,
            **child_lock_options(),
        )
    except Exception:
        with _lock:
            _starting.discard(job_id)
        raise
    stderr_lines: list[str] = []
    last_progress_persisted = 0.0

    def _drain() -> None:
        nonlocal last_progress_persisted
        assert process.stderr is not None
        for line in process.stderr:
            stripped = line.rstrip()
            stderr_lines.append(stripped)
            if stripped.startswith("FILETRUST_PROGRESS "):
                try:
                    progress = json.loads(stripped.split(" ", 1)[1])
                    now = time.monotonic()
                    complete = int(progress.get("bytes", 0)) >= int(progress.get("totalBytes", 1))
                    if complete or now-last_progress_persisted >= 5:
                        update_download_job(base_dir, job, status="running", progress=progress)
                        last_progress_persisted = now
                    if progress_callback:
                        progress_callback(progress)
                except Exception:
                    pass

    with _lock:
        _starting.discard(job_id)
        _active[job_id] = process
        paused_after_start = _pause_requested.is_set()
        if paused_after_start:
            _paused_transfers.add(job_id)
    if paused_after_start and process.poll() is None:
        process.terminate()
    try:
        update_download_job(base_dir, job, status="running", lastError="")
    except Exception:
        if process.poll() is None:
            process.terminate()
        process.communicate(timeout=5)
        with _lock:
            _active.pop(job_id, None)
        raise
    drain = threading.Thread(target=_drain, daemon=True)
    drain.start()
    assert process.stdout is not None
    stdout = process.stdout.read()
    return_code = process.wait()
    drain.join(timeout=2)
    process.stdout.close()
    if process.stderr is not None:
        process.stderr.close()
    with _lock:
        _active.pop(job_id, None)
        was_paused = job_id in _paused_transfers
        _paused_transfers.discard(job_id)
    if was_paused and return_code != 0:
        update_download_job(base_dir, job, status="paused")
        raise TransferPaused("download paused; saved partial bytes will be resumed")
    if return_code != 0:
        error = "\n".join(line for line in stderr_lines if not line.startswith("FILETRUST_PROGRESS ")).strip()
        error = error or stdout.strip() or f"VaultMesh exited with status {return_code}"
        update_download_job(base_dir, job, status="pending", lastError=error)
        raise RuntimeError(error)
    update_download_job(base_dir, job, status="completed", result=stdout.strip())
    return stdout.strip()
