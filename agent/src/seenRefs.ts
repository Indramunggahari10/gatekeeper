// Durable record of seen proof references (replay protection).
//
// The in-memory Set is the hot path; the append-only file is the durable
// record, loaded at boot, so a process restart cannot forget a replay
// and approve it. One normalized ref per line; loading dedupes into the
// Set. SeenRefStore.record() is the ONLY write path, so the dedupe check
// and the append cannot drift apart: a ref already in the set is never
// appended again, and the file holds each ref exactly once.
//
// Durability: appends write with fsync (file, plus the directory when
// the file is newly created), and a flush that finds a torn last line
// (no trailing newline, e.g. a crash mid-write) starts with a newline so
// the new refs cannot fuse onto the partial line. A failed flush keeps
// its refs in a pending queue retried on the next record() — a transient
// disk failure must not silently downgrade a ref to memory-only forever.
//
// Writes are synchronous and best-effort: a failed append is logged
// loudly but never crashes the server — the in-memory set still protects
// this process lifetime. A failed load likewise starts from an empty set
// rather than refusing to serve tasks (availability wins over replay
// protection on a corrupted log; the failure is logged loudly).
//
// NOTE: this survives process restarts on the same filesystem. A
// redeploy onto a fresh filesystem wipes it unless the path lives on a
// persistent volume — mount one at SEEN_REFS_PATH for full durability.
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  statSync,
  writeSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const DEFAULT_PATH = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "data",
  "seen-proof-refs.log",
);

/** Effective log path, always absolute (a relative override resolves once, here). */
export function seenRefsPath(): string {
  return resolve(process.env.SEEN_REFS_PATH ?? DEFAULT_PATH);
}

/** Load all recorded refs. Never throws: failures log and yield an empty set. */
export function loadSeenRefs(path: string = seenRefsPath()): Set<string> {
  const refs = new Set<string>();
  try {
    if (!existsSync(path)) return refs;
    for (const line of readFileSync(path, "utf8").split("\n")) {
      const ref = line.trim().toLowerCase();
      if (ref) refs.add(ref);
    }
  } catch (err) {
    console.error(
      `seen-refs: FAILED to load ${path} (starting with an empty set):`,
      err,
    );
  }
  return refs;
}

function writeAll(fd: number, buf: Buffer): void {
  let written = 0;
  while (written < buf.length) {
    written += writeSync(fd, buf, written, buf.length - written);
  }
}

/**
 * Append refs to the log, durably. Returns true on success. Never throws:
 * failures log loudly and return false (the caller keeps the refs
 * pending). Guards against fusing onto a torn last line.
 */
export function appendSeenRefs(
  refs: string[],
  path: string = seenRefsPath(),
): boolean {
  if (refs.length === 0) return true;
  try {
    mkdirSync(dirname(path), { recursive: true });
    const existed = existsSync(path);
    let prefix = "";
    if (existed && statSync(path).size > 0) {
      const rfd = openSync(path, "r");
      try {
        const size = statSync(path).size;
        const buf = Buffer.alloc(1);
        readSync(rfd, buf, 0, 1, size - 1);
        if (buf[0] !== 0x0a) prefix = "\n";
      } finally {
        closeSync(rfd);
      }
    }
    const payload = prefix + refs.map((r) => r + "\n").join("");
    const fd = openSync(path, "a");
    try {
      writeAll(fd, Buffer.from(payload, "utf8"));
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    if (!existed) {
      // New file: fsync the directory so the entry itself survives a crash.
      try {
        const dfd = openSync(dirname(path), "r");
        try {
          fsyncSync(dfd);
        } finally {
          closeSync(dfd);
        }
      } catch {
        // Directory fsync is best-effort (some filesystems reject it).
      }
    }
    return true;
  } catch (err) {
    console.error(
      `seen-refs: FAILED to persist ${refs.length} ref(s) to ${path}:`,
      err,
    );
    return false;
  }
}

/**
 * Replay-protection store: in-memory Set (hot path) + append-only file
 * (durable record). record() dedupes against the set and appends only
 * new refs; failed appends stay pending and are retried on the next
 * record(). Single-process use: the file is not locked.
 */
export class SeenRefStore {
  readonly refs: Set<string>;
  private pending: string[] = [];
  private readonly path: string;

  constructor(path: string = seenRefsPath()) {
    this.path = path;
    this.refs = loadSeenRefs(path);
  }

  get size(): number {
    return this.refs.size;
  }

  get filePath(): string {
    return this.path;
  }

  has(ref: string): boolean {
    return this.refs.has(ref);
  }

  record(ref: string): void {
    if (this.refs.has(ref)) return;
    this.refs.add(ref);
    this.pending.push(ref);
    this.flush();
  }

  private flush(): void {
    if (this.pending.length === 0) return;
    const batch = this.pending;
    this.pending = [];
    // Synchronous: nothing interleaves, so re-queueing the same batch on
    // failure is exact — no ref is lost or duplicated by the retry.
    if (!appendSeenRefs(batch, this.path)) this.pending = batch;
  }
}
