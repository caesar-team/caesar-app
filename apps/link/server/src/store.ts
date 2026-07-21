import { Database } from "bun:sqlite";
import { mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { nanoid } from "nanoid";

export interface ShareRecord {
  id: string;
  size: number;
  meta: string;
  expiresAt: number;
  viewsLeft: number | null;
  createdAt: number;
}

export interface CreateInput {
  blob: Uint8Array;
  meta: string;
  ttlSeconds: number;
  views: number | null;
  now: number;
}

interface ShareRow {
  id: string;
  blob_path: string;
  size: number;
  meta: string;
  expires_at: number;
  views_left: number | null;
  delete_token_hash: string;
  created_at: number;
}

function sha256hex(token: string): string {
  return new Bun.CryptoHasher("sha256").update(token).digest("hex");
}

export class ShareStore {
  private readonly db: Database;
  private readonly blobsDir: string;

  constructor(dbPath: string, dataDir: string) {
    this.blobsDir = join(dataDir, "blobs");
    mkdirSync(this.blobsDir, { recursive: true });

    this.db = new Database(dbPath);
    this.db.run(`
      CREATE TABLE IF NOT EXISTS shares (
        id                TEXT PRIMARY KEY,
        blob_path         TEXT NOT NULL,
        size              INTEGER NOT NULL,
        meta              TEXT NOT NULL,
        expires_at        INTEGER NOT NULL,
        views_left        INTEGER,
        delete_token_hash TEXT NOT NULL,
        created_at        INTEGER NOT NULL
      );
    `);
    this.db.run(
      "CREATE INDEX IF NOT EXISTS idx_shares_expires ON shares(expires_at);",
    );
  }

  private blobPath(id: string): string {
    return join(this.blobsDir, id);
  }

  private deleteBlobFile(path: string): void {
    try {
      unlinkSync(path);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
        throw err;
      }
    }
  }

  private deleteRowAndFile(id: string, blobPath: string): void {
    this.db.run("DELETE FROM shares WHERE id = ?", [id]);
    this.deleteBlobFile(blobPath);
  }

  private readBlobOrNull(path: string): Uint8Array | null {
    try {
      return readFileSync(path);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        return null;
      }
      throw err;
    }
  }

  create(input: CreateInput): { id: string; deleteToken: string } {
    const id = nanoid();
    const deleteToken = nanoid();
    const path = this.blobPath(id);
    const expiresAt = input.now + input.ttlSeconds * 1000;

    writeFileSync(path, input.blob);

    this.db.run(
      `INSERT INTO shares
        (id, blob_path, size, meta, expires_at, views_left, delete_token_hash, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        id,
        path,
        input.blob.byteLength,
        input.meta,
        expiresAt,
        input.views,
        sha256hex(deleteToken),
        input.now,
      ],
    );

    return { id, deleteToken };
  }

  getMeta(id: string, now: number): ShareRecord | null {
    const row = this.db
      .query<ShareRow, [string]>("SELECT * FROM shares WHERE id = ?")
      .get(id);
    if (!row) {
      return null;
    }
    if (row.expires_at <= now) {
      this.deleteRowAndFile(row.id, row.blob_path);
      return null;
    }
    return {
      id: row.id,
      size: row.size,
      meta: row.meta,
      expiresAt: row.expires_at,
      viewsLeft: row.views_left,
      createdAt: row.created_at,
    };
  }

  consumeBlob(id: string, now: number): Uint8Array | null {
    // The DB mutations run inside a transaction (so concurrent last-view reads
    // can't double-spend); the blob unlink is deferred until AFTER commit, since
    // filesystem ops aren't transactional — a crash mid-transaction must never
    // leave a live row pointing at an already-deleted file.
    let blobToDelete: string | null = null;
    const consume = this.db.transaction((): Uint8Array | null => {
      const row = this.db
        .query<ShareRow, [string]>("SELECT * FROM shares WHERE id = ?")
        .get(id);
      if (!row) {
        return null;
      }
      if (row.expires_at <= now || row.views_left === 0) {
        this.db.run("DELETE FROM shares WHERE id = ?", [row.id]);
        blobToDelete = row.blob_path;
        return null;
      }

      // A missing file under a live row is an inconsistency; treat as gone.
      const bytes = this.readBlobOrNull(row.blob_path);
      if (bytes === null) {
        this.db.run("DELETE FROM shares WHERE id = ?", [row.id]);
        blobToDelete = row.blob_path;
        return null;
      }

      if (row.views_left === null) {
        return bytes;
      }
      const next = row.views_left - 1;
      if (next === 0) {
        this.db.run("DELETE FROM shares WHERE id = ?", [row.id]);
        blobToDelete = row.blob_path;
      } else {
        this.db.run("UPDATE shares SET views_left = ? WHERE id = ?", [
          next,
          row.id,
        ]);
      }
      return bytes;
    });

    const result = consume();
    if (blobToDelete !== null) {
      this.deleteBlobFile(blobToDelete);
    }
    return result;
  }

  remove(id: string, deleteToken: string): boolean {
    const row = this.db
      .query<ShareRow, [string]>("SELECT * FROM shares WHERE id = ?")
      .get(id);
    if (!row) {
      return false;
    }
    if (row.delete_token_hash !== sha256hex(deleteToken)) {
      return false;
    }
    this.deleteRowAndFile(row.id, row.blob_path);
    return true;
  }

  sweep(now: number): number {
    const rows = this.db
      .query<Pick<ShareRow, "id" | "blob_path">, [number]>(
        "SELECT id, blob_path FROM shares WHERE expires_at <= ?",
      )
      .all(now);
    for (const row of rows) {
      this.deleteRowAndFile(row.id, row.blob_path);
    }
    return rows.length;
  }

  close(): void {
    this.db.close();
  }
}
