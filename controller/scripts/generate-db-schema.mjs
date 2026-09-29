import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

// Generate the Worker embedded schema from the SQL migrations.

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const migrationsDir = resolve(root, "db/migrations");
const targetPath = resolve(root, "src/db-schema.ts");

function loadMigrations() {
  const files = readdirSync(migrationsDir).filter((name) => name.endsWith(".sql")).sort();
  if (files.length === 0) throw new Error(`no migration files in ${migrationsDir}`);
  return files.map((file) => {
    const sql = readFileSync(join(migrationsDir, file), "utf8").trimEnd();
    return { name: file.replace(/\.sql$/, ""), sql };
  });
}

function render(migrations) {
  return `// GENERATED FILE — do not edit. Regenerate with: node scripts/generate-db-schema.mjs
// Source of truth: db/migrations/*.sql, applied in filename order.

export interface SchemaMigration {
  /** Migration filename without the .sql extension (e.g. "0001_initial"). */
  name: string;
  sql: string;
}

export const MIGRATIONS: SchemaMigration[] = ${JSON.stringify(migrations, null, 2)};

/** The full schema for a fresh database: every migration concatenated. */
export const SCHEMA_SQL = MIGRATIONS.map((migration) => migration.sql).join("\\n\\n") + "\\n";
`;
}

const migrations = loadMigrations();
writeFileSync(targetPath, render(migrations));
console.log(`generated embedded schema from ${migrations.length} migration(s)`);
