export interface Db {
  query<T = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<{ rows: T[] }>;
  exec(sql: string): Promise<void>;
  withTransaction<T>(fn: (tx: Db) => Promise<T>): Promise<T>;
}
