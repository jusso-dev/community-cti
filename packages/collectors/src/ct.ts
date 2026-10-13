export function nextBackoffMs(attempt: number): number {
  return Math.min(30_000, 1000 * 2 ** Math.max(0, attempt));
}

export function crtshUrl(keyword: string): string {
  return `https://crt.sh/?q=${encodeURIComponent(`%.${keyword}`)}&output=json`;
}

export interface CertMessage {
  allDomains: string[];
}

export function readCertMessage(payload: string): CertMessage {
  const body = JSON.parse(payload) as { data?: { leaf_cert?: { all_domains?: string[] } } };
  return { allDomains: body.data?.leaf_cert?.all_domains ?? [] };
}

export interface CertSocket {
  send(text: string): void;
  close(): void;
  onMessage(handler: (payload: string) => void): void;
  onClose(handler: () => void): void;
}

/** Reconnects with backoff. The caller supplies the socket so tests do not open a network connection. */
export function attachCertstream(connect: () => CertSocket, onName: (name: string) => void, sleep: (ms: number) => Promise<void>): { stop: () => void } {
  let stopped = false;
  let attempt = 0;
  const loop = async () => {
    while (!stopped) {
      const socket = connect();
      let closed = false;
      socket.onMessage((payload) => {
        for (const name of readCertMessage(payload).allDomains) onName(name);
      });
      socket.onClose(() => {
        closed = true;
      });
      while (!closed && !stopped) await sleep(5);
      if (stopped) {
        socket.close();
        return;
      }
      await sleep(nextBackoffMs(attempt));
      attempt += 1;
    }
  };
  void loop();
  return { stop: () => { stopped = true; } };
}
