import { beforeEach, describe, expect, it } from 'vitest';
import { useStore } from '../state/store';

// The store persists to localStorage; the vitest env is `node`, so provide a minimal in-memory shim.
const _mem = new Map<string, string>();
(globalThis as unknown as { localStorage: Storage }).localStorage = {
  get length() {
    return _mem.size;
  },
  clear: () => _mem.clear(),
  getItem: (k: string) => (_mem.has(k) ? _mem.get(k)! : null),
  key: (i: number) => Array.from(_mem.keys())[i] ?? null,
  removeItem: (k: string) => {
    _mem.delete(k);
  },
  setItem: (k: string, v: string) => {
    _mem.set(k, String(v));
  },
};

// The IP-Mon grouping feature: setMonitorGroup assigns/clears an arbitrary group label on the given
// IPs, persists it (raw stripped) to localStorage, and — with no proxy configured — does no network.
describe('monitor grouping', () => {
  beforeEach(() => {
    localStorage.clear();
    useStore.setState({
      monitors: {},
      settings: { ...useStore.getState().settings, proxyBaseUrl: null, shareMonitors: false },
    });
  });

  it('assigns a group to only the chosen IPs and persists it', async () => {
    const s = useStore.getState();
    await s.addMonitor('1.1.1.1');
    await s.addMonitor('2.2.2.2');

    await useStore.getState().setMonitorGroup(['1.1.1.1'], 'APT29');

    expect(useStore.getState().monitors['1.1.1.1'].group).toBe('APT29');
    expect(useStore.getState().monitors['2.2.2.2'].group).toBeUndefined();

    const saved = JSON.parse(localStorage.getItem('vteeee.monitors')!);
    expect(saved['1.1.1.1'].group).toBe('APT29');
  });

  it('treats a blank name as "ungroup" (clears the label)', async () => {
    const s = useStore.getState();
    await s.addMonitor('3.3.3.3');
    await useStore.getState().setMonitorGroup(['3.3.3.3'], 'Botnet');
    expect(useStore.getState().monitors['3.3.3.3'].group).toBe('Botnet');

    await useStore.getState().setMonitorGroup(['3.3.3.3'], '   ');
    expect(useStore.getState().monitors['3.3.3.3'].group).toBeUndefined();
  });

  it('bulk-assigns several IPs at once', async () => {
    const s = useStore.getState();
    await s.addMonitor('4.4.4.4');
    await s.addMonitor('5.5.5.5');
    await useStore.getState().setMonitorGroup(['4.4.4.4', '5.5.5.5'], 'C2');
    const m = useStore.getState().monitors;
    expect(m['4.4.4.4'].group).toBe('C2');
    expect(m['5.5.5.5'].group).toBe('C2');
  });
});
