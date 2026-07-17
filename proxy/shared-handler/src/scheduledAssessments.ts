import { buildCampaignDigest, buildMonitorDigest, type CampaignLike, type MonitorLike } from './assessmentDigest';
import { assessCampaign } from './campaignAssessment';
import { assessMonitors } from './monitorAssessment';
import { getSharedMonitors } from './monitorStore';
import { getSharedCampaigns, putSharedCampaigns } from './campaignStore';
import { getSharedMonitorAssessments, putSharedMonitorAssessments } from './monitorAssessStore';
import type { ProxyEnv, Storage } from './types';

// Daily server-side ASSESSMENT batch. So the CP-Mon CTI reports and the IP-Mon monitoring report are
// generated once a day with NO browser open, and accumulate into the shared assessment time-series —
// the foundation for the "Assessment Timeline" integrated analysis. Runs on the same daily cron as the
// enrich/魚拓 batches, AFTER them, so it assesses freshly-enriched data.

const HOUR = 3_600_000;
const DUE_MS = 20 * HOUR; // (re)generate only when the newest report for that target is ≳20h old (≈1回/日)
const ASSESS_HISTORY_MAX = 60; // keep ~60 days of reports (matches the web app's mergeAssessments cap)
const CAMPAIGN_MAX_PER_RUN = 25; // bound Claude calls per run; oldest-assessed campaigns go first

/** One report in a time-series (mirrors the web app's CampaignAssessment). */
interface AssessEntry {
  text: string;
  at: number;
  by?: string;
  model?: string;
  tlp?: string;
}
/** Loose view of a shared campaign record (digest fields + its assessment history). */
interface CampaignRecord extends CampaignLike {
  tlp?: string;
  updatedAt?: number;
  assessment?: AssessEntry;
  assessments?: AssessEntry[];
}

/** Union assessment entries by `at`, newest first, capped. */
function mergeEntries(...lists: (AssessEntry[] | undefined)[]): AssessEntry[] {
  const byAt = new Map<number, AssessEntry>();
  for (const l of lists) for (const e of l ?? []) if (e && typeof e.at === 'number' && !byAt.has(e.at)) byAt.set(e.at, e);
  return [...byAt.values()].sort((a, b) => b.at - a.at).slice(0, ASSESS_HISTORY_MAX);
}

/**
 * Generate the daily CP-Mon + IP-Mon Claude assessments and append them to the shared time-series.
 * Throttled to ~once a day per target (skips when the newest report is fresh), tagged `by:'auto'`, and
 * bounded per run. Requires ANTHROPIC_API_KEY; disabled when SCHEDULED_ASSESS=false. Never throws.
 */
export async function runScheduledAssessments(
  store: Storage,
  env: ProxyEnv,
): Promise<{ ipMon: boolean; campaigns: number; skipped: number }> {
  if (!env.anthropicApiKey || env.scheduledAssess === false) return { ipMon: false, campaigns: 0, skipped: 0 };
  const now = Date.now();
  let ipMon = false;
  let campaigns = 0;
  let skipped = 0;

  // ---- IP-Mon: one global monitoring report per day ----
  try {
    const monitors = (await getSharedMonitors(store)) as Record<string, MonitorLike>;
    if (monitors && typeof monitors === 'object' && Object.keys(monitors).length) {
      const arr = (await getSharedMonitorAssessments(store)) as AssessEntry[];
      const list = Array.isArray(arr) ? arr : [];
      const newest = list.reduce((m, e) => Math.max(m, e?.at ?? 0), 0);
      if (now - newest >= DUE_MS) {
        const digest = buildMonitorDigest(monitors, [], 'AMBER');
        const r = await assessMonitors(digest, env);
        if (r.text && !r.error) {
          const next = mergeEntries([{ text: r.text, at: now, by: 'auto', model: r.model, tlp: 'AMBER' }], list);
          await putSharedMonitorAssessments(store, next);
          ipMon = true;
        }
      } else {
        skipped++;
      }
    }
  } catch {
    /* leave the IP-Mon timeline as-is on any error */
  }

  // ---- CP-Mon: one CTI report per non-empty campaign per day (oldest-assessed first, bounded) ----
  try {
    const blob = (await getSharedCampaigns(store)) as Record<string, CampaignRecord>;
    if (blob && typeof blob === 'object') {
      const due = Object.values(blob)
        .filter((c) => c && c.iocs && Object.keys(c.iocs).length)
        .map((c) => {
          const newest = mergeEntries(c.assessments, c.assessment ? [c.assessment] : []).reduce(
            (m, e) => Math.max(m, e.at),
            0,
          );
          return { c, newest };
        })
        .filter((x) => now - x.newest >= DUE_MS)
        .sort((a, b) => a.newest - b.newest);

      let changed = false;
      for (const { c } of due.slice(0, CAMPAIGN_MAX_PER_RUN)) {
        const digest = buildCampaignDigest(c);
        const r = await assessCampaign(digest, env);
        if (!r.text || r.error) continue;
        c.assessments = mergeEntries(
          [{ text: r.text, at: now, by: 'auto', model: r.model, tlp: c.tlp ?? 'AMBER' }],
          c.assessments,
          c.assessment ? [c.assessment] : [],
        );
        c.assessment = c.assessments[0];
        c.updatedAt = now;
        campaigns++;
        changed = true;
      }
      if (changed) await putSharedCampaigns(store, blob);
    }
  } catch {
    /* leave campaigns as-is on any error */
  }

  return { ipMon, campaigns, skipped };
}
