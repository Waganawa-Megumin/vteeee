import { describe, it, expect } from 'vitest';
import { extractIndicators, type EnrichableType, type NormalizedResult } from '@vteeee/shared';
import { DemoClient } from '../api/demoClient';
import { DEMO_INPUT } from '../fixtures/samples';

describe('DemoClient end-to-end against fixtures', () => {
  it('parses the sample input and enriches with correct verdicts/links', async () => {
    const { indicators } = extractIndicators(DEMO_INPUT);
    const enrichable = indicators
      .filter((i) => i.type !== 'unknown' && !i.private)
      .map((i) => ({ value: i.value, type: i.type as EnrichableType, input: i.input }));

    // The private IP must have been excluded from the enrich set.
    expect(enrichable.some((i) => i.value === '192.168.1.10')).toBe(false);

    const results = new Map<string, NormalizedResult>();
    let doneCount = 0;
    await new DemoClient().enrich(
      { indicators: enrichable },
      {
        onProgress: () => {},
        onResult: (r) => results.set(r.value, r),
        onDone: (d) => (doneCount = d.done),
        onError: () => {},
      },
    );

    expect(doneCount).toBe(enrichable.length);
    expect(results.get('1.1.1.1')?.verdict).toBe('harmless');
    expect(results.get('185.220.101.1')?.verdict).toBe('malicious');
    expect(results.get('185.220.101.1')?.gti?.severity).toBe('SEVERITY_HIGH');
    expect(results.get('google.com')?.verdict).toBe('harmless');
    expect(results.get('phishy-malware-example.com')?.verdict).toBe('malicious');
    expect(
      results.get('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f')?.verdict,
    ).toBe('malicious');
    expect(results.get('44d88612fea8a8f36de82e1278abb02f')?.type).toBe('md5');
    expect(results.get('never-scanned-vteeee-7f3a9.com')?.status).toBe('not_found');

    // URL GUI deep-link must use the SHA-256 form; API id is the base64 form.
    const url = results.get('http://phishy-malware-example.com/login.php');
    expect(url?.type).toBe('url');
    expect(url?.links.gui).toMatch(/\/gui\/url\/[a-f0-9]{64}$/);
    expect(url?.links.apiId).toBeTruthy();
  });
});
