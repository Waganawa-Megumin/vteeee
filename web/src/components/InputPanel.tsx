import { useRef, useState } from 'react';
import { useStore } from '../state/store';
import { DEMO_INPUT } from '../fixtures/samples';

export function InputPanel() {
  const rawInput = useStore((s) => s.rawInput);
  const setRawInput = useStore((s) => s.setRawInput);
  const parse = useStore((s) => s.parse);
  const smartParse = useStore((s) => s.smartParse);
  const parsing = useStore((s) => s.parsing);
  const mode = useStore((s) => s.mode);
  const fileRef = useRef<HTMLInputElement>(null);
  const [drag, setDrag] = useState(false);

  async function onFiles(files: FileList | null) {
    if (!files || !files.length) return;
    const texts = await Promise.all(Array.from(files).map((f) => f.text()));
    setRawInput((rawInput ? rawInput + '\n' : '') + texts.join('\n'));
  }

  return (
    <section className="panel input-panel">
      <div className="panel-head">
        <h2>Input</h2>
        <div className="spacer" />
        <button className="btn btn-sm" onClick={() => setRawInput(DEMO_INPUT)}>
          Load sample
        </button>
        <button className="btn btn-sm" onClick={() => fileRef.current?.click()}>
          Upload file…
        </button>
        <input
          ref={fileRef}
          type="file"
          accept=".txt,.csv,.log,.tsv,text/*"
          multiple
          hidden
          onChange={(e) => onFiles(e.target.files)}
        />
      </div>

      <textarea
        className={`input-area${drag ? ' dragover' : ''}`}
        value={rawInput}
        spellCheck={false}
        placeholder={
          'Paste or drop IPs / domains / URLs / hashes — defanged is fine\n' +
          'e.g.  1[.]1[.]1[.]1   hxxps://evil[.]com/login   44d88612fea8a8f36de82e1278abb02f'
        }
        onChange={(e) => setRawInput(e.target.value)}
        onDragOver={(e) => {
          e.preventDefault();
          setDrag(true);
        }}
        onDragLeave={() => setDrag(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDrag(false);
          void onFiles(e.dataTransfer.files);
        }}
      />

      <div className="panel-actions">
        <button className="btn btn-primary" onClick={parse} disabled={!rawInput.trim()}>
          Parse
        </button>
        <button
          className="btn"
          onClick={() => void smartParse()}
          disabled={!rawInput.trim() || parsing}
          title={
            mode === 'demo'
              ? 'Demo: uses the local regex extractor'
              : 'Uses Claude to extract IOCs from messy report text'
          }
        >
          {parsing ? 'Parsing…' : `Smart parse ${mode === 'demo' ? '(regex)' : '(Claude)'}`}
        </button>
        <button className="btn btn-ghost" onClick={() => setRawInput('')} disabled={!rawInput}>
          Clear
        </button>
      </div>
    </section>
  );
}
