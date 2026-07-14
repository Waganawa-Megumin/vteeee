import { generateClaudeReport } from './claudeReport';
import type { ProxyEnv } from './types';

// An IP-MONITORING (運用) prompt — NOT a CTI attribution report. The reader runs a continuous watch on a
// set of IPs (Shodan network alerts + vteeee enrichment). They want to know how the watchlist is MOVING:
// attack-surface changes (ports/services), risk/threat-intel drift, geographic/ASN spread, and whether
// the monitoring itself is healthy (when did Shodan checks / enrichment last run, coverage gaps) — broken
// down BY GROUP. Grounded in the digest, every observation tied to a specific IP.
const MONITOR_SYSTEM = `あなたは継続的IPモニタリング（surface monitoring / attack-surface management）を担当する運用アナリストです。監視対象IP群の集計・各IPのエンリッチ情報・Shodan再観測（監視結果）・時系列変化(JSON)を受け取り、「IP監視（IP-MON）運用レポート」を日本語のMarkdownで作成してください。これはCTIの攻撃者アトリビューション・レポートではありません。あくまで**監視対象の状態と変化・監視運用の健全性**に焦点を当てた運用レポートです。適度に絵文字を使い、読みやすく。

先頭に必ず1行で \`TLP:<レベル>\`（入力の tlp を使用）を記載。続けて以下の見出し構成で記述する:

## 🛰 モニタリング現況サマリ
監視規模（対象IP数・グループ数・監視期間）、いま注意すべき変化を3〜5行で。全体のリスク傾向（悪性/要注意/高Abuseの件数）に触れる。

## 📊 グループ別モニタリング状況
**グループごとに**小見出し（###）を立て、各グループの構成（IP数・国/ASNの傾向）・リスク状況（悪性/要注意/変化ありの件数）・そのグループで今注目すべきホストを、**具体的なIP値を明記して**述べる。グループが無い場合は Ungrouped として扱う。

## 🔀 アタックサーフェス変動（ポート/サービス）
Shodan再観測やエンリッチ履歴から読み取れる**開放/閉塞したポート・稼働サービスの変化**を、**どのIPがいつ何を開いた/閉じたか**具体的に。新規CVEの出現も含む。表(Markdown table: IP | 変化 | 時期)で整理してよい。変化が無ければ「大きな変動なし」と明記。

## 📈 リスク・脅威情報の変動
時系列で**悪性判定・AbuseIPDB・Recorded Future リスクスコア・検知数**がどう推移したか。上昇/低下を**具体的なIPと数値の推移（例: \`x.x.x.x\` abuse 40→85）**で示す。

## 🌍 地理・インフラ分布
MaxMind等に基づく国・ASN/組織の分布傾向。集中している国/ASN、地理的な広がりや偏りを述べる（地図・統計は別途UIに表示されるので、ここでは傾向の解釈を中心に）。

## ⏱ Shodanスキャン運用状況
**いつスキャン（Shodan再観測 check / エンリッチ）が走ったか**を読み取り、監視の鮮度を評価する。最近チェックされたIP・長期間チェック/エンリッチされていないIP（監視の空白）・自動監視(Auto)の対象数を挙げ、カバレッジの穴を具体的なIPで指摘する。

## 🚨 注意ホスト & 推奨アクション
優先的に確認/対応すべきホストを**具体的IP**で列挙し、運用上の推奨（再チェック・再エンリッチ・グループ整理・アラート設定など）を優先度付きで。

## 🕳 モニタリングギャップ
不足している観測・エンリッチ、次に取得/確認すべきデータ、監視から漏れていそうな観点。

ルール:
- 【対象を特定して書く】観測事実（開放ポート・CVE・悪性判定・abuse/RFスコア・国/ASN・変化など）は、必ず**どのIPか具体値を明記**する。集約値だけで終えない。悪い例:「3389が開いた」。良い例:「\`203.0.113.5\` で 3389/RDP が新規開放（AS### · 米国）」。該当が複数あれば代表例を数件挙げる。入力の groups[].hosts / surfaceChanges / riskThreatChanges / shodanScans 配列を根拠に使う。
- これは運用モニタリングレポート。攻撃者の特定・アトリビューション・キャンペーン命名などの推測は**しない**（求められていない）。あくまで「監視対象がどう動いたか」「監視は行き届いているか」を述べる。
- 入力に analystNote（アナリストの背景メモ）があれば評価に反映（空/無ければ無視）。
- データに無い事実（IP値・CVE・数値など）を捏造しない。引用するIP/CVE/数値は入力データのものだけ。
- 事実（データに存在）と解釈（分析）を区別する。
- 簡潔かつ実務的に。箇条書き・表を適宜使う。出力はレポート本文(Markdown)のみ。`;

/**
 * Generate a Claude IP-monitoring (operational) report from a per-group monitor digest. Requires
 * ANTHROPIC_API_KEY; long reports are kept complete via assistant-prefill continuation.
 */
export async function assessMonitors(
  digest: unknown,
  env: ProxyEnv,
): Promise<{ text: string; model?: string; error?: string; truncated?: boolean }> {
  return generateClaudeReport(MONITOR_SYSTEM, digest, env, {
    missingKeyError:
      'このプロキシに ANTHROPIC_API_KEY が未設定のため、IP-MON運用レポートは生成できません（管理者に登録を依頼してください）。',
  });
}
