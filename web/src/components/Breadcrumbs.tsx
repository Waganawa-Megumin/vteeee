import { useStore } from '../state/store';

type Crumb = { label: string; onClick?: () => void };

/** "You are here" trail for the section pages (TOP › IP-Mon › PJ › レポート …). Each segment except the
 *  last navigates up; returns null on the main search view (which is the TOP itself). */
export function Breadcrumbs() {
  const view = useStore((s) => s.view);
  const setView = useStore((s) => s.setView);
  const openMonitorProjects = useStore((s) => s.openMonitorProjects);
  const openMonitorProject = useStore((s) => s.openMonitorProject);
  const openCampaigns = useStore((s) => s.openCampaigns);
  const openCampaign = useStore((s) => s.openCampaign);
  const monitorProjectId = useStore((s) => s.monitorProjectId);
  const monitorProjects = useStore((s) => s.monitorProjects);
  const campaignId = useStore((s) => s.campaignId);
  const campaigns = useStore((s) => s.campaigns);
  const analysisIp = useStore((s) => s.analysisIp);
  const analysisCampaign = useStore((s) => s.analysisCampaign);

  const pjName = (id: string | null) =>
    id === null ? 'All IPs' : id === '__none__' ? '未分類' : (monitorProjects[id]?.name ?? 'PJ');

  const home: Crumb = { label: '🏠 TOP', onClick: () => setView('app') };
  const ipmon: Crumb = { label: 'IP-Mon', onClick: () => openMonitorProjects() };
  const cpmon: Crumb = { label: 'CP-Mon', onClick: () => openCampaigns() };

  let crumbs: Crumb[];
  switch (view) {
    case 'monitor-projects':
      crumbs = [home, { label: 'IP-Mon' }];
      break;
    case 'monitor':
      crumbs = [home, ipmon, { label: pjName(monitorProjectId) }];
      break;
    case 'monitor-assessment':
      crumbs = [home, ipmon, { label: pjName(monitorProjectId), onClick: () => openMonitorProject(monitorProjectId) }, { label: '📋 レポート' }];
      break;
    case 'analysis':
      crumbs = [
        home,
        ipmon,
        { label: pjName(monitorProjectId), onClick: () => openMonitorProject(monitorProjectId) },
        { label: `📈 ${analysisIp ?? ''} 分析` },
      ];
      break;
    case 'campaigns':
      crumbs = [home, { label: 'CP-Mon' }];
      break;
    case 'campaign':
      crumbs = [home, cpmon, { label: campaigns[campaignId ?? '']?.name ?? 'Campaign' }];
      break;
    case 'campaign-analysis': {
      const cid = analysisCampaign?.id;
      crumbs = [
        home,
        cpmon,
        { label: campaigns[cid ?? '']?.name ?? 'Campaign', onClick: cid ? () => openCampaign(cid) : undefined },
        { label: `📈 ${analysisCampaign?.value ?? ''} 分析` },
      ];
      break;
    }
    case 'admin':
      crumbs = [home, { label: 'Manage' }];
      break;
    default:
      return null; // 'app' — the search view is the TOP; no trail
  }

  return (
    <nav className="breadcrumbs" aria-label="現在地">
      {crumbs.map((c, i) => {
        const last = i === crumbs.length - 1;
        return (
          <span className="crumb-wrap" key={`${i}-${c.label}`}>
            {i > 0 && (
              <span className="crumb-sep" aria-hidden>
                ›
              </span>
            )}
            {last || !c.onClick ? (
              <span className="crumb crumb-current" aria-current="page">
                {c.label}
              </span>
            ) : (
              <button className="crumb crumb-link" onClick={c.onClick} title={`${c.label} へ戻る`}>
                {c.label}
              </button>
            )}
          </span>
        );
      })}
    </nav>
  );
}
