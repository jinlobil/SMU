import React, { useEffect, useMemo, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { Activity, Bell, ChevronLeft, ChevronRight, Database, FileSearch, Flame, LayoutDashboard, Mail, Menu, Network, RefreshCw, Search, Settings, Shield, Users, X } from 'lucide-react'
import './styles.css'

type Page = { id: string; label: string; group: string; source?: string; icon: React.ElementType }
type RecordResponse = { total: number; page: number; pageSize: number; items: Record<string, unknown>[] }
const pages: Page[] = [
  {id:'dashboard',label:'Dashboard',group:'Overview',icon:LayoutDashboard},
  {id:'detections',label:'Detection - XDR',group:'Detection',source:'detections',icon:Shield},
  {id:'xdr-email',label:'Email - XDR',group:'Detection',source:'xdr-email',icon:Mail},
  {id:'emails',label:'Inbound Mail',group:'Detection',source:'emails',icon:Mail},
  {id:'outbound',label:'Outbound Mail',group:'Detection',source:'emails',icon:Mail},
  {id:'dlp',label:'File',group:'Detection',source:'dlp',icon:FileSearch},
  {id:'timeline',label:'Timeline',group:'Forensics',source:'detections',icon:Activity},
  {id:'sensitive-files',label:'Sensitive Files',group:'Forensics',source:'dlp',icon:FileSearch},
  {id:'sensitive-sites',label:'Sensitive Sites',group:'Forensics',source:'dlp',icon:Network},
  {id:'firewall',label:'Firewall',group:'Response',icon:Flame},
  {id:'easy-query',label:'Easy Query',group:'Response',icon:Search},
  {id:'endpoints',label:'Endpoint',group:'Asset',source:'endpoints',icon:Database},
  {id:'organizations',label:'Organization',group:'Asset',source:'organizations',icon:Users},
  {id:'layout-user',label:'Layout - User',group:'Lab',source:'users',icon:Users},
  {id:'config',label:'Config',group:'System',icon:Settings},
]
const today = new Date().toISOString().slice(0,10)
const weekAgo = new Date(Date.now()-6*86400000).toISOString().slice(0,10)

async function api<T>(path:string, init?:RequestInit):Promise<T>{
  const response=await fetch(path,init); if(!response.ok) throw new Error((await response.text())||'요청 실패'); return response.json()
}
const display=(value:unknown)=> typeof value==='object' ? JSON.stringify(value) : String(value ?? '—')

function App(){
  const [active,setActive]=useState('dashboard'), [collapsed,setCollapsed]=useState(false)
  const [start,setStart]=useState(weekAgo), [end,setEnd]=useState(today), [refresh,setRefresh]=useState(0)
  const [notice,setNotice]=useState<string|null>(null)
  const page=pages.find(p=>p.id===active)!
  const groups=[...new Set(pages.map(p=>p.group))]
  const reindex=async()=>{const job=await api<{id:string}>('/api/jobs/reindex',{method:'POST'});setNotice('데이터 인덱싱을 시작했습니다.');const timer=setInterval(async()=>{const state=await api<{status:string;message:string}>(`/api/jobs/${job.id}`);if(['completed','failed'].includes(state.status)){clearInterval(timer);setNotice(state.message);setRefresh(x=>x+1)}},700)}
  return <div className="app-shell">
    <aside style={{width:collapsed?82:264}} className="sidebar">
      <div className="brand"><div className="brand-mark"><Shield size={22}/></div>{!collapsed&&<div className="fade-in"><strong>SMU</strong><span>Security Center</span></div>}</div>
      <nav>{groups.map(group=><div className="nav-group" key={group}>{!collapsed&&<p>{group}</p>}{pages.filter(p=>p.group===group).map(item=>{const Icon=item.icon;return <button title={item.label} key={item.id} onClick={()=>setActive(item.id)} className={active===item.id?'active':''}><Icon size={19}/>{!collapsed&&<span>{item.label}</span>}{active===item.id&&<i/>}</button>})}</div>)}</nav>
      <button className="collapse" onClick={()=>setCollapsed(x=>!x)}>{collapsed?<ChevronRight/>:<><ChevronLeft/><span>메뉴 접기</span></>}</button>
    </aside>
    <main>
      <header><div><button className="mobile-menu"><Menu/></button><p>{page.group}</p><h1>{page.label}</h1></div><div className="toolbar"><label><span>From</span><input type="date" value={start} onChange={e=>setStart(e.target.value)}/></label><label><span>To</span><input type="date" value={end} onChange={e=>setEnd(e.target.value)}/></label><button className="icon-button" title="인덱싱" onClick={reindex}><RefreshCw size={18}/></button><button className="icon-button"><Bell size={18}/><i/></button></div></header>
      <><section key={active} className="content page-enter">
        {active==='dashboard'?<Dashboard start={start} end={end} refresh={refresh}/>:page.source?<Records page={page} start={start} end={end} refresh={refresh}/>:<ActionPage page={page}/>}
      </section></>
    </main>
    <>{notice&&<div className="toast toast-enter"><Shield size={18}/><span>{notice}</span><button onClick={()=>setNotice(null)}><X size={16}/></button></div>}</>
  </div>
}

function Dashboard({start,end,refresh}:{start:string,end:string,refresh:number}){
 const [data,setData]=useState<any>(null),[error,setError]=useState('')
 useEffect(()=>{setData(null);api<any>(`/api/overview?start=${start}&end=${end}`).then(setData).catch(e=>setError(e.message))},[start,end,refresh])
 if(error)return <Empty title="데이터를 불러오지 못했습니다" detail={error}/>
 if(!data)return <Skeleton/>
 const cards=[['Endpoint Detection',data.metrics.detections,'detections'],['Email XDR',data.metrics['xdr-email'],'xdr'],['Inbound Mail',data.metrics.emails,'mail'],['DLP Events',data.metrics.dlp,'dlp']]
 const max=Math.max(...cards.map(x=>Number(x[1])),1)
 return <><div className="hero"><div><span className="eyebrow">SECURITY OVERVIEW</span><h2>오늘의 보안 상태를 한눈에 확인하세요.</h2><p>{start} — {end} · 로컬 데이터가 안전하게 분석되고 있습니다.</p></div><div className="pulse"><i/><span>All systems operational</span></div></div>
 <div className="metrics">{cards.map(([label,value,tone],i)=><article key={label} className="metric-enter" style={{animationDelay:`${i*.045}s`}}><span className={`metric-icon ${tone}`}><Activity/></span><div><p>{label}</p><strong>{Number(value).toLocaleString()}</strong><small>selected period</small></div></article>)}</div>
 <div className="dashboard-grid"><article className="panel chart"><PanelTitle title="Threat activity" subtitle="선택 기간 이벤트 분포"/><div className="bars">{cards.map(([label,value,tone])=><div key={label}><span>{label}</span><div><i className={String(tone)} style={{width:`${Math.max(Number(value)/max*100,2)}%`}}/></div><b>{Number(value).toLocaleString()}</b></div>)}</div></article><article className="panel posture"><PanelTitle title="Security posture" subtitle="실시간 로컬 인덱스"/><div className="score"><div><strong>92</strong><span>/100</span></div></div><h3>Excellent posture</h3><p>중요 이벤트를 계속 모니터링하고 있습니다.</p></article></div></>
}

function Records({page,start,end,refresh}:{page:Page,start:string,end:string,refresh:number}){
 const [query,setQuery]=useState(''),[debounced,setDebounced]=useState(''),[pageNo,setPageNo]=useState(1),[data,setData]=useState<RecordResponse|null>(null),[selected,setSelected]=useState<Record<string,unknown>|null>(null)
 useEffect(()=>{const t=setTimeout(()=>setDebounced(query),280);return()=>clearTimeout(t)},[query])
 useEffect(()=>{setData(null);api<RecordResponse>(`/api/records/${page.source}?start=${start}&end=${end}&page=${pageNo}&page_size=50&search=${encodeURIComponent(debounced)}`).then(setData)},[page.source,start,end,pageNo,debounced,refresh])
 useEffect(()=>setPageNo(1),[page.source,start,end,debounced])
 const columns=useMemo(()=>{const keys=new Set<string>();data?.items.slice(0,10).forEach(row=>Object.keys(row).forEach(k=>keys.add(k)));return [...keys].slice(0,7)},[data])
 return <><div className="page-intro"><div><span className="eyebrow">{page.group.toUpperCase()}</span><h2>{page.label}</h2><p>기존 SMU 로컬 인덱스에서 실시간으로 조회합니다.</p></div><div className="search"><Search size={17}/><input value={query} onChange={e=>setQuery(e.target.value)} placeholder="전체 필드 검색"/></div></div><article className="panel table-panel">{!data?<Skeleton rows={6}/>:<><div className="table-meta"><span><b>{data.total.toLocaleString()}</b> records</span><small>페이지당 50개</small></div><div className="table-scroll"><table><thead><tr>{columns.map(c=><th key={c}>{c.replaceAll('_',' ')}</th>)}</tr></thead><tbody>{data.items.map((row,i)=><tr key={i} onClick={()=>setSelected(row)}>{columns.map(c=><td key={c} title={display(row[c])}>{display(row[c])}</td>)}</tr>)}</tbody></table>{!data.items.length&&<Empty title="검색 결과가 없습니다" detail="기간 또는 검색어를 변경해 보세요."/>}</div><div className="pagination"><button disabled={pageNo===1} onClick={()=>setPageNo(x=>x-1)}><ChevronLeft/> 이전</button><span>{pageNo} / {Math.max(Math.ceil(data.total/50),1)}</span><button disabled={pageNo*50>=data.total} onClick={()=>setPageNo(x=>x+1)}>다음 <ChevronRight/></button></div></>}</article><>{selected&&<><div className="scrim scrim-enter" onClick={()=>setSelected(null)}/><aside className="drawer drawer-enter"><div><span className="eyebrow">RECORD DETAIL</span><button onClick={()=>setSelected(null)}><X/></button></div><h2>{page.label} 상세</h2><dl>{Object.entries(selected).map(([k,v])=><React.Fragment key={k}><dt>{k}</dt><dd>{display(v)}</dd></React.Fragment>)}</dl></aside></>}</></>
}
function ActionPage({page}:{page:Page}){return <div className="action-grid"><div className="hero"><span className="eyebrow">{page.group.toUpperCase()}</span><h2>{page.label}</h2><p>기존 Python 실행 기능을 위한 로컬 작업 공간입니다.</p></div><article className="panel action-card"><page.icon size={28}/><h3>{page.label} workspace</h3><p>보안상 실행 작업은 로컬 Python 서비스에서 처리되고 결과만 이 화면에 전달됩니다.</p><button>새 작업 준비</button></article></div>}
function PanelTitle({title,subtitle}:{title:string,subtitle:string}){return <div className="panel-title"><div><h3>{title}</h3><p>{subtitle}</p></div><button><Menu size={18}/></button></div>}
function Empty({title,detail}:{title:string,detail:string}){return <div className="empty"><Search/><h3>{title}</h3><p>{detail}</p></div>}
function Skeleton({rows=3}:{rows?:number}){return <div className="skeleton">{Array.from({length:rows}).map((_,i)=><i key={i}/>)}</div>}
createRoot(document.getElementById('root')!).render(<React.StrictMode><App/></React.StrictMode>)
