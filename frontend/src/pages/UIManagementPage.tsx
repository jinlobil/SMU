import { useEffect, useMemo, useRef, useState } from "react";
import { applyTheme, themeDefinitions, themeStyle, type Theme } from "../theme";

type Preset={name:string;theme:Theme};
const clone=(theme:Theme):Theme=>({...theme});

export function UIManagementPage(){
  const [savedTheme,setSavedTheme]=useState<Theme>({}),[draftTheme,setDraftTheme]=useState<Theme>({}),[defaultTheme,setDefaultTheme]=useState<Theme>({});
  const [presets,setPresets]=useState<Preset[]>([]),[presetName,setPresetName]=useState(""),[selectedPreset,setSelectedPreset]=useState("");
  const [selectedKey,setSelectedKey]=useState("Primary_Blue"),[group,setGroup]=useState("강조"),[message,setMessage]=useState(""),[saving,setSaving]=useState(false);
  const groups=useMemo(()=>[...new Set(themeDefinitions.map(item=>item.group))],[]);
  const selected=themeDefinitions.find(item=>item.key===selectedKey)||themeDefinitions[0];
  const highlighted=new Set(selected.preview);
  const previewRef=useRef<HTMLElement>(null);
  useEffect(()=>{previewRef.current?.querySelector(".theme-preview-highlight")?.scrollIntoView({block:"nearest",inline:"nearest",behavior:"smooth"})},[selectedKey]);

  const load=async()=>{
    const [current,defaults,presetPayload]=await Promise.all([
      fetch("/api/config/theme").then(r=>r.json()),fetch("/api/config/theme/default").then(r=>r.json()),fetch("/api/config/theme/presets").then(r=>r.json()),
    ]);
    setSavedTheme(current.data);setDraftTheme(clone(current.data));setDefaultTheme(defaults.data.theme);setPresets(presetPayload.data.items||[]);
  };
  useEffect(()=>{void load().catch(error=>setMessage(String(error)))},[]);
  const update=(key:string,value:string)=>setDraftTheme(current=>({...current,[key]:value}));
  const saveApplied=async()=>{setSaving(true);try{const response=await fetch("/api/config/theme",{method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify(draftTheme)}),payload=await response.json();if(!response.ok)throw new Error(payload?.error?.message||"테마 저장 실패");setSavedTheme(payload.data);setDraftTheme(clone(payload.data));applyTheme(payload.data);setMessage("UI 색상을 저장하고 전체 화면에 적용했습니다.")}catch(error){setMessage(String(error))}finally{setSaving(false)}};
  const savePreset=async()=>{if(!presetName.trim()){setMessage("Preset 이름을 입력하세요.");return}const response=await fetch("/api/config/theme/presets",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name:presetName,theme:draftTheme})}),payload=await response.json();if(!response.ok){setMessage(payload?.error?.message||"Preset 저장 실패");return}setPresets(payload.data.items);setSelectedPreset(presetName.trim());setPresetName("");setMessage("현재 Draft를 Preset으로 저장했습니다.")};
  const loadPreset=()=>{const preset=presets.find(item=>item.name===selectedPreset);if(preset){setDraftTheme(clone(preset.theme));setMessage("Preset을 Draft에 불러왔습니다. 전체 적용 전 Preview를 확인하세요.")}};
  const removePreset=async()=>{if(!selectedPreset||!confirm(`Preset '${selectedPreset}'을 삭제하시겠습니까?`))return;const response=await fetch(`/api/config/theme/presets/${encodeURIComponent(selectedPreset)}`,{method:"DELETE"}),payload=await response.json();setPresets(payload.data.items||[]);setSelectedPreset("");setMessage("Preset을 삭제했습니다.")};
  const restoreDefault=()=>{setDraftTheme(clone(defaultTheme));setMessage("SMU Neon Purple 기본값을 Draft에 불러왔습니다.")};
  const cancel=()=>{setDraftTheme(clone(savedTheme));setMessage("저장하지 않은 변경을 취소했습니다.")};
  const mark=(...names:string[])=>names.some(name=>highlighted.has(name))?" theme-preview-highlight":"";

  return <><header className="topbar"><div><p className="breadcrumb">Config / UI Management</p><h1>UI Management</h1></div><span>{message}</span></header>
    <section className="ui-management-workspace">
      <aside className="config-card ui-settings-panel">
        <header><div><h2>SMU Neon Purple</h2><small>59개 역할별 색상을 편집합니다.</small></div></header>
        <div className="theme-preset-box"><label><span>Theme Preset</span><select value={selectedPreset} onChange={e=>setSelectedPreset(e.target.value)}><option value="">사용자 Preset 선택</option>{presets.map(item=><option key={item.name}>{item.name}</option>)}</select></label><div><button onClick={loadPreset} disabled={!selectedPreset}>불러오기</button><button className="danger-action" onClick={removePreset} disabled={!selectedPreset}>삭제</button></div><label><span>새 Preset 이름</span><input value={presetName} maxLength={60} onChange={e=>setPresetName(e.target.value)} placeholder="예: My Purple Theme"/></label><button onClick={savePreset}>현재 Draft를 Preset으로 저장</button></div>
        <div className="theme-group-tabs">{groups.map(name=><button key={name} className={group===name?"active":""} onClick={()=>setGroup(name)}>{name}</button>)}</div>
        <div className="theme-setting-list">{themeDefinitions.filter(item=>item.group===group).map(item=><div key={item.key} role="button" tabIndex={0} className={`theme-setting-item ${selectedKey===item.key?"selected":""}`} onClick={()=>setSelectedKey(item.key)} onKeyDown={event=>{if(event.key==="Enter"||event.key===" ")setSelectedKey(item.key)}}><span><b>{item.label}</b><small>{item.description}</small><em>{item.scope}</em></span><input aria-label={`${item.label} 색상`} type="color" value={draftTheme[item.key]||defaultTheme[item.key]} onClick={event=>event.stopPropagation()} onChange={event=>update(item.key,event.target.value)}/><code>{draftTheme[item.key]}</code></div>)}</div>
        <footer className="theme-actions"><button onClick={restoreDefault}>기본값 복원</button><button onClick={cancel}>변경 취소</button><button className="primary-action" disabled={saving} onClick={saveApplied}>{saving?"저장 중...":"저장 및 전체 적용"}</button></footer>
      </aside>
      <article ref={previewRef} className="config-card ui-preview-panel" style={themeStyle(draftTheme)}>
        <header><div><h2>실시간 SMU Preview</h2><p><b>{selected.label}</b> · {selected.scope}</p></div><span>선택한 색상의 영향 영역이 표시됩니다.</span></header>
        <div data-theme-tokens="app-bg app-bg-deep app-bg-glow accent-secondary-soft glow-secondary" className={`theme-mini-app${mark("app-bg","app-bg-deep","app-bg-glow","accent-secondary-soft","glow-secondary")}`}>
          <aside data-theme-tokens="sidebar-bg-start sidebar-bg-end sidebar-text sidebar-text-muted sidebar-hover-bg sidebar-selected-text sidebar-selected-bg" className={`theme-mini-sidebar${mark("sidebar-bg-start","sidebar-bg-end","sidebar-text","sidebar-text-muted","sidebar-hover-bg","sidebar-selected-text","sidebar-selected-bg")}`}><strong>SMU</strong><small>Monitoring</small><nav><i>Dashboard</i><i className={mark("accent-secondary","sidebar-selected-text","sidebar-selected-bg","sidebar-hover-bg")}>Detection</i><i>Forensics</i><i>Config</i></nav><span className={mark("status-success","status-success-bright","status-warning","status-warning-bright","status-fail","status-fail-bright","surface-secondary")}>● 백엔드 연결됨</span></aside>
          <main><div className="theme-mini-heading"><div><small>Detection / Email - XDR</small><h3 className={mark("card-title","text-bright")}>Email - XDR</h3></div><button className={mark("accent-main","accent-secondary","text-bright","border-action","control-hover-bg")}>조회</button></div>
            <div className="theme-mini-cards"><section className={mark("surface","surface-raised","app-bg-mid","card-border","app-bg-deep","glow-accent")}><small className={mark("text-muted")}>조회 결과</small><strong className={mark("accent-bright")}>1,284</strong><span className={mark("text-secondary")}>보안 이벤트</span></section><section className={mark("status-success","status-success-bright","status-warning","status-warning-bright","status-fail","status-fail-bright","surface-secondary")}><small className={mark("status-warning","status-warning-bright","text-subtle")}>대기 1</small><strong className={`preview-success${mark("status-success","status-success-bright")}`}>정상</strong><span className={`preview-fail${mark("status-fail","status-fail-bright")}`}>실패 2</span></section><section className={mark("trend-detection","trend-xdr","trend-email","trend-outbound","trend-file","accent-soft")}><small className={mark("accent-soft")}>Security Trend</small><div className="theme-mini-graph"><i className={mark("trend-detection")}/><i className={mark("trend-xdr")}/><i className={mark("trend-email")}/><i className={mark("trend-outbound")}/><i className={mark("trend-file")}/></div></section></div>
            <section data-theme-tokens="surface card-border table-head-bg table-head-text table-selection-bg table-selection-text table-row-hover border-table-row" className={`theme-mini-panel${mark("surface","surface-raised","app-bg-mid","card-border","app-bg-deep","glow-accent")}`}><div className={`theme-mini-toolbar${mark("surface-toolbar","border-soft")}`}><select className={mark("input-bg","border-strong","focus-color","text-primary","text-subtle")}><option>ALL</option></select><input className={mark("input-bg","border-strong","focus-color","text-primary","text-subtle")} placeholder="검색어 입력"/><button className={mark("accent-main","accent-secondary","text-bright","border-action","control-hover-bg")}>+ 조건 추가</button></div><table className={mark("table-head-bg","table-head-text","table-selection-bg","table-selection-text","table-row-hover","border-table-row","text-secondary","text-table-accent","text-department")}><thead className={mark("table-head-bg","table-head-text","text-table-accent")}><tr><th>Time</th><th>Rule</th><th>User</th><th>Department</th><th>Detail</th></tr></thead><tbody><tr className={mark("table-row-hover","border-table-row")}><td className={mark("text-primary")}>11:28:04</td><td className={mark("text-secondary")}>Threat detected</td><td className={`preview-entity${mark("text-entity")}`}>HONG</td><td className={`preview-dept${mark("text-department")}`}>보안팀</td><td>보기</td></tr><tr className={`selected${mark("table-selection-bg","table-selection-text")}`}><td>11:20:31</td><td>Mail IOC</td><td>KIM</td><td>인프라팀</td><td>보기</td></tr></tbody></table></section>
          </main>
          <div data-theme-tokens="modal-overlay" className={`theme-mini-overlay${mark("modal-overlay")}`}><section data-theme-tokens="modal-bg border-strong border-soft" className={`theme-mini-modal${mark("modal-bg","border-strong","border-soft")}`}><header><b className={mark("card-title")}>Raw Detail</b><button className={mark("border-danger")}>×</button></header><pre className={mark("raw-bg","text-secondary")}>{`{ "status": "detected", "severity": "high" }`}</pre></section></div>
          <div className={`theme-preview-glow${mark("glow-accent","glow-secondary")}`}/>
        </div>
      </article>
    </section>
  </>;
}
