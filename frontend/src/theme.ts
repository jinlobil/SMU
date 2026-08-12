import type { CSSProperties } from "react";

export type Theme = Record<string, string>;
export type ThemeDefinition = {
  key: string; variable: string; label: string; description: string; scope: string; group: string; preview: string[];
};

const d = (key:string, variable:string, label:string, description:string, scope:string, group:string, preview:string[]):ThemeDefinition => ({key,variable,label,description,scope,group,preview});

export const themeDefinitions:ThemeDefinition[] = [
  d("Primary_Blue","--accent-main","메인 핑크","주요 버튼과 활성 메뉴의 핵심 강조색입니다.","전체 화면 · 버튼 · 활성 상태","강조",["button","nav","graph"]),
  d("Primary_Blue_Dark","--accent-secondary","메인 퍼플","핑크와 함께 그라데이션과 보조 강조에 사용됩니다.","Sidebar · 버튼 · Glow","강조",["nav","button","glow"]),
  d("Accent_Soft","--accent-soft","부드러운 핑크","보조 라벨과 은은한 강조를 표현합니다.","표 · 배지 · 장식","강조",["table","badge"]),
  d("Accent_Bright","--accent-bright","밝은 핑크","강한 텍스트 강조와 포커스 장식에 사용됩니다.","제목 · 강조 글씨","강조",["title","input"]),
  d("Accent_Secondary_Soft","--accent-secondary-soft","부드러운 퍼플","보조 그래디언트와 분위기 효과에 사용됩니다.","배경 · 장식 · 그래프","강조",["background","graph"]),
  d("UI_Background","--app-bg","앱 전체 배경","모든 페이지의 기본 바탕색입니다.","전체 화면","배경과 표면",["background"]),
  d("UI_Background_Deep","--app-bg-deep","깊은 배경","가장 깊은 레이어와 그림자의 기반색입니다.","전체 배경 · Sidebar","배경과 표면",["background","sidebar"]),
  d("UI_Background_Mid","--app-bg-mid","중간 배경","배경과 카드 사이의 중간 깊이를 만듭니다.","Workspace · 보조 영역","배경과 표면",["background","toolbar"]),
  d("UI_Background_Glow","--app-bg-glow","배경 광원","페이지 배경의 보라색 광원입니다.","전체 배경 Gradient","배경과 표면",["background","glow"]),
  d("UI_Surface","--surface","기본 카드 배경","일반 Card와 Panel의 기본 표면입니다.","Dashboard · Config · 목록","배경과 표면",["card"]),
  d("UI_Surface_Raised","--surface-raised","돌출 카드 배경","기본 카드보다 앞에 있는 표면을 표현합니다.","요약 카드 · 상세 카드","배경과 표면",["card","modal"]),
  d("UI_Surface_Secondary","--surface-secondary","보조 표면","카드 내부의 구분된 보조 영역입니다.","카드 내부 · 보조 패널","배경과 표면",["card","state"]),
  d("UI_Surface_Toolbar","--surface-toolbar","도구 모음 배경","검색·필터 도구 모음의 표면입니다.","검색 · 필터 · Toolbar","배경과 표면",["toolbar"]),
  d("UI_Input_Background","--input-bg","입력창 배경","Input, Select, Textarea의 배경입니다.","모든 입력 컨트롤","배경과 표면",["input"]),
  d("UI_Modal_Background","--modal-bg","모달 배경","상세보기와 편집 Modal 본문의 배경입니다.","Modal · Raw Detail","배경과 표면",["modal"]),
  d("UI_Raw_Background","--raw-bg","원본 데이터 배경","Raw JSON/코드 표시 영역의 깊은 배경입니다.","Raw Detail · 코드","배경과 표면",["raw"]),
  d("Text_Primary","--text-primary","기본 글자","본문과 주요 정보의 기본 글자색입니다.","전체 화면","글자",["text","table"]),
  d("Text_Bright","--text-bright","강한 글자","제목과 강조 정보에 사용하는 가장 밝은 글자색입니다.","제목 · 버튼 · 선택","글자",["title","button"]),
  d("Text_Secondary","--text-secondary","보조 글자","설명과 테이블 본문의 보조 글자색입니다.","카드 설명 · 표","글자",["text","table"]),
  d("Text_Muted","--text-muted","흐린 글자","도움말과 중요도가 낮은 정보에 사용합니다.","설명 · 메타 정보","글자",["muted"]),
  d("Text_Subtle","--text-subtle","아주 흐린 글자","비활성·빈 상태 등 가장 낮은 계층의 글자색입니다.","빈 상태 · Placeholder","글자",["muted","input"]),
  d("Text_Table_Accent","--text-table-accent","테이블 강조 글자","테이블 Header와 주요 Cell의 핑크 강조색입니다.","Detection · Email · DLP 표","글자",["table"]),
  d("Text_Entity","--text-entity","대상 정보 글자","Hostname/User 등 핵심 Entity의 강조색입니다.","목록 · Timeline","글자",["table","title"]),
  d("Text_Department","--text-department","부서 정보 글자","부서 Badge와 관련 정보의 보라 강조색입니다.","목록 · 조직 화면","글자",["badge","table"]),
  d("Card_Title_Text","--card-title","카드 제목 글자","카드와 관리 화면 제목에 사용하는 노란 강조색입니다.","Dashboard · Config · Modal","글자",["title","card","modal"]),
  d("Card_Border","--card-border","기본 카드 테두리","Card와 Panel의 기본 경계선입니다.","전체 Card · Panel","테두리",["card"]),
  d("Border_Soft","--border-soft","부드러운 테두리","내부 구분선과 약한 경계에 사용합니다.","카드 내부 · Divider","테두리",["card","table"]),
  d("Border_Strong","--border-strong","강한 테두리","입력창과 활성 영역의 명확한 경계입니다.","Input · Select · Filter","테두리",["input","toolbar"]),
  d("Border_Action","--border-action","동작 테두리","편집·저장 등 동작 버튼의 테두리입니다.","Button · Action","테두리",["button"]),
  d("Border_Danger","--border-danger","위험 테두리","삭제와 실패 동작을 구분합니다.","Danger Button · Error","테두리",["state","button"]),
  d("Border_Table_Row","--border-table-row","테이블 행 구분선","테이블 각 행의 구분선입니다.","모든 목록 표","테두리",["table"]),
  d("Table_Header_Background","--table-head-bg","테이블 헤더 배경","목록 표의 Header 배경입니다.","Detection · Email · DLP · Config","테이블과 상호작용",["table"]),
  d("Table_Header_Text","--table-head-text","테이블 헤더 글자","목록 표 Header의 글자색입니다.","모든 목록 표","테이블과 상호작용",["table"]),
  d("Table_Selection_Background","--table-selection-bg","선택 행 배경","선택한 테이블 행의 배경입니다.","목록 · Timeline","테이블과 상호작용",["table"]),
  d("Table_Selection_Text","--table-selection-text","선택 행 글자","선택한 테이블 행의 글자색입니다.","목록 · Timeline","테이블과 상호작용",["table"]),
  d("Table_Row_Hover","--table-row-hover","행 Hover 배경","마우스를 올린 테이블 행의 배경입니다.","모든 목록 표","테이블과 상호작용",["table"]),
  d("Control_Hover_Background","--control-hover-bg","컨트롤 Hover 배경","버튼·필터에 마우스를 올렸을 때의 배경입니다.","Button · Filter · Tab","테이블과 상호작용",["button","toolbar"]),
  d("Focus_Color","--focus-color","포커스 색","키보드 포커스와 입력 활성 상태를 표시합니다.","Input · Select · Button","테이블과 상호작용",["input"]),
  d("Status_Success_Text","--status-success","성공 상태","정상 연결과 성공 결과의 기본색입니다.","상태 · Job · 연결","상태",["state"]),
  d("Status_Success_Bright","--status-success-bright","밝은 성공 상태","성공 상태의 강한 Highlight입니다.","Badge · Heartbeat","상태",["state","glow"]),
  d("Status_Warning_Text","--status-warning","경고 상태","주의 또는 진행 대기 상태의 기본색입니다.","경고 · 진행 상태","상태",["state"]),
  d("Status_Warning_Bright","--status-warning-bright","밝은 경고 상태","경고 Badge와 중요 알림의 강조색입니다.","Badge · 알림","상태",["state","badge"]),
  d("Status_Fail_Text","--status-fail","실패 상태","오류와 실패 결과의 기본색입니다.","Error · 실패 결과","상태",["state"]),
  d("Status_Fail_Bright","--status-fail-bright","밝은 실패 상태","삭제·실패의 강한 Highlight입니다.","Danger · Error Glow","상태",["state","glow"]),
  d("Sidebar_Background_Start","--sidebar-bg-start","사이드바 시작 배경","Sidebar Gradient의 시작색입니다.","Sidebar","사이드바",["sidebar"]),
  d("Sidebar_Background_End","--sidebar-bg-end","사이드바 끝 배경","Sidebar Gradient의 끝색입니다.","Sidebar","사이드바",["sidebar"]),
  d("Sidebar_Text","--sidebar-text","사이드바 글자","Sidebar 메뉴의 기본 글자색입니다.","Sidebar 메뉴","사이드바",["sidebar"]),
  d("Sidebar_Text_Muted","--sidebar-text-muted","사이드바 흐린 글자","Sidebar 보조 메뉴와 상태의 흐린 글자색입니다.","Sidebar Submenu","사이드바",["sidebar"]),
  d("Sidebar_Hover_Background","--sidebar-hover-bg","사이드바 Hover","Sidebar 메뉴 Hover 배경입니다.","Sidebar 메뉴","사이드바",["sidebar"]),
  d("Sidebar_Selected_Text","--sidebar-selected-text","선택 메뉴 글자","현재 선택된 Sidebar 메뉴 글자색입니다.","Sidebar 활성 메뉴","사이드바",["sidebar"]),
  d("Sidebar_Selected_Background","--sidebar-selected-bg","선택 메뉴 배경","현재 선택된 Sidebar 메뉴 배경입니다.","Sidebar 활성 메뉴","사이드바",["sidebar"]),
  d("Modal_Overlay","--modal-overlay","모달 바깥 배경","Modal 뒤 화면을 어둡게 가리는 Overlay입니다.","모든 Modal","모달과 효과",["overlay","modal"]),
  d("Glow_Accent","--glow-accent","핑크 네온 광원","핑크 계열 Shadow와 Neon Glow의 기반색입니다.","Card · Button · Animation","모달과 효과",["glow"]),
  d("Glow_Secondary","--glow-secondary","퍼플 네온 광원","퍼플 계열 Shadow와 배경 Glow의 기반색입니다.","배경 · Modal · Animation","모달과 효과",["glow","background"]),
  d("Threat_trend_Detection","--trend-detection","Detection 그래프","Dashboard Detection Series 색상입니다.","Dashboard 그래프","보안 그래프",["graph"]),
  d("Threat_trend_Detection_XDR","--trend-xdr","Email XDR 그래프","Dashboard Email XDR Series 색상입니다.","Dashboard 그래프","보안 그래프",["graph"]),
  d("Threat_trend_Email","--trend-email","Inbound 그래프","Dashboard Inbound Series 색상입니다.","Dashboard 그래프","보안 그래프",["graph"]),
  d("Threat_trend_Outbound_Mail","--trend-outbound","Outbound 그래프","Dashboard Outbound Series 색상입니다.","Dashboard 그래프","보안 그래프",["graph"]),
  d("Threat_trend_File","--trend-file","File 그래프","Dashboard File/DLP Series 색상입니다.","Dashboard 그래프","보안 그래프",["graph"]),
];

export const cssVariableForKey = Object.fromEntries(themeDefinitions.map(item => [item.key,item.variable]));
export function applyTheme(theme:Theme, target:HTMLElement=document.documentElement) {
  themeDefinitions.forEach(item => { if (theme[item.key]) target.style.setProperty(item.variable,theme[item.key]); });
  window.dispatchEvent(new CustomEvent("smu-theme", {detail:theme}));
}
export function themeStyle(theme:Theme):CSSProperties {
  return Object.fromEntries(themeDefinitions.map(item => [item.variable,theme[item.key]]).filter(([,value])=>Boolean(value))) as CSSProperties;
}
