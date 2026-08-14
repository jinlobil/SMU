import type { CSSProperties } from "react";

export type Theme = Record<string, string>;
export type ThemeDefinition = {
  key: string; variable: string; label: string; description: string; scope: string; group: string; preview: string[];
};

const d = (key:string, variable:string, label:string, description:string, scope:string, group:string, preview:string[]):ThemeDefinition => ({key,variable,label,description,scope,group,preview});

export const themeDefinitions:ThemeDefinition[] = [
  d("Primary_Blue","--accent-main","주요 강조색","주요 강조색 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","전체 화면 · 버튼 · 활성 상태","강조",["accent-main"]),
  d("Primary_Blue_Dark","--accent-secondary","보조 강조색","보조 강조색 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","Sidebar · 버튼 · Glow","강조",["accent-secondary"]),
  d("Accent_Soft","--accent-soft","장식 강조색","장식 강조색 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","표 · 배지 · 장식","강조",["accent-soft"]),
  d("Accent_Bright","--accent-bright","주요 수치 강조색","주요 수치 강조색 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","제목 · 강조 글씨","강조",["accent-bright"]),
  d("Accent_Secondary_Soft","--accent-secondary-soft","그래프·광원 강조색","그래프·광원 강조색 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","배경 · 장식 · 그래프","강조",["accent-secondary-soft"]),
  d("UI_Background","--app-bg","앱 기본 배경","앱 기본 배경 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","전체 화면","배경과 표면",["app-bg"]),
  d("UI_Background_Deep","--app-bg-deep","깊은 배경","깊은 배경 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","전체 배경 · Sidebar","배경과 표면",["app-bg-deep"]),
  d("UI_Background_Mid","--app-bg-mid","중간 배경","중간 배경 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","Workspace · 보조 영역","배경과 표면",["app-bg-mid"]),
  d("UI_Background_Glow","--app-bg-glow","배경 광원","배경 광원 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","전체 배경 Gradient","배경과 표면",["app-bg-glow"]),
  d("UI_Surface","--surface","기본 카드 배경","기본 카드 배경 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","Dashboard · Config · 목록","배경과 표면",["surface"]),
  d("UI_Surface_Raised","--surface-raised","돌출 카드 배경","돌출 카드 배경 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","요약 카드 · 상세 카드","배경과 표면",["surface-raised"]),
  d("UI_Surface_Secondary","--surface-secondary","내부 영역 배경","내부 영역 배경 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","카드 내부 · 보조 패널","배경과 표면",["surface-secondary"]),
  d("UI_Surface_Toolbar","--surface-toolbar","도구 영역 배경","도구 영역 배경 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","검색 · 필터 · Toolbar","배경과 표면",["surface-toolbar"]),
  d("UI_Input_Background","--input-bg","입력창 배경","입력창 배경 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","모든 입력 컨트롤","배경과 표면",["input-bg"]),
  d("UI_Modal_Background","--modal-bg","팝업 배경","팝업 배경 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","Modal · Raw Detail","배경과 표면",["modal-bg"]),
  d("UI_Raw_Background","--raw-bg","원본 데이터 배경","원본 데이터 배경 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","Raw Detail · 코드","배경과 표면",["raw-bg"]),
  d("Text_Primary","--text-primary","기본 글씨","기본 글씨 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","전체 화면","글자",["text-primary"]),
  d("Text_Bright","--text-bright","강조 글씨","강조 글씨 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","제목 · 버튼 · 선택","글자",["text-bright"]),
  d("Text_Secondary","--text-secondary","보조 글씨","보조 글씨 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","카드 설명 · 표","글자",["text-secondary"]),
  d("Text_Muted","--text-muted","비활성 글씨","비활성 글씨 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","설명 · 메타 정보","글자",["text-muted"]),
  d("Text_Subtle","--text-subtle","최소 강조 글씨","최소 강조 글씨 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","빈 상태 · Placeholder","글자",["text-subtle"]),
  d("Text_Table_Accent","--text-table-accent","테이블 강조 글씨","테이블 강조 글씨 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","Detection · Email · DLP 표","글자",["text-table-accent"]),
  d("Text_Entity","--text-entity","사용자·장비 강조","사용자·장비 강조 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","목록 · Timeline","글자",["text-entity"]),
  d("Text_Department","--text-department","부서 강조","부서 강조 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","목록 · 조직 화면","글자",["text-department"]),
  d("Card_Title_Text","--card-title","카드 제목","카드 제목 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","Dashboard · Config · Modal","글자",["card-title"]),
  d("Card_Border","--card-border","기본 카드 테두리","기본 카드 테두리 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","전체 Card · Panel","테두리",["card-border"]),
  d("Border_Soft","--border-soft","내부 구분선","내부 구분선 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","카드 내부 · Divider","테두리",["border-soft"]),
  d("Border_Strong","--border-strong","입력 영역 테두리","입력 영역 테두리 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","Input · Select · Filter","테두리",["border-strong"]),
  d("Border_Action","--border-action","동작 영역 테두리","동작 영역 테두리 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","Button · Action","테두리",["border-action"]),
  d("Border_Danger","--border-danger","위험 동작 테두리","위험 동작 테두리 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","Danger Button · Error","테두리",["border-danger"]),
  d("Border_Table_Row","--border-table-row","테이블 행 구분선","테이블 행 구분선 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","모든 목록 표","테두리",["border-table-row"]),
  d("Table_Header_Background","--table-head-bg","테이블 헤더 배경","테이블 헤더 배경 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","Detection · Email · DLP · Config","테이블과 상호작용",["table-head-bg"]),
  d("Table_Header_Text","--table-head-text","테이블 헤더 글씨","테이블 헤더 글씨 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","모든 목록 표","테이블과 상호작용",["table-head-text"]),
  d("Table_Selection_Background","--table-selection-bg","선택 행 배경","선택 행 배경 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","목록 · Timeline","테이블과 상호작용",["table-selection-bg"]),
  d("Table_Selection_Text","--table-selection-text","선택 행 글씨","선택 행 글씨 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","목록 · Timeline","테이블과 상호작용",["table-selection-text"]),
  d("Table_Row_Hover","--table-row-hover","테이블 행 Hover","테이블 행 Hover 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","모든 목록 표","테이블과 상호작용",["table-row-hover"]),
  d("Control_Hover_Background","--control-hover-bg","컨트롤 Hover 배경","컨트롤 Hover 배경 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","Button · Filter · Tab","테이블과 상호작용",["control-hover-bg"]),
  d("Focus_Color","--focus-color","입력 포커스","입력 포커스 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","Input · Select · Button","테이블과 상호작용",["focus-color"]),
  d("Status_Success_Text","--status-success","성공 상태","성공 상태 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","상태 · Job · 연결","상태",["status-success"]),
  d("Status_Success_Bright","--status-success-bright","성공 상태 강조","성공 상태 강조 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","Badge · Heartbeat","상태",["status-success-bright"]),
  d("Status_Warning_Text","--status-warning","경고 상태","경고 상태 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","경고 · 진행 상태","상태",["status-warning"]),
  d("Status_Warning_Bright","--status-warning-bright","경고 상태 강조","경고 상태 강조 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","Badge · 알림","상태",["status-warning-bright"]),
  d("Status_Fail_Text","--status-fail","실패 상태","실패 상태 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","Error · 실패 결과","상태",["status-fail"]),
  d("Status_Fail_Bright","--status-fail-bright","실패 상태 강조","실패 상태 강조 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","Danger · Error Glow","상태",["status-fail-bright"]),
  d("Sidebar_Background_Start","--sidebar-bg-start","사이드바 상단 배경","사이드바 상단 배경 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","Sidebar","사이드바",["sidebar-bg-start"]),
  d("Sidebar_Background_End","--sidebar-bg-end","사이드바 하단 배경","사이드바 하단 배경 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","Sidebar","사이드바",["sidebar-bg-end"]),
  d("Sidebar_Text","--sidebar-text","사이드바 기본 글씨","사이드바 기본 글씨 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","Sidebar 메뉴","사이드바",["sidebar-text"]),
  d("Sidebar_Text_Muted","--sidebar-text-muted","사이드바 보조 글씨","사이드바 보조 글씨 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","Sidebar Submenu","사이드바",["sidebar-text-muted"]),
  d("Sidebar_Hover_Background","--sidebar-hover-bg","사이드바 Hover 배경","사이드바 Hover 배경 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","Sidebar 메뉴","사이드바",["sidebar-hover-bg"]),
  d("Sidebar_Selected_Text","--sidebar-selected-text","사이드바 선택 글씨","사이드바 선택 글씨 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","Sidebar 활성 메뉴","사이드바",["sidebar-selected-text"]),
  d("Sidebar_Selected_Background","--sidebar-selected-bg","사이드바 선택 배경","사이드바 선택 배경 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","Sidebar 활성 메뉴","사이드바",["sidebar-selected-bg"]),
  d("Modal_Overlay","--modal-overlay","팝업 뒤 배경","팝업 뒤 배경 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","모든 Modal","모달과 효과",["modal-overlay"]),
  d("Glow_Accent","--glow-accent","주요 네온 광원","주요 네온 광원 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","Card · Button · Animation","모달과 효과",["glow-accent"]),
  d("Glow_Secondary","--glow-secondary","보조 네온 광원","보조 네온 광원 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","배경 · Modal · Animation","모달과 효과",["glow-secondary"]),
  d("Threat_trend_Detection","--trend-detection","Detection 계열 색상","Detection 계열 색상 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","Dashboard 그래프","보안 그래프",["trend-detection"]),
  d("Threat_trend_Detection_XDR","--trend-xdr","Email XDR 계열 색상","Email XDR 계열 색상 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","Dashboard 그래프","보안 그래프",["trend-xdr"]),
  d("Threat_trend_Email","--trend-email","Inbound 계열 색상","Inbound 계열 색상 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","Dashboard 그래프","보안 그래프",["trend-email"]),
  d("Threat_trend_Outbound_Mail","--trend-outbound","Outbound 계열 색상","Outbound 계열 색상 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","Dashboard 그래프","보안 그래프",["trend-outbound"]),
  d("Threat_trend_File","--trend-file","File·DLP 계열 색상","File·DLP 계열 색상 역할이 적용되는 실제 SMU 구성요소에 사용합니다.","Dashboard 그래프","보안 그래프",["trend-file"]),
];

export const cssVariableForKey = Object.fromEntries(themeDefinitions.map(item => [item.key,item.variable]));
export function applyTheme(theme:Theme, target:HTMLElement=document.documentElement) {
  themeDefinitions.forEach(item => { if (theme[item.key]) target.style.setProperty(item.variable,theme[item.key]); });
  window.dispatchEvent(new CustomEvent("smu-theme", {detail:theme}));
}
export function themeStyle(theme:Theme):CSSProperties {
  return Object.fromEntries(themeDefinitions.map(item => [item.variable,theme[item.key]]).filter(([,value])=>Boolean(value))) as CSSProperties;
}
