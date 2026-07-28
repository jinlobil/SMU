from datetime import date
from pathlib import Path
from backend.services.dashboard import DashboardService
class ReportService:
 def __init__(self,root:Path):self.root=root;self.dashboard=DashboardService(root)
 def build(self,start:date,end:date,progress=lambda m:None):
  progress("보고서 데이터 집계 중");data=self.dashboard.summary(start,end);progress("PDF 생성 중")
  from reportlab.lib import colors
  from reportlab.lib.pagesizes import A4
  from reportlab.lib.styles import getSampleStyleSheet
  from reportlab.lib.enums import TA_CENTER
  from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle,PageBreak
  out=self.root/"reports"/f"security_report_{start}_{end}.pdf";out.parent.mkdir(parents=True,exist_ok=True);styles=getSampleStyleSheet();styles["Title"].alignment=TA_CENTER
  story=[Paragraph("SMU Security Monitoring Report",styles["Title"]),Paragraph(f"Period: {start} ~ {end}",styles["Normal"]),Spacer(1,20)]
  metrics=[["Metric","Value"],["Endpoints",data["endpoints"]["total"]],["PC",data["endpoints"]["pc"]],["Server",data["endpoints"]["server"]],["Departments",data["organization"]["departments"]],["Users",data["organization"]["users"]]]+[[k,v] for k,v in data["totals"].items()]
  table=Table(metrics,colWidths=[280,150]);table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#0863e2")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.5,colors.HexColor("#d8e8ff")),("PADDING",(0,0),(-1,-1),8)]));story+=[table,Spacer(1,20),Paragraph("Top Analysis",styles["Heading2"])]
  tops=[["Rank","Hostname","Rule","Sender IP"]]
  for i in range(6):tops.append([i+1,*[(data["top"][key][i][0]+f" ({data['top'][key][i][1]})") if i<len(data["top"][key]) else "" for key in ("hosts","rules","senders")]])
  t=Table(tops,colWidths=[35,145,210,120]);t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#eef5ff")),("GRID",(0,0),(-1,-1),.4,colors.grey),("FONTSIZE",(0,0),(-1,-1),8),("PADDING",(0,0),(-1,-1),6)]));story.append(t)
  SimpleDocTemplate(str(out),pagesize=A4,rightMargin=36,leftMargin=36,topMargin=40,bottomMargin=40).build(story);return {"path":str(out),"filename":out.name}
