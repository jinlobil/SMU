from .base import behaviors,text
def adapt(i,t,r):
 p=text(r,"file"); parent=text(r,"parentProcess"); return behaviors("detections",i,t,r,[("process",p),("parent_process",parent),("parent_child",f"{parent} → {p}" if parent and p else ""),("command_line",text(r,"commandLine")),("file_path",text(r,"filePath","file")),("detection_rule",text(r,"rule"))])
