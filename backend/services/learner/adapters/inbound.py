from .base import behaviors,text,domain,extension
def adapt(i,t,r):
 recipient=text(r,"to"); row={**r}
 # Inbound identity is the internal recipient; never promote the external sender to person identity.
 if recipient: row.setdefault("email",recipient); row.setdefault("userId",recipient.split("@",1)[0])
 s=text(row,"from"); a=text(row,"attachment"); return behaviors("inbound",i,t,row,[("sender",s),("sender_domain",domain(s)),("sender_ip",text(row,"senderIp")),("recipient",recipient),("subject",text(row,"subject")),("attachment_extension",extension(a)),("mail_size",text(row,"size"))])
