from .base import behaviors,text,domain,extension
def adapt(i,t,r):
 recipient=text(r,"to","mailbox"); row={**r}
 # Identity is the protected internal mailbox/user. The external sender remains behavior context only.
 if recipient: row.setdefault("email",recipient.split(",",1)[0]); row.setdefault("userId",recipient.split(",",1)[0].split("@",1)[0])
 s=text(row,"from"); u=text(row,"ioc"); return behaviors("xdr",i,t,row,[("sender",s),("sender_domain",domain(s)),("sender_ip",text(row,"senderIp")),("recipient",recipient),("subject",text(row,"subject")),("url",u),("url_domain",domain(u)),("attachment_extension",extension(u))])
