from .base import behaviors,text,domain,extension
def adapt(i,t,r):
 s=text(r,"from"); u=text(r,"ioc"); return behaviors("xdr",i,t,r,[("sender",s),("sender_domain",domain(s)),("sender_ip",text(r,"senderIp")),("recipient",text(r,"to","mailbox")),("subject",text(r,"subject")),("url",u),("url_domain",domain(u)),("attachment_extension",extension(u))])
