from .base import behaviors,text,domain,extension
def adapt(i,t,r):
 s=text(r,"from"); a=text(r,"attachment"); return behaviors("inbound",i,t,r,[("sender",s),("sender_domain",domain(s)),("sender_ip",text(r,"senderIp")),("recipient",text(r,"to")),("subject",text(r,"subject")),("attachment_extension",extension(a)),("mail_size",text(r,"size"))])
