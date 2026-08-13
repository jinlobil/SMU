from .base import behaviors,text,domain,extension
def adapt(i,t,r):
 rec=text(r,"receiver"); return behaviors("outbound",i,t,r,[("sender",text(r,"senderEmail")),("receiver",rec),("receiver_domain",domain(rec)),("attachment_extension",extension(text(r,"attachment"))),("mail_size",text(r,"size")),("hour",t[11:13] if len(t)>12 else "")])
