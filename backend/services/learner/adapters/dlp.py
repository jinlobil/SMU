from .base import behaviors,text,domain,extension
def adapt(i,t,r):
 d=text(r,"destination","destinationDetail"); return behaviors("dlp",i,t,r,[("user",text(r,"username")),("device",text(r,"computer")),("event_type",text(r,"event")),("destination",d),("destination_domain",domain(d)),("destination_type",text(r,"destinationType")),("file_extension",extension(text(r,"destinationDetail"))),("file_size",text(r,"fileSize"))])
