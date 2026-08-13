from .base import behaviors,text,domain
def adapt(i,t,r):
 u=text(r,"url"); return behaviors("firewall",i,t,r,[("destination_ip",text(r,"destinationIp")),("destination_domain",domain(u)),("destination_port",text(r,"destinationPort")),("protocol",text(r,"protocol")),("application",text(r,"application")),("source_zone",text(r,"sourceZone")),("destination_zone",text(r,"destinationZone"))])
