from . import detection,email_xdr,inbound,outbound,dlp,firewall
ADAPTERS={"detections":detection.adapt,"xdr":email_xdr.adapt,"inbound":inbound.adapt,"outbound":outbound.adapt,"dlp":dlp.adapt,"firewall":firewall.adapt}
