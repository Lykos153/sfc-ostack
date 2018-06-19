############
#  Config  #
############

# MAC address of source and destination instances in the SFC
SRC_MAC = 'fa:16:3e:04:07:36'  # MAC of the Proxy
DST_MAC = 'fa:16:3e:58:25:fb'

BUFFER_SIZE = 8192  # bytes

CTL_IP = '192.168.12.10'
CTL_PORT = 6666

NEXT_IP = ''

ingress_iface = 'eth1'
egress_iface = 'eth2'
