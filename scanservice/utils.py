import ipaddress


def ip2num(ip):
    ip = [int(x) for x in ip.split('.')]
    return ip[0] << 24 | ip[1] << 16 | ip[2] << 8 | ip[3]


def num2ip(num):
    return '%s.%s.%s.%s' % ((num & 0xff000000) >> 24,
                            (num & 0x00ff0000) >> 16,
                            (num & 0x0000ff00) >> 8,
                            num & 0x000000ff
                            )


def continuous_ip_handler(ip):
    start, end = [ip2num(x) for x in ip.split('-')]
    return [num2ip(num) for num in range(start, end + 1) if num & 0xff]


def ip_mask_handler(ip):
    return [str(x) for x in ipaddress.ip_network(ip, False)]


def ip_format(ip):
    if '-' in ip:
        return continuous_ip_handler(ip)
    else:
        return [ip]
