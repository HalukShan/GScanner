import psutil
import re
import socket


def get_adapter():
    adpater_info = {}
    info = psutil.net_if_addrs()
    for k, v in info.items():
        if v[0][0] == 2 and not v[0][1] == '127.0.0.1':
            adpater_info[k] = [v[0][1], v[1][1]]
    return adpater_info


def check_ip(ip):
    pattern = re.compile(r"^(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])(\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)){3}(-(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)){0,1}$")
    result = pattern.search(ip)
    if result:
        if result.group(4):
            return int(result.group(4)[1:]) > int(result.group(3))
        else:
            return True
    else:
        return False


def check_domain(host):
    pattern = re.compile(r"^(?=^.{3,255}$)[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$")
    if pattern.search(host):
        try:
            socket.getaddrinfo(host, None)
            return True
        except:
            return False


def check_port(port):
    pattern = re.compile(r"^([1-9]\d{0,3}|0|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])(-([1-9]\d{0,3}|0|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])){0,1}$")
    result = pattern.search(port)
    if result:
        if result.group(2):
            return int(result.group(2)[1:]) > int(result.group(1))
        else:
            return True
    else:
        return False


def get_hosts_list(text):
    hosts_list = []
    for host in text.split('|'):
        if check_ip(host):
            if '-' in host:
                hosts_list.extend(get_ip_range(host))
            else:
                hosts_list.append(host)
        elif check_domain(host):
            hosts_list.append(host)
        else:
            return None
    return hosts_list


def get_ports_list(text):
    if text == '':
        return []
    ports_list = []
    for port in text.split("|"):
        if check_port(port):
            if '-' in port:
                ports_list.extend(get_port_range(port))
            else:
                ports_list.append(port)
        else:
            return "error"
    return ports_list


def get_port_range(port):
    left, right = port.split('-')
    return [str(port) for port in range(int(left), int(right) + 1)]


def get_ip_range(ip):
    r = ip.split('-')
    index = r[0].rindex('.')
    left = int(r[0][index + 1:])
    right = int(r[1])
    return [ip[:index + 1] + str(i) for i in range(left, right + 1)]


def get_common_port():
    return [21, 22, 23, 25, 80, 443, 1433, 1521, 3306, 3389, 6379, 8080]


def get_target_from_file(filename):
    target_list = []
    with open(filename, 'r') as f:
        for line in f.readline():
            l = line.split(' ', 1)
            if len(l) == 2:
                ip = l[0].replace(' ', '')
                port = l[1].replace(' ', '')
                if (check_ip(ip) and check_port(port)) or (check_domain(ip) and check_port(port)):
                    target_list.append([ip, port])
                else:
                    return "error"
            elif len(l) == 1:
                ip = l[0].replace(' ', '')
                if check_ip(ip):
                    target_list.append(ip)
                else:
                    return "error"
    return target_list
