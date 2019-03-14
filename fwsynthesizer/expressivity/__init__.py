import sys
from enum import IntEnum
from copy import deepcopy
import argparse
import fwsynthesizer


class IP(IntEnum):
    LOCAL = 0
    NON_LOCAL = 1

    def __str__(self):
        if self.value == IP.LOCAL:
            return " Self"
        else:
            return "~Self"


class T_IP(IntEnum):
    ID = 0
    CONST_LOCAL = 1
    CONST_NON_LOCAL = 2

    def __str__(self):
        if self.value == T_IP.ID:
            return "id"
        elif self.value == T_IP.CONST_LOCAL:
            return "NAT ( Self)"
        else:
            return "NAT (~Self)"


class T_port(IntEnum):
    ID = 0
    CONST = 1

    def __str__(self):
        if self.value == T_port.ID:
            return "id"
        else:
            return "NAT"


def local(pkt_Ip, t_Ip):
    return (pkt_Ip == IP.LOCAL and t_Ip == T_IP.ID) or t_Ip == T_IP.CONST_LOCAL


def non_local(pkt_Ip, t_Ip):
    return (pkt_Ip == IP.NON_LOCAL and t_Ip == T_IP.ID) or t_Ip == T_IP.CONST_NON_LOCAL


ipfw_array_path = [
    # p1 = qi; q0; qf
    # p2 = qi; q1; qf
    # p3 = qi; q0; q1; qf
    # p4 = qi; q1; q0; qf
    ("p1", lambda pkt_srcIp, pkt_dstIp, tr_srcIp, tr_srcPort, tr_dstIp, tr_dstPort:
        (pkt_srcIp == IP.NON_LOCAL and tr_srcIp == T_IP.ID and tr_srcPort == T_port.ID and local(pkt_dstIp, tr_dstIp))
        or (pkt_srcIp == IP.NON_LOCAL and pkt_dstIp == IP.LOCAL and tr_dstIp == T_IP.ID and tr_dstPort == T_port.ID)),
    ("p2", lambda pkt_srcIp, pkt_dstIp, tr_srcIp, tr_srcPort, tr_dstIp, tr_dstPort:
        (pkt_srcIp == IP.LOCAL and tr_srcIp == T_IP.ID and tr_srcPort == T_port.ID and non_local(pkt_dstIp, tr_dstIp))
        or (pkt_srcIp == IP.LOCAL and pkt_dstIp == IP.NON_LOCAL and tr_dstIp == T_IP.ID and tr_dstPort == T_port.ID)),
    ("p3", lambda pkt_srcIp, pkt_dstIp, tr_srcIp, tr_srcPort, tr_dstIp, tr_dstPort:
        (pkt_srcIp == IP.NON_LOCAL and pkt_dstIp == T_IP.CONST_NON_LOCAL and tr_dstIp == T_IP.ID and tr_dstPort == T_port.ID)
        or (pkt_srcIp == IP.NON_LOCAL and pkt_dstIp == IP.NON_LOCAL and non_local(pkt_dstIp, tr_dstIp))
        or (pkt_srcIp == IP.NON_LOCAL and non_local(pkt_dstIp, tr_dstIp) and tr_srcIp == T_IP.ID and tr_srcPort == T_port.ID)
        or (pkt_srcIp == IP.NON_LOCAL and non_local(pkt_dstIp, tr_dstIp))),
    ("p4", lambda pkt_srcIp, pkt_dstIp, tr_srcIp, tr_srcPort, tr_dstIp, tr_dstPort:
        (pkt_srcIp == IP.LOCAL and pkt_dstIp == IP.LOCAL and tr_dstIp == T_IP.ID and tr_dstPort == T_port.ID)
        or (pkt_srcIp == IP.LOCAL and pkt_dstIp == IP.LOCAL and local(pkt_dstIp, tr_dstIp))
        or (pkt_srcIp == IP.LOCAL and local(pkt_dstIp, tr_dstIp) and tr_srcIp == T_IP.ID and tr_srcPort == T_port.ID)
        or (pkt_srcIp == IP.LOCAL and local(pkt_dstIp, tr_dstIp)))
]

pf_array_path = [
    # p1 = qi; q0; q1; qf
    # p2 = qi; q2; q3; qf
    # p3 = qi; q0; q1; q2; q3; qf
    # p4 = qi; q2; q3; q0; q1; qf
    ("p1", lambda pkt_srcIp, pkt_dstIp, tr_srcIp, tr_srcPort, tr_dstIp, tr_dstPort:
        pkt_srcIp == IP.NON_LOCAL and tr_srcIp == T_IP.ID and tr_srcPort == T_port.ID and local(pkt_dstIp, tr_dstIp)),
    ("p2", lambda pkt_srcIp, pkt_dstIp, tr_srcIp, tr_srcPort, tr_dstIp, tr_dstPort:
        pkt_srcIp == IP.LOCAL and tr_dstIp == T_IP.ID and tr_dstPort == T_port.ID and pkt_dstIp == IP.NON_LOCAL),
    ("p3", lambda pkt_srcIp, pkt_dstIp, tr_srcIp, tr_srcPort, tr_dstIp, tr_dstPort:
        pkt_srcIp == IP.NON_LOCAL and non_local(pkt_dstIp, tr_dstIp)),
    ("p4", lambda pkt_srcIp, pkt_dstIp, tr_srcIp, tr_srcPort, tr_dstIp, tr_dstPort:
        pkt_srcIp == IP.LOCAL and pkt_dstIp == IP.LOCAL and local(pkt_dstIp, tr_dstIp))
]

iptables_array_path = [
    # p1 = qi; q0; q1; q2; q3; q10; q11; qf
    # p2 = qi; q7; q8; q9; q10; q11; qf
    # p3 = qi; q0; q1; q4; q5; q6; qf
    # p4 = qi; q7; q8; q9; q4; q5; q6; qf
    ("p1", lambda pkt_srcIp, pkt_dstIp, tr_srcIp, tr_srcPort, tr_dstIp, tr_dstPort:
        pkt_srcIp == IP.NON_LOCAL and local(pkt_dstIp, tr_dstIp)),
    ("p2", lambda pkt_srcIp, pkt_dstIp, tr_srcIp, tr_srcPort, tr_dstIp, tr_dstPort:
        pkt_srcIp == IP.LOCAL and non_local(pkt_dstIp, tr_dstIp)),
    ("p3", lambda pkt_srcIp, pkt_dstIp, tr_srcIp, tr_srcPort, tr_dstIp, tr_dstPort:
        pkt_srcIp == IP.NON_LOCAL and non_local(pkt_dstIp, tr_dstIp)),
    ("p4", lambda pkt_srcIp, pkt_dstIp, tr_srcIp, tr_srcPort, tr_dstIp, tr_dstPort:
        pkt_srcIp == IP.LOCAL and local(pkt_dstIp, tr_dstIp))
]


array_paths = {
    "ipfw": ipfw_array_path,
    "pf": pf_array_path,
    "iptables": iptables_array_path
}

# ----------------------------------------- IPrange to subnets implementation ---------------------------------------- #


def bits_to_32bits(b):
    return bin(b)[2:].zfill(32)


def ip_to_bits(ip):
    ip_parts = ip.split(".")
    ip_parts.reverse()
    ip_int = 0
    base = 1
    for part in ip_parts:
        ip_int += int(part) * base
        base *= 256
    return bits_to_32bits(ip_int)
# add zero at the end


def bits_to_ip(b):
    int_b = int(b, 2)
    ip = ''
    for i in range(3, -1, -1):
        part = int_b // (256 ** i)
        int_b = int_b - part * (256 ** i)
        ip = ip + str(part)
        if i > 0:
            ip = ip + '.'
    return ip


def range_to_masks_bin(a, b):
    # print(a, b)
    # print(int(a, 2), int(b, 2))
    if b < a:
        print('errore')
        return []
    if a == b:
        return [(bits_to_ip(a), 32)]
    au = a.rfind('1')
    if au == -1:
        ap = '1' * 32
    else:
        ap = a[:au] + '1' * (32 - au)
    # print(au, ap)
    # print(int(ap, 2))

    if ap == b:
        return [(bits_to_ip(a), au + 1)]
    elif int(ap, 2) < int(b, 2):
        ra = range_to_masks_bin(bits_to_32bits(int(ap, 2) + 1), b)
        ra.append((bits_to_ip(a), au + 1))
        return ra
    else:
        bz = b.rfind('0')
        bp = b[:bz] + '0' * (32 - bz)
        if bp == a:
            return [(bits_to_ip(bp), bz + 1)]
        else:
            rb = range_to_masks_bin(a, bits_to_32bits(int(bp, 2) - 1))
            rb.append((bits_to_ip(bp), bz + 1))
            return rb


def compute_table(array_path):
    table = []
    for pkt_srcIp in IP:
        table.append([])
        for pkt_dstIp in IP:
            table[pkt_srcIp].append([])
            for tr_srcIp in T_IP:
                table[pkt_srcIp][pkt_dstIp].append([])
                for tr_srcPort in T_port:
                    table[pkt_srcIp][pkt_dstIp][tr_srcIp].append([])
                    for tr_dstIp in T_IP:
                        table[pkt_srcIp][pkt_dstIp][tr_srcIp][tr_srcPort].append([])
                        for tr_dstPort in T_port:

                            verified_paths = []
                            feasible = False
                            for path in array_path:
                                if path[1](pkt_srcIp, pkt_dstIp, tr_srcIp, tr_srcPort, tr_dstIp, tr_dstPort):
                                    verified_paths.append(path[0])
                                    if feasible:
                                        feasible = True
                            table[pkt_srcIp][pkt_dstIp][tr_srcIp][tr_srcPort][tr_dstIp].append(verified_paths)
    return table


def verify_some(paths, pkt_srcIp, pkt_dstIp, tr_srcIp, tr_srcPort, tr_dstIp, tr_dstPort):
    for path in paths:
        if path[1](pkt_srcIp, pkt_dstIp, tr_srcIp, tr_srcPort, tr_dstIp, tr_dstPort):
            return True
    return False


def compare(firewallName1, firewallName2):

    array_paths1 = array_paths[firewallName1]
    array_paths2 = array_paths[firewallName2]

    table_only1 = compute_table([("Exists",
                                 lambda pkt_srcIp, pkt_dstIp, tr_srcIp, tr_srcPort, tr_dstIp, tr_dstPort:
                                  verify_some(
                                      array_paths1, pkt_srcIp, pkt_dstIp, tr_srcIp, tr_srcPort, tr_dstIp, tr_dstPort)
                                  and
                                  not verify_some(
                                      array_paths2, pkt_srcIp, pkt_dstIp, tr_srcIp, tr_srcPort, tr_dstIp, tr_dstPort)
                                  )])
    table_only2 = compute_table([("Exists",
                                 lambda pkt_srcIp, pkt_dstIp, tr_srcIp, tr_srcPort, tr_dstIp, tr_dstPort:
                                  verify_some(
                                      array_paths2, pkt_srcIp, pkt_dstIp, tr_srcIp, tr_srcPort, tr_dstIp, tr_dstPort)
                                  and
                                  not verify_some(
                                      array_paths1, pkt_srcIp, pkt_dstIp, tr_srcIp, tr_srcPort, tr_dstIp, tr_dstPort)
                                  )])

    table_both = compute_table([("Exists",
                                lambda pkt_srcIp, pkt_dstIp, tr_srcIp, tr_srcPort, tr_dstIp, tr_dstPort:
                                 verify_some(
                                      array_paths1, pkt_srcIp, pkt_dstIp, tr_srcIp, tr_srcPort, tr_dstIp, tr_dstPort)
                                 and
                                 verify_some(
                                      array_paths2, pkt_srcIp, pkt_dstIp, tr_srcIp, tr_srcPort, tr_dstIp, tr_dstPort)
                                 )])

    table_neither = compute_table([("Exists",
                                  lambda pkt_srcIp, pkt_dstIp, tr_srcIp, tr_srcPort, tr_dstIp, tr_dstPort:
                                   not verify_some(
                                        array_paths1, pkt_srcIp, pkt_dstIp, tr_srcIp, tr_srcPort, tr_dstIp, tr_dstPort)
                                   and
                                   not verify_some(
                                      array_paths2, pkt_srcIp, pkt_dstIp, tr_srcIp, tr_srcPort, tr_dstIp, tr_dstPort)
                                    )])

    print(",----------------------------------------------------------------------------,")
    print("|                            FW1 but not FW2                                 |")
    print("|____________________________________________________________________________|")
    print_compress_table(table_only1,
                         lambda pkt_srcIp, pkt_dstIp, tr_srcIp, tr_srcPort, tr_dstIp, tr_dstPort: True,
                         lambda paths: paths != [],
                         lambda paths: paths)

    print(",----------------------------------------------------------------------------,")
    print("|                            FW2 but not FW1                                 |")
    print("|____________________________________________________________________________|")
    print_compress_table(table_only2,
                         lambda pkt_srcIp, pkt_dstIp, tr_srcIp, tr_srcPort, tr_dstIp, tr_dstPort: True,
                         lambda paths: paths != [],
                         lambda paths: paths)

    print(",----------------------------------------------------------------------------,")
    print("|                           both FW1 and FW2                                 |")
    print("|____________________________________________________________________________|")
    print_compress_table(table_both,
                         lambda pkt_srcIp, pkt_dstIp, tr_srcIp, tr_srcPort, tr_dstIp, tr_dstPort: True,
                         lambda paths: paths != [],
                         lambda paths: paths)

    print(",----------------------------------------------------------------------------,")
    print("|                         neither FW1 or FW2                                 |")
    print("|____________________________________________________________________________|")
    print_compress_table(table_neither,
                         lambda pkt_srcIp, pkt_dstIp, tr_srcIp, tr_srcPort, tr_dstIp, tr_dstPort: True,
                         lambda paths: paths != [],
                         lambda paths: paths)


def is_inside(ip, subnet):
    subnetParts = subnet.split("/")
    if len(subnetParts) == 1:
        if ip == subnet:
            return True
        else:
            return False
    subnetIpBits = ip_to_bits(subnetParts[0])
    IpBits = ip_to_bits(ip)
    maskLen = int(subnetParts[1])
    if subnetIpBits[:maskLen] == IpBits[:maskLen]:
        return True
    return False


def scan_param_ad(address, firewall_addresses):
    if address is None:
        return lambda ad: True
    # We simply remove the eventual port since it is not important for the expressivity
    address = address.split(":")[0]
    if address == "local":
        return lambda ad: ad == IP.LOCAL
    if address == "nonlocal":
        return lambda ad: ad == IP.NON_LOCAL
    if firewall_addresses is None:
        raise Exception('missing argument', 'firewall_addesses is needed when using IP source or dest addresses')
    for subnet in firewall_addresses:
        if is_inside(address, subnet):
            return lambda ad: ad == IP.LOCAL
    return lambda ad: ad == IP.NON_LOCAL


def scan_param_tr_ad(address, firewall_addresses):
    if address is None:
        return lambda i, p: True
    addressParts = address.split(":")
    if len(addressParts) == 1:
        okPort = lambda p: True
    else:
        port = addressParts[1]
        if port == "id":
            okPort = lambda ad: ad == T_port.ID
        elif port == "non-id":
            okPort = lambda ad: ad == T_port.CONST
    ip = addressParts[0]
    if ip == "id":
        okIP = lambda ad: ad == T_IP.ID
    elif ip == "non-id":
        okIP = lambda ad: ad != T_IP.ID
    elif ip == "NAT-local":
        okIP = lambda ad: ad == T_IP.CONST_LOCAL
    elif ip == "NAT-nonlocal":
        okIP = lambda ad: ad == T_IP.CONST_NON_LOCAL
    elif firewall_addresses is None:
        raise Exception('missing argument', 'firewall_addesses is needed when using IP source or dest addresses')
    else:
        ip = ip.split("-")[1]
        for subnet in firewall_addresses:
            if is_inside(ip, subnet):
                okIP = lambda ad: ad == T_IP.CONST_LOCAL
                break
        okIP = lambda ad: ad == T_IP.CONST_NON_LOCAL

    return lambda ip, port: okIP(ip) and okPort(port)


def print_expr_table(array_path, source, dest, trsource, trdest, firewall_addresses):
    oksource = scan_param_ad(source, firewall_addresses)
    okdest = scan_param_ad(dest, firewall_addresses)
    oktrsource = scan_param_tr_ad(trsource, firewall_addresses)
    oktrdest = scan_param_tr_ad(trdest, firewall_addresses)

    okall = lambda pkt_srcIp, pkt_dstIp, tr_srcIp, tr_srcPort, tr_dstIp, tr_dstPort: \
        oksource(pkt_srcIp) and okdest(pkt_dstIp) and \
        oktrsource(tr_srcIp, tr_srcPort) and oktrdest(tr_dstIp, tr_dstPort)

    table = compute_table(array_path)
    print_explicit_table(table, okall)

    print(",----------------------------------------------------------------------------,")
    print("|                            COMPRESSED TABLE                                |")
    print("|____________________________________________________________________________|")
    print_compress_table(table, okall)

    print(",----------------------------------------------------------------------------,")
    print("|                             EXPRESSIBLE                                    |")
    print("|____________________________________________________________________________|")
    print_compress_table(table,
                         okall,
                         lambda paths: paths != [],
                         lambda paths: "Exist")

    print(",----------------------------------------------------------------------------,")
    print("|                            UNEXPRESSIBLE                                   |")
    print("|____________________________________________________________________________|")
    print_compress_table(table,
                         okall,
                         lambda paths: paths == [],
                         lambda paths: paths)


def check(array_path, source, dest, trsource, trdest, firewall_addresses):
    oksource = scan_param_ad(source, firewall_addresses)
    okdest = scan_param_ad(dest, firewall_addresses)
    oktrsource = scan_param_tr_ad(trsource, firewall_addresses)
    oktrdest = scan_param_tr_ad(trdest, firewall_addresses)

    okall = lambda pkt_srcIp, pkt_dstIp, tr_srcIp, tr_srcPort, tr_dstIp, tr_dstPort: \
        oksource(pkt_srcIp) and okdest(pkt_dstIp) and \
        oktrsource(tr_srcIp, tr_srcPort) and oktrdest(tr_dstIp, tr_dstPort)

    table = compute_table(array_path)
    for pkt_srcIp in IP:
        for pkt_dstIp in IP:
            for tr_srcIp in T_IP:
                for tr_srcPort in T_port:
                    for tr_dstIp in T_IP:
                        for tr_dstPort in T_port:
                            paths = table[pkt_srcIp][pkt_dstIp][tr_srcIp][tr_srcPort][tr_dstIp][tr_dstPort]
                            if paths != [] and okall(pkt_srcIp, pkt_dstIp, tr_srcIp, tr_srcPort, tr_dstIp, tr_dstPort):
                                print("EXPRESSIBLE")
                                return
                            if paths == [] and okall(pkt_srcIp, pkt_dstIp, tr_srcIp, tr_srcPort, tr_dstIp, tr_dstPort):
                                print("NOT EXPRESSIBLE")
                                return
    print("NOT EXPRESSIBLE")


def print_explicit_table(table,
                         filter_cond=lambda pkt_srcIp, pkt_dstIp, tr_srcIp, tr_srcPort, tr_dstIp, tr_dstPort: True,
                         filter_paths=lambda paths: True):
    print(",----------------------------------------------------------------------------,")
    print("|                             EXPLICIT TABLE                                 |")
    print("|____________________________________________________________________________|")
    print("|| srcIp , dstIp | tr_srcIp   : tr_srcPort , tr_dstIp   : tr_dstPort || paths ")
    print("------------------------------------------------------------------------------")
    for pkt_srcIp in IP:
        for pkt_dstIp in IP:
            for tr_srcIp in T_IP:
                for tr_srcPort in T_port:
                    for tr_dstIp in T_IP:
                        for tr_dstPort in T_port:
                            paths = table[pkt_srcIp][pkt_dstIp][tr_srcIp][tr_srcPort][tr_dstIp][tr_dstPort]
                            if filter_cond(pkt_srcIp, pkt_dstIp, tr_srcIp, tr_srcPort, tr_dstIp, tr_dstPort) and \
                               filter_paths(paths):
                                print("|| " + str(pkt_srcIp).ljust(5) + " , " + str(pkt_dstIp).ljust(5) + " | " +
                                      str(tr_srcIp).ljust(10) + " : " + str(tr_srcPort).ljust(10) + " , " +
                                      str(tr_dstIp).ljust(10) + " : " + str(tr_dstPort).ljust(10) + " || " +
                                      str(table[pkt_srcIp][pkt_dstIp][tr_srcIp][tr_srcPort][tr_dstIp][tr_dstPort]))

    print("------------------------------------------------------------------------------")


def print_compress_table(table,
                         filter_cond=lambda pkt_srcIp, pkt_dstIp, tr_srcIp, tr_srcPort, tr_dstIp, tr_dstPort: True,
                         filter_paths=lambda paths: True,
                         represent_paths=lambda paths: paths):

    symbols = [IP, IP, T_IP, T_port, T_IP, T_port]
    lines_spec = []
    paths = []
    for num_char in range(7):
        for positions in subsets_of_given_dim(num_char, 6):
            specification = ["_", "_", "_", "_", "_", "_"]
            for chars_combination in combinations([symbols[position] for position in positions], num_char):
                for index in range(num_char):
                    specification[positions[index]] = chars_combination[index]
                if not_discarded(specification, lines_spec):
                    path = compute_path(specification, table, filter_cond, filter_paths, represent_paths)
                    if path is not None:
                        paths.append(path)
                        lines_spec.append(deepcopy(specification))

    print("|| srcIp , dstIp | tr_srcIp   : tr_srcPort , tr_dstIp   : tr_dstPort || paths ")
    print("------------------------------------------------------------------------------")
    strings_for_lines = []
    for i in range(len(lines_spec)):
        specification = lines_spec[i]
        path = paths[i]
        strings_for_lines.append("|| " + str(specification[0]).ljust(5) + " , " + str(specification[1]).ljust(5) +
                                 " | " + str(specification[2]).ljust(10) + " : " + str(specification[3]).ljust(10) +
                                 " , " + str(specification[4]).ljust(10) + " : " + str(specification[5]).ljust(10) +
                                 " || " + str(path))
    strings_for_lines.sort()
    for string_line in strings_for_lines:
        print(string_line)
    print("------------------------------------------------------------------------------")


def subsets_of_given_dim(dim_sub, dim_set):
    index = [i for i in range(dim_sub)]
    sets = []
    if dim_sub < 1:
        return [[]]
    while index[0] <= dim_set - dim_sub:
        sets.append(deepcopy(index))
        for i in range(dim_sub - 1, -1, -1):
            if index[i] + 1 <= dim_set - dim_sub + i:
                index[i] = index[i] + 1
                for j in range(i, dim_sub):
                    index[j] = index[i] + (j - i)
                break
            elif i == 0:
                return sets
    return sets


def combinations(symbols, num_char):
    combination_list = []
    if num_char == 0:
        return [[]]
    for symbol in symbols[0]:
        for subCombination in combinations(symbols[1:], num_char - 1):
            combination_list.append([symbol] + subCombination)
    return combination_list


def compute_path(specification, table, filter_cond, filter_paths, represent_paths):
    label = False
    first_path = None
    for pkt_srcIp in (IP if specification[0] == "_" else [specification[0]]):
        for pkt_dstIp in (IP if specification[1] == "_" else [specification[1]]):
            for tr_srcIp in (T_IP if specification[2] == "_" else [specification[2]]):
                for tr_srcPort in (T_port if specification[3] == "_" else [specification[3]]):
                    for tr_dstIp in (T_IP if specification[4] == "_" else [specification[4]]):
                        for tr_dstPort in (T_port if specification[5] == "_" else [specification[5]]):
                            if filter_cond(pkt_srcIp, pkt_dstIp, tr_srcIp, tr_srcPort, tr_dstIp, tr_dstPort):
                                path = table[pkt_srcIp][pkt_dstIp][tr_srcIp][tr_srcPort][tr_dstIp][tr_dstPort]
                                if not filter_paths(path):
                                    return None
                                elif not label:
                                    first_path = represent_paths(path)
                                    label = True
                                elif first_path != represent_paths(path):
                                    return None
    return first_path


def not_discarded(specification, discarded):
    for discarded_spec in discarded:
        if represent(discarded_spec, specification):
            return False
    return True


def represent(spec1, spec2):
    for i in range(len(spec1)):
        if spec1[i] != "_" and spec1[i] != spec2[i]:
            return False
    return True


def intersect_diff(list_of_segments, list_of_address):
    inter = []
    # print("list of segment", list_of_segments)
    diff = [ [(4294967296 + s[0]) % 4294967296, (4294967296 + s[1]) % 4294967296] for s in list_of_segments ]

    # print(list_of_segments, list_of_address)
    for address in list_of_address:
        new_diff = []
        for segment in diff:
            if address == segment[0] and segment[1] == segment[0]:
                inter.append([address,address])
            elif address == segment[0] and segment[1] != segment[0]:
                inter.append([address,address])
                new_diff.append([segment[0]+1, segment[1]])
            elif address == segment[1] and segment[1] != segment[0]:
                inter.append([address,address])
                new_diff.append([segment[0], segment[1]-1])
            elif address > segment[0] and address < segment[1]:
                inter.append([address,address])
                new_diff.append([segment[0], address-1])
                new_diff.append([address+1, segment[1]])
            elif address < segment[0] or address > segment[1]:
                new_diff.append(segment)
        diff = new_diff

    return (inter, diff)


def dot_to_integer_ip(dot):
    values = dot.split(".")
    values.reverse()
    integer = 0
    base = 1
    for value in values:
        integer = integer + (base * int(value))
        base = base * 256
    return integer


def integer_to_dot_ip(integer):
    string = ""
    value = integer
    positions = range(4)
    positions.reverse()
    for pos in positions:
        base = 256 ** pos
        pos_val = value / base
        string = string + str(pos_val)
        value = value - (base * pos_val)
        if pos != 0:
            string = string + "."
    return string


def print_ip_rages(ranges):
    s =  ""
    for range in ranges:
        s = s + str(range[0]) + " - " + str(range[1]) + ", "
    return s


def print_port_rages(ranges):
    s =  ""
    for range in ranges:
        s = s + str(range[0]) + " - " + str(range[1]) + ", "
    return s


def check(semantics, target_system, interfaces):

    self_addresses = [dot_to_integer_ip(v[1]) for v in interfaces.values()]
    rules = semantics.get_rules()
    for rule in rules:
        if rule[0][5] == [[1, 1]]:
            # we do not consider enstablished connections
            continue

        # split based on selfness of addresses
        IP_types = [IP.LOCAL, IP.NON_LOCAL]
        src_IPs = intersect_diff(rule[0][0], self_addresses)
        dst_IPs = intersect_diff(rule[0][2], self_addresses)

        # check each resulting rule
        # srcIP
        if rule[1][0] == []:
            tr_srcIP = T_IP.ID
        else:
            (tr_srcIP_self, tr_srcIP_Noself) = intersect_diff(rule[1][0], self_addresses)
            if tr_srcIP_self == []:
                tr_srcIP = T_IP.CONST_NON_LOCAL
            elif tr_srcIP_Noself == []:
                tr_srcIP = T_IP.CONST_LOCAL
            else:
                print('ERROR! This tool does not support NAT to range of addresses')
                continue
        # srcPort
        if rule[1][1] == []:
            tr_srcPort = T_port.ID
        else:
            tr_srcPort = T_port.CONST
        # dstIP
        if rule[1][2] == []:
            tr_dstIP = T_IP.ID
        else:
            (tr_dstIP_self, tr_dstIP_Noself) = intersect_diff(rule[1][2], self_addresses)
            if tr_dstIP_self == []:
                tr_dstIP = T_IP.CONST_NON_LOCAL
            elif tr_dstIP_Noself == []:
                tr_dstIP = T_IP.CONST_LOCAL
            else:
                print("EEE")
        # dstPort
        if rule[1][3] == []:
            tr_dstPort = T_port.ID
        else:
            tr_dstPort = T_port.CONST

        # compute tables representing the expressivity of target system
        target_table = compute_table(array_paths[target_system])

        for i in range(2):
            for j in range(2):
                if src_IPs[i] != [] and dst_IPs[j] != [] and \
                        target_table[IP_types[i]][IP_types[j]][tr_srcIP][tr_srcPort][tr_dstIP][tr_dstPort] == []:
                            # if something is not expressible then print it and complain
                            print("\nPROBLEM FOUND!\n"
                                  "In " + target_system + " the following rule schema is not expressible!")
                            print("==============================================================================")
                            print("|  srcIp  |  dstIp  ||   tr_srcIp   : tr_srcPort |   tr_dstIp   : tr_dstPort |")
                            print("==============================================================================")
                            print("| " + str(IP_types[i]).ljust(7) + " | " + str(IP_types[j]).ljust(7) +
                                  " || " + str(tr_srcIP).ljust(12) + " : " + str(tr_srcPort).ljust(10) +
                                  " | " + str(tr_dstIP).ljust(12) + " : " + str(tr_dstPort).ljust(10) + " |")
                            # print("srcIP: " + str(IP_types[i]) + ", dstIP: " + str(IP_types[j]) + " --> tr_srcIP: " +
                            #       str(tr_srcIP) + ", tr_srcPort: " + str(tr_srcPort) + ", tr_dstIP: " + str(tr_dstIP) +
                            #       ", tr_dstPort: " + str(tr_dstPort))
                            print("==============================================================================")
                            print("Hence the following is impossible to achieve:")
                            print_rule(src_IPs[i], dst_IPs[j], rule)

                            # print("-----------------------------------------------------------------------------------------")
                            # print("|| srcIp | srcPort |  dstIp | dstPort || tr_srcIp : tr_srcPort | tr_dstIp : tr_dstPort ||")
                            # print("-----------------------------------------------------------------------------------------")
                            #
                            # print(print_ip_rages(src_IPs[i]) + " | " + print_port_rages(rule[0][1]) + " | " +
                            #       print_ip_rages(dst_IPs[j]) + " | " + print_port_rages(rule[0][3]) + " || " +
                            #       print_ip_rages(rule[1][0]) + print_ip_rages(rule[1][0]))


def print_rule(src_segments, dst_segments, rule):
    row = [["sIp"], ["sPort"], ["dIp"], ["dPort"], ["prot"],
           ["tr_src"], ["tr_dst"]]

    if rule[0][4] == [[18, 255], [0, 16]]:
        row[4].append("* \ {udp}")
    elif rule[0][4] == [[7, 255], [0, 5]]:
        row[4].append("* \ {tcp}")
    elif rule[0][4] == [[18, 255], [7, 16], [0, 5]]:
        row[4].append("* \ {tcp, udp}")
    else:
        row[4] += [print_prot_range(r) for r in rule[0][4]]

    # plus one because of the header line
    line_num = max([len(list_of_segments) + 1 for list_of_segments in
                   [rule[0][1]] + [row[4]] + [src_segments, dst_segments]])
    # print(row_num)
    # print(rule[0])
    # print(src_segments)
    # print(dst_segments)

    for line in range(line_num):
        if len(src_segments) > line:
            row[0].append(print_ip_range(src_segments[line]))
        else:
            row[0].append("")

        if len(rule[0][1]) > line:
            row[1].append(print_port_range(rule[0][1][line]))
        else:
            row[1].append("")

        if len(dst_segments) > line:
            row[2].append(print_ip_range(dst_segments[line]))
        else:
            row[2].append("")

        if len(rule[0][3]) > line:
            row[3].append(print_port_range(rule[0][3][line]))
        else:
            row[3].append("")

        if len(row[4]) <= line:
            row[4].append("")

        if line == 0:
            tr_src_string = ""
            if rule[1][0] != []:
                tr_src_string += print_ip_range(rule[1][0][0])
            else:
                tr_src_string += "-"
            tr_src_string += " : "
            if rule[1][1] != []:
                tr_src_string += print_port_range(rule[1][1][0])
            else:
                tr_src_string += "-"
            row[5].append(tr_src_string)

            tr_dst_string = ""
            if rule[1][2] != []:
                tr_dst_string += print_ip_range(rule[1][2][0])
            else:
                tr_dst_string += "-"
            tr_dst_string += " : "
            if rule[1][3] != []:
                tr_dst_string += print_port_range(rule[1][3][0])
            else:
                tr_dst_string += "-"
            row[6].append(tr_dst_string)
        else:
            for i in range(5, 7):
                row[i].append("")

    width = [0]*7
    for i in range(7):
        width[i] = max([len(field) + 2 for field in row[i]])

    print("=" * (sum(width) + 11))
    for line in range(line_num):
        sys.stdout.write("||")
        for field in range(7):
            sys.stdout.write(row[field][line].center(width[field]))
            sys.stdout.write("|")
            if field == 4 or field == 6:
                sys.stdout.write("|")
        print("")
        if line == 0 or line == line_num - 1:
            print("=" * (sum(width) + 11))


def print_ip(ip):
    if ip < 0:
        ip = (4294967296 + ip) % 4294967296
    return integer_to_dot_ip(ip)


def print_port(port):
    return str(port)


def print_prot(prot):
    return str(prot)


def print_ip_range(range):
    if range[0] == range[1]:
        return print_ip(range[0])
    elif range[0] == 0 and range[1] == 4294967295:
        return "*"
    else:
        return print_ip(range[0]) + " - " + print_ip(range[1])


def print_port_range(range):
    if range[0] == range[1]:
        return print_port(range[0])
    elif range[0] == 0 and range[1] == 65535:
        return "*"
    else:
        return print_port(range[0]) + " - " + print_port(range[1])


def print_prot_range(range):
    if range[0] == range[1]:
        if range[0] == 17:
            return "udp"
        else:
            return print_prot(range[0])
    elif range[0] == 0 and range[1] == 255:
        return "*"
    else:
        return print_prot(range[0]) + " - " + print_prot(range[1])
