import sys
from enum import IntEnum
from copy import deepcopy
import argparse
import fwsynthesizer
import functools
foldl = lambda func, acc, xs: functools.reduce(func, xs, acc)


self_addresses = []


class IP(IntEnum):
    LOCAL = 0
    NON_LOCAL = 1

    def __str__(self):
        if self.value == IP.LOCAL:
            return "     Self   "
        else:
            return "    ~Self   "


class T_IP(IntEnum):
    ID = 0
    CONST_LOCAL = 1
    CONST_NON_LOCAL = 2

    def __str__(self):
        if self.value == T_IP.ID:
            return "    id     "
        elif self.value == T_IP.CONST_LOCAL:
            return "NAT ( Self)"
        else:
            return "NAT (~Self)"


class T_port(IntEnum):
    ID = 0
    CONST = 1

    def __str__(self):
        if self.value == T_port.ID:
            return "    id     "
        else:
            return "   NAT     "


class Arrow:
    def __init__(self, psi, node):
        self.psi = psi
        self.node = node


def reverse(trace):
    revtrace = trace[:]
    revtrace.reverse()

    for i in range(len(revtrace)-1):
        revtrace[i] = (revtrace[i][0], revtrace[i][1], revtrace[i+1][2])
    revtrace[len(revtrace)-1] = (revtrace[len(revtrace)-1][0], revtrace[len(revtrace)-1][1], lambda x, y: True)

    return revtrace


def epsilon(trace, transformation):
    if transformation == "DROP":
        # print('a')
        if trace[-1][1] == "DROP":
            return True
        else:
            return False
    # print('b')

    mustBe = set()
    if transformation["srcIP"] != "id" or transformation["srcPort"] != "id":
        mustBe.add("SNAT")
    if transformation["dstIP"] != "id" or transformation["dstPort"] != "id":
        mustBe.add("DNAT")
    
    are = set()
    for pair in trace:
        are.add(pair[1])
        # print(are, mustBe)

    are.remove("ID")
    if mustBe == are:
        return True
    return False


def apply_t(transformation, packet):
    packet1 = packet.copy()
    for key in transformation:
        if transformation[key] != "id":
            packet1[key] = transformation[key]
    return packet1


class Control_diagram:
    def __init__(self, node_name, labels = set()):
        self.node_name = node_name
        self.content = [] # FixMe
        self.arrows = set()
        self.labels = labels.union({"ID"})


    def insert(self, packets, transformation, trace):
        P_a = packets
        t_r = transformation
        t_l = {"srcIP": "id", "srcPort": "id", "dstIP": "id", "dstPort": "id"}

        for step in trace:
            # print(step[0].node_name)
            (t_a, t_r) = split(t_r, step[1])
            for annotated_pair in step[0].content:
                if annotated_pair["t_a"] != t_a:
                    P_ax = MC_intersec(P_a, annotated_pair["P_a"])
                    # print(P_a)
                    # print(annotated_pair["P_a"])
                    # print(P_ax)
                    # print("ddd")
                    if P_ax != "empty":
                        # print("P1")
                        # print(packets)
                        # print("P2")
                        # print(annotated_pair["P"])
                        P_x = inverse_t(t_l, P_ax, packets)
                        tldP_x = inverse_t(annotated_pair["t_l"], P_ax, annotated_pair["P"])
                        # print("P1x")
                        # print(P_x)
                        # print("P2x")
                        # print(tldP_x)
                        print_conflicting_pairs(P_x, tldP_x, transformation, annotated_pair["t"],
                                                step[0].node_name, P_ax, t_a, annotated_pair["t_a"], trace[1][0].node_name)
            step[0].content.append({"P_a" : P_a[:], "t_l": t_l,  "t_a": t_a, "t": transformation, "P": packets[:]})
            # if step[0].node_name == "q2":
            #     print(foldl(lambda x, y: x + "\n" + str(y), "", step[0].content))
            # print(t_a)
            # print(t_l)
            if t_a != "DROP":
                t_l = compose(t_a, t_l)
                P_a = MC_apply_t(t_a, P_a)
        # print(len(self.content))


    def check(self, packet, transformation):
        for trace in self.traces():
            if self.check_trace(packet, transformation, trace):
                # print(packet)
                # print(transformation)
                # print(print_trace(trace))
                return [trace]
        return []

    def chi(self, trace, packet, seen):
        if len(trace) <= 1:
            return True
        seenNow = seen.union({trace[0][1]})
        return self.chi(trace[1:], packet, seenNow) and trace[0][2](packet, seenNow)

    def check_trace(self, packet, transformation, trace):
        if transformation == "DROP" and trace[-1][1] == "DROP" and self.chi(trace, packet, set()):
            return True
        if transformation != "DROP" and epsilon(trace, transformation) and self.chi(trace, packet, set()) and self.chi(reverse(trace), apply_t(transformation, packet), set()):
            return True
        return False

    def traces(self, seen = set()):
        alltraces = self.traces1(seen)
        return filter(
            lambda trace: 
                trace[-1][1] != "DROP" or
                all(lbl == "ID" or lbl == "DROP" for (n, lbl, phi) in trace),
            alltraces
        )

    def traces1(self, seen = set()):
        traces = []
        nodechoices = []
        for label in self.labels:
            nodechoices.append([(self, label, lambda x, y: True)])
        if self.arrows == set():
            traces = nodechoices
        else:
            for nodechoice in nodechoices:
                if nodechoice[0][1] == "DROP":
                    traces.append(nodechoice)
                else:
                    for arrow in self.arrows:
                        if not arrow.node.node_name in seen.union({self.node_name}):
                            nodechoice[0] = (nodechoice[0][0], nodechoice[0][1], arrow.psi)
                            for subtrace in arrow.node.traces(seen.union({self.node_name})):
                                traces.append(nodechoice + subtrace)
        return traces


class IPFW_firewall(Control_diagram):
    def __init__(self):
        self.ipfw_qf = Control_diagram('qf')
        self.ipfw_q0 = Control_diagram('q0', {"DNAT", "DROP"})
        self.ipfw_q1 = Control_diagram('q1', {"SNAT", "DROP"})
        self.ipfw_q0.arrows = [
            Arrow(lambda p, seen=set() : "DNAT" in seen or p["dstIP"] in self_addresses, self.ipfw_qf),
            Arrow(lambda p, seen=set() : "DNAT" in seen or not p["dstIP"] in self_addresses, self.ipfw_q1)
        ]
        self.ipfw_q1.arrows = [
            Arrow(lambda p, seen=set() : "DNAT" in seen or p["dstIP"] in self_addresses, self.ipfw_q0),
            Arrow(lambda p, seen=set() : "DNAT" in seen or not p["dstIP"] in self_addresses, self.ipfw_qf)
        ]

        Control_diagram.__init__(self, 'qi')
        self.arrows = [
            Arrow(lambda p, seen=set() : "SNAT" in seen or p["srcIP"] in self_addresses, self.ipfw_q1),
            Arrow(lambda p, seen=set() : "SNAT" in seen or not p["srcIP"] in self_addresses, self.ipfw_q0)
        ]


class PF_firewall(Control_diagram):
    def __init__(self):
        self.pf_qf = Control_diagram('qf')
        self.pf_q0 = Control_diagram('q0', {"SNAT"})
        self.pf_q1 = Control_diagram('q1', {"DROP"})
        self.pf_q2 = Control_diagram('q2', {"DNAT"})
        self.pf_q3 = Control_diagram('q3', {"DROP"})
        self.pf_q0.arrows = [
            Arrow(lambda p, seen=set(): True, self.pf_q1),
        ]
        self.pf_q2.arrows = [
            Arrow(lambda p, seen=set() : True, self.pf_q3),
        ]
        self.pf_q1.arrows = [
            Arrow(lambda p, seen=set() : "DNAT" in seen or p["dstIP"] in self_addresses, self.pf_q2),
            Arrow(lambda p, seen=set() : "DNAT" in seen or not p["dstIP"] in self_addresses, self.pf_qf)
        ]
        self.pf_q3.arrows = [
            Arrow(lambda p, seen=set() : "DNAT" in seen or p["dstIP"] in self_addresses, self.pf_qf),
            Arrow(lambda p, seen=set() : "DNAT" in seen or not p["dstIP"] in self_addresses, self.pf_q0)
        ]
        Control_diagram.__init__(self, 'qi')
        self.arrows = [
            Arrow(lambda p, seen=set() : "SNAT" in seen or p["srcIP"] in self_addresses, self.pf_q0),
            Arrow(lambda p, seen=set() : "SNAT" in seen or not p["srcIP"] in self_addresses, self.pf_q2)
        ]


class IPTABLES_firewall(Control_diagram):
    def __init__(self):
        self.ipt_qf = Control_diagram('qf')
        self.ipt_q0 = Control_diagram('q0')
        self.ipt_q1 = Control_diagram('q1', {"DNAT"})
        self.ipt_q2 = Control_diagram('q2')
        self.ipt_q3 = Control_diagram('q3', {"DROP"})
        self.ipt_q4 = Control_diagram('q4')
        self.ipt_q5 = Control_diagram('q5', {"SNAT"})
        self.ipt_q6 = Control_diagram('q6', {"DROP"})
        self.ipt_q7 = Control_diagram('q7')
        self.ipt_q8 = Control_diagram('q8', {"DNAT"})
        self.ipt_q9 = Control_diagram('q9', {"DROP"})
        self.ipt_q10 = Control_diagram('q10')
        self.ipt_q11 = Control_diagram('q11', {"SNAT"})
        self.ipt_q0.arrows = [
            Arrow(lambda p, seen=set() : True, self.ipt_q1),
        ]
        self.ipt_q2.arrows = [
            Arrow(lambda p, seen=set() : True, self.ipt_q3),
        ]
        self.ipt_q3.arrows = [
            Arrow(lambda p, seen=set() : True, self.ipt_q10),
        ]
        self.ipt_q4.arrows = [
            Arrow(lambda p, seen=set() : True, self.ipt_q5),
        ]
        self.ipt_q5.arrows = [
            Arrow(lambda p, seen=set() : True, self.ipt_q6),
        ]
        self.ipt_q6.arrows = [
            Arrow(lambda p, seen=set() : True, self.ipt_qf),
        ]
        self.ipt_q7.arrows = [
            Arrow(lambda p, seen=set() : True, self.ipt_q8),
        ]
        self.ipt_q8.arrows = [
            Arrow(lambda p, seen=set() : True, self.ipt_q9),
        ]
        self.ipt_q10.arrows = [
            Arrow(lambda p, seen=set() : True, self.ipt_q11),
        ]
        self.ipt_q11.arrows = [
            Arrow(lambda p, seen=set() : True, self.ipt_qf),
        ]
        self.ipt_q1.arrows = [
            Arrow(lambda p, seen=set() : "DNAT" in seen or p["dstIP"] in self_addresses, self.ipt_q4),
            Arrow(lambda p, seen=set() : "DNAT" in seen or not p["dstIP"] in self_addresses, self.ipt_q2)
        ]
        self.ipt_q9.arrows = [
            Arrow(lambda p, seen=set() : "DNAT" in seen or p["dstIP"] in self_addresses, self.ipt_q4),
            Arrow(lambda p, seen=set() : "DNAT" in seen or not p["dstIP"] in self_addresses, self.ipt_q10)
        ]
        Control_diagram.__init__(self, 'qi')
        self.arrows = [
            Arrow(lambda p, seen=set() : "SNAT" in seen or p["srcIP"] in self_addresses, self.ipt_q7),
            Arrow(lambda p, seen=set() : "SNAT" in seen or not p["srcIP"] in self_addresses, self.ipt_q1)
        ]


def compute_fields(pkt_srcIP, pkt_dstIP, tr_srcIP, tr_dstIP):
    if tr_srcIP == T_IP.ID and tr_dstIP == T_IP.ID:
        tr_type = "  ID  "
    elif tr_srcIP == T_IP.ID:
        tr_type = " DNAT "
    elif tr_dstIP == T_IP.ID:
        tr_type = " SNAT "
    else:
        tr_type = " -NAT "

    if tr_srcIP == T_IP.ID:
        pkt1_srcIP = pkt_srcIP
    elif tr_srcIP == T_IP.CONST_LOCAL:
        pkt1_srcIP = IP.LOCAL
    else:
        pkt1_srcIP = IP.NON_LOCAL

    if tr_dstIP == T_IP.ID:
        pkt1_dstIP = pkt_dstIP
    elif tr_dstIP == T_IP.CONST_LOCAL:
        pkt1_dstIP = IP.LOCAL
    else:
        pkt1_dstIP = IP.NON_LOCAL   

    return "|" + str(pkt_dstIP) + "|" + str(pkt_srcIP) + "|" +  tr_type + "|" + str(pkt1_dstIP) + "|" + str(pkt1_srcIP) + " :: "


def print_expr_table(firewall):
    table = compute_table(firewall)
    s = ""
    transformations_type = [
        (T_IP.ID, T_IP.ID), (T_IP.ID, T_IP.CONST_LOCAL), (T_IP.ID, T_IP.CONST_NON_LOCAL), 
        (T_IP.CONST_LOCAL, T_IP.ID), (T_IP.CONST_NON_LOCAL, T_IP.ID), (T_IP.CONST_LOCAL, T_IP.CONST_LOCAL), 
        (T_IP.CONST_LOCAL, T_IP.CONST_NON_LOCAL), (T_IP.CONST_NON_LOCAL, T_IP.CONST_LOCAL), (T_IP.CONST_NON_LOCAL, T_IP.CONST_NON_LOCAL)]
    for (tr_srcIP, tr_dstIP) in transformations_type:
            for pkt_dstIP in IP:
                for pkt_srcIP in IP:
                    fields = compute_fields(pkt_srcIP, pkt_dstIP, tr_srcIP, tr_dstIP)
                    s += fields + print_traces(table[pkt_srcIP][pkt_dstIP][tr_srcIP][tr_dstIP]) + "\n" 
    print(s[:-1])


def compute_table(firewall):
    table = []
    for pkt_srcIP in IP:
        table.append([])
        for pkt_dstIP in IP:
            table[pkt_srcIP].append([])
            for tr_srcIP in T_IP:
                table[pkt_srcIP][pkt_dstIP].append([])
                for tr_dstIP in T_IP:
                    table[pkt_srcIP][pkt_dstIP][tr_srcIP].append([])
                    packet = create_packet(pkt_srcIP, pkt_dstIP)
                    transformation = create_transformation(tr_srcIP, tr_dstIP)
                    # if firewall.check(packet, transformation) == []:
                    #     print(pkt_srcIP,pkt_dstIP,tr_srcIP,tr_dstIP)
                    #     print(packet, transformation)
                    table[pkt_srcIP][pkt_dstIP][tr_srcIP][tr_dstIP] = firewall.check(packet, transformation)
    return table


def create_packet(pkt_srcIP, pkt_dstIP):
    if pkt_srcIP == IP.LOCAL:
        srcIP = "127.0.0.1"
    else:
        srcIP = "1.1.1.1"
    if pkt_dstIP == IP.LOCAL:
        dstIP = "127.0.0.1"
    else:
        dstIP = "1.1.1.1"
    return {"srcIP": srcIP, "srcPort": "54", "dstIP": dstIP, "dstPort": "58"}


def create_transformation(tr_srcIP, tr_dstIP):
    if tr_srcIP == T_IP.ID:
        srcIP = "id"
    elif tr_srcIP == T_IP.CONST_LOCAL:
        srcIP = "127.0.0.1"
    else:
        srcIP = "1.1.1.1"

    if tr_dstIP == T_IP.ID:
        dstIP = "id"
    elif tr_dstIP == T_IP.CONST_LOCAL:
        dstIP = "127.0.0.1"
    else:
        dstIP = "1.1.1.1"

    return {"srcIP": srcIP, "srcPort": "id", "dstIP": dstIP, "dstPort": "id"}


def print_trace(trace):
    if trace != []:
        return "(" + trace[0][0].node_name + ", " + trace[0][1] + ")" + ", " + print_trace(trace[1:])
    return ""


def print_traces(traces):
    s = "{ "
    for trace in traces:
        s += print_trace(trace)
    s = s + "}" if len(s) < 4 else s[:-2] + " }"
    return s


def print_expr_tables():
    iptables_ex = IPTABLES_firewall()
    pf_ex = PF_firewall()
    ipfw_ex = IPFW_firewall()

    print("==============================================================================")
    print("|                                     PF                                     |")
    print("==============================================================================")
    print("|    p_dst   |    p_src   |  t   |  t(p)_dst  |  t(p)_src   |")
    print("-------------------------------------------------------------")
    print_expr_table(pf_ex)
    print("==============================================================================\n")

    print("==============================================================================")
    print("|                                    IPFW                                    |")
    print("==============================================================================")
    print("|    p_dst   |    p_src   |  t   |  t(p)_dst  |  t(p)_src   |")
    print("-------------------------------------------------------------")
    print_expr_table(ipfw_ex)
    print("==============================================================================\n")

    print("==============================================================================")
    print("|                                  IPTABLES                                  |")
    print("==============================================================================")
    print("|    p_dst   |    p_src   |  t   |  t(p)_dst  |  t(p)_src   |")
    print("-------------------------------------------------------------")
    print_expr_table(iptables_ex)
    print("==============================================================================\n")


def dot_to_integer_ip(dot):
    values = dot.split(".")
    values.reverse()
    integer = 0
    base = 1
    for value in values:
        integer = integer + (base * int(value))
        base = base * 256
    return integer


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


def take_one_packet(packets):
    return {"srcIP": packets[0][0][0], "srcPort": packets[1][0][0], "dstIP": packets[2][0][0], "dstPort": packets[3][0][0]}


def print_conflicting_pairs(P_x, tldP_x, t, tldt, node_name, P_ax, t_a, tldt_a, tag_node):
    print("\n\n!!! Conflicting Pairs Found !!!\n")

    print("(P1, t1):")
    print_rule(P_x, t)

    print("\n(P2, t2):")
    print_rule(tldP_x, tldt)

    print("\nin node " + node_name + ":")
    print("with [P@ || t1@ || t2@]:")
    print_rule_conflict(P_ax, t_a, tldt_a)
    print("Hint: Apply tags to P1 in node " + tag_node + " and use them to choose the transformation in node " + node_name)

def print_rule(packets, transformation):
    if transformation != "DROP":
        print_rule_accept(packets, transformation)
    else:
        print_rule_drop(packets, transformation)

def print_rule_accept(packets, transformation):
    row = [["sIp"], ["sPort"], ["dIp"], ["dPort"], ["prot"],
           ["tr_src"], ["tr_dst"]]
    
    src_segments = packets[0]
    dst_segments = packets[2]

    if packets[4] == [[18, 255], [0, 16]]:
        row[4].append("* \ {udp}")
    elif packets[4] == [[7, 255], [0, 5]]:
        row[4].append("* \ {tcp}")
    elif packets[4] == [[18, 255], [7, 16], [0, 5]]:
        row[4].append("* \ {tcp, udp}")
    else:
        row[4] += [print_prot_range(r) for r in packets[4]]

    # plus one because of the header line
    line_num = max([len(list_of_segments) + 1 for list_of_segments in
                   [packets[1]] + [row[4]] + [src_segments, dst_segments]])
    # print(row_num)
    # print(packets)
    # print(src_segments)
    # print(dst_segments)

    for line in range(line_num):
        if len(src_segments) > line:
            row[0].append(print_ip_range(src_segments[line]))
        else:
            row[0].append("")

        if len(packets[1]) > line:
            row[1].append(print_port_range(packets[1][line]))
        else:
            row[1].append("")

        if len(dst_segments) > line:
            row[2].append(print_ip_range(dst_segments[line]))
        else:
            row[2].append("")

        if len(packets[3]) > line:
            row[3].append(print_port_range(packets[3][line]))
        else:
            row[3].append("")

        if len(row[4]) <= line:
            row[4].append("")

        if line == 0:
            tr_src_string = "" 
            if transformation["srcIP"] != "id":
                tr_src_string += print_ip_range([transformation["srcIP"], transformation["srcIP"]])
            else:
                tr_src_string += "id"
            tr_src_string += " : "
            if transformation["srcPort"] != "id":
                tr_src_string += print_port_range([transformation["srcPort"], transformation["srcPort"]])
            else:
                tr_src_string += "id"
            row[5].append(tr_src_string)

            tr_dst_string = ""
            if transformation["dstIP"] != "id":
                tr_dst_string += print_ip_range([transformation["dstIP"], transformation["dstIP"]])
            else:
                tr_dst_string += "id"
            tr_dst_string += " : "
            if transformation["dstPort"] != "id":
                tr_dst_string += print_port_range([transformation["dstPort"], transformation["dstPort"]])
            else:
                tr_dst_string += "id"
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


def print_rule_drop(packets, transformation):
    row = [["sIp"], ["sPort"], ["dIp"], ["dPort"], ["prot"],
           ["tr"]]
    
    src_segments = packets[0]
    dst_segments = packets[2]

    if packets[4] == [[18, 255], [0, 16]]:
        row[4].append("* \ {udp}")
    elif packets[4] == [[7, 255], [0, 5]]:
        row[4].append("* \ {tcp}")
    elif packets[4] == [[18, 255], [7, 16], [0, 5]]:
        row[4].append("* \ {tcp, udp}")
    else:
        row[4] += [print_prot_range(r) for r in packets[4]]

    # plus one because of the header line
    line_num = max([len(list_of_segments) + 1 for list_of_segments in
                   [packets[1]] + [row[4]] + [src_segments, dst_segments]])

    for line in range(line_num):
        if len(src_segments) > line:
            row[0].append(print_ip_range(src_segments[line]))
        else:
            row[0].append("")

        if len(packets[1]) > line:
            row[1].append(print_port_range(packets[1][line]))
        else:
            row[1].append("")

        if len(dst_segments) > line:
            row[2].append(print_ip_range(dst_segments[line]))
        else:
            row[2].append("")

        if len(packets[3]) > line:
            row[3].append(print_port_range(packets[3][line]))
        else:
            row[3].append("")

        if len(row[4]) <= line:
            row[4].append("")

        if line == 0:
            tr_string = "DROP" 
            row[5].append(tr_string)
        else:
            row[5].append("")

    width = [0]*6
    for i in range(6):
        width[i] = max([len(field) + 2 for field in row[i]])

    print("=" * (sum(width) + 10))
    for line in range(line_num):
        sys.stdout.write("||")
        for field in range(6):
            sys.stdout.write(row[field][line].center(width[field]))
            sys.stdout.write("|")
            if field == 4 or field == 5:
                sys.stdout.write("|")
        print("")
        if line == 0 or line == line_num - 1:
            print("=" * (sum(width) + 10))


def print_rule_conflict(packets, transformation1, transformation2):
    row = [["sIp"], ["sPort"], ["dIp"], ["dPort"], ["prot"]]
    if transformation1 == "DROP":
        row = row + [["tr1"]]
    else: row = row + [["tr1_src"], ["tr1_dst"]]
    if transformation2 == "DROP":
        row = row + [["tr2"]]
    else: row = row + [["tr2_src"], ["tr2_dst"]]

    src_segments = packets[0]
    dst_segments = packets[2]

    if packets[4] == [[18, 255], [0, 16]]:
        row[4].append("* \ {udp}")
    elif packets[4] == [[7, 255], [0, 5]]:
        row[4].append("* \ {tcp}")
    elif packets[4] == [[18, 255], [7, 16], [0, 5]]:
        row[4].append("* \ {tcp, udp}")
    else:
        row[4] += [print_prot_range(r) for r in packets[4]]

    # plus one because of the header line
    line_num = max([len(list_of_segments) + 1 for list_of_segments in
                    [packets[1]] + [row[4]] + [src_segments, dst_segments]])
    # print(row_num)
    # print(packets)
    # print(src_segments)
    # print(dst_segments)

    for line in range(line_num):
        if len(src_segments) > line:
            row[0].append(print_ip_range(src_segments[line]))
        else:
            row[0].append("")

        if len(packets[1]) > line:
            row[1].append(print_port_range(packets[1][line]))
        else:
            row[1].append("")

        if len(dst_segments) > line:
            row[2].append(print_ip_range(dst_segments[line]))
        else:
            row[2].append("")

        if len(packets[3]) > line:
            row[3].append(print_port_range(packets[3][line]))
        else:
            row[3].append("")

        if len(row[4]) <= line:
            row[4].append("")

        if line == 0:
            col = 5
            if transformation1 == "DROP":
                row[col].append("DROP")
                col = col + 1
            else:
                tr_src_string = ""
                if transformation1["srcIP"] != "id":
                    tr_src_string += print_ip_range([transformation1["srcIP"], transformation1["srcIP"]])
                else:
                    tr_src_string += "id"
                tr_src_string += " : "
                if transformation1["srcPort"] != "id":
                    tr_src_string += print_port_range([transformation1["srcPort"], transformation1["srcPort"]])
                else:
                    tr_src_string += "id"
                row[col].append(tr_src_string)
                col = col + 1

                tr_dst_string = ""
                if transformation1["dstIP"] != "id":
                    tr_dst_string += print_ip_range([transformation1["dstIP"], transformation1["dstIP"]])
                else:
                    tr_dst_string += "id"
                tr_dst_string += " : "
                if transformation1["dstPort"] != "id":
                    tr_dst_string += print_port_range([transformation1["dstPort"], transformation1["dstPort"]])
                else:
                    tr_dst_string += "id"
                row[col].append(tr_dst_string)
                col = col + 1

            tr1_tr2_sep = col -1
            if transformation2 == "DROP":
                row[col].append("DROP")
                col = col + 1
            else:
                tr_src_string = ""
                if transformation2["srcIP"] != "id":
                    tr_src_string += print_ip_range([transformation2["srcIP"], transformation2["srcIP"]])
                else:
                    tr_src_string += "id"
                tr_src_string += " : "
                if transformation2["srcPort"] != "id":
                    tr_src_string += print_port_range([transformation2["srcPort"], transformation2["srcPort"]])
                else:
                    tr_src_string += "id"
                row[col].append(tr_src_string)
                col = col + 1

                tr_dst_string = ""
                if transformation2["dstIP"] != "id":
                    tr_dst_string += print_ip_range([transformation2["dstIP"], transformation2["dstIP"]])
                else:
                    tr_dst_string += "id"
                tr_dst_string += " : "
                if transformation2["dstPort"] != "id":
                    tr_dst_string += print_port_range([transformation2["dstPort"], transformation2["dstPort"]])
                else:
                    tr_dst_string += "id"
                row[col].append(tr_dst_string)
                col = col + 1
        else:
            for i in range(5, len(row)):
                row[i].append("")

    width = [0] * len(row)
    for i in range(len(row)):
        width[i] = max([len(field) + 2 for field in row[i]])

    print("=" * (sum(width) + 14))
    for line in range(line_num):
        sys.stdout.write("||")
        for field in range(len(row)):
            sys.stdout.write(row[field][line].center(width[field]))
            sys.stdout.write("|")
            if field == 4 or field == tr1_tr2_sep or field == len(row)-1:
                sys.stdout.write("|")
        print("")
        if line == 0 or line == line_num - 1:
            print("=" * (sum(width) + 14))


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
        elif range[0] == 6:
            return "tcp"
        elif range[0] == 1:
            return "icmp"
        else:
            return print_prot(range[0])
    elif range[0] == 0 and range[1] == 255:
        return "*"
    else:
        return print_prot(range[0]) + " - " + print_prot(range[1])


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
            elif segment[0] < address < segment[1]:
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
    s = ""
    for range in ranges:
        s = s + str(range[0]) + " - " + str(range[1]) + ", "
    return s


def print_port_rages(ranges):
    s = ""
    for range in ranges:
        s = s + str(range[0]) + " - " + str(range[1]) + ", "
    return s


def verify(packets, transformation, firewall):
    packet = take_one_packet(packets)
    # print("checking " + str(packet) + str(transformation))
    # print(print_traces(firewall.check(packet, transformation)))
    traces = firewall.check(packet, transformation)
    if traces == []:
        # print(packets, transformation)
        print("\n\n!!! Inexpressible Pair Found !!!\n")
        print_rule(packets, transformation)
    else:
        firewall.insert(packets, transformation, traces[0])


def check(rules, target_system, interfaces):

    global self_addresses
    # print("\n")
    # print(target_system)
    if target_system == "iptables":
        firewall = IPTABLES_firewall()
    elif target_system == "ipfw":
        firewall = IPFW_firewall()
    else:
        firewall = PF_firewall()
    
    self_addresses = [dot_to_integer_ip(v[1]) for v in interfaces.values()]

    # checkrules = semantics.get_packets()
    # print_rules([], checkrules)

    for rule in rules:
        # split based on selfness of addresses
        packets = rule[0]
        transformation = rule[1]
        IP_types = [IP.LOCAL, IP.NON_LOCAL]
        src_IPs = intersect_diff(rule[0][0], self_addresses)
        dst_IPs = intersect_diff(rule[0][2], self_addresses)
        # check each resulting rule
        for i in range(2):
            for j in range(2):
                if src_IPs[i] != [] and dst_IPs[j] != []:
                    packets[0] = src_IPs[i]
                    packets[2] = dst_IPs[j]
                    # print_rule(packets, transformation)
                    verify(packets, transformation, firewall)


def split(t, lbl):
    # print(t)
    # print(lbl)
    if lbl == "ID":
        t_a = {"srcIP": "id", "srcPort": "id", "dstIP": "id", "dstPort": "id"}
        t_r = t
    if lbl == "SNAT":
        t_a = {"srcIP": t["srcIP"], "srcPort": t["srcPort"], "dstIP": "id", "dstPort": "id"}
        t_r = {"srcIP": "id", "srcPort": "id", "dstIP": t["dstIP"], "dstPort": t["dstPort"]}
    if lbl == "DNAT":
        t_a = {"srcIP": "id", "srcPort": "id", "dstIP": t["dstIP"], "dstPort": t["dstPort"]}
        t_r = {"srcIP": t["srcIP"], "srcPort": t["srcPort"], "dstIP": "id", "dstPort": "id"}
    if lbl == "DROP":
        t_a = "DROP"
        t_r = None
    return (t_a, t_r)


# XXX TODO occorre ordinare i field prima...
def MC_intersec(P_a, tldP_a):
    I = []
    for i in range(len(P_a)):
        P_a[i].sort(key=(lambda x : x[0]))
        tldP_a[i].sort(key=(lambda x : x[0]))
        field = field_intersec(P_a[i], tldP_a[i])
        if field == []:
            return "empty"
        I.append(field)
    return I


def field_intersec(f1, f2):
    # print(f1, f2)
    if f1 == [] or f2 == []:
        return []
    elif f1[0][0] > f2[0][0]:
        return field_intersec(f2, f1)
    elif f1[0][1] < f2[0][0]:
        return field_intersec(f1[1:], f2)
    elif f1[0][1] <= f2[0][1]:
        return [[f2[0][0], f1[0][1]]] + field_intersec(f1[1:], f2)
    else:
        return [[f2[0][0], f2[0][1]]] + field_intersec(f1, f2[1:])


def inverse_t(t, Pa, P):
    Pb = P[:]
    if t["srcIP"] == "id":
        Pb[0] = Pa[0]
    if t["srcPort"] == "id":
        Pb[1] = Pa[1]
    if t["dstIP"] == "id":
        Pb[2] = Pa[2]
    if t["dstPort"] == "id":
        Pb[3] = Pa[3]
    return Pb


def compose(t_a, t_l):
    return {
        "srcIP": compose_f(t_a["srcIP"], t_l["srcIP"]),
        "srcPort": compose_f(t_a["srcPort"], t_l["srcPort"]),
        "dstIP": compose_f(t_a["dstIP"], t_l["dstIP"]),
        "dstPort": compose_f(t_a["dstPort"], t_l["dstPort"])
    }


def compose_f(t_a, t_l):
    if t_a == "id":
        return t_l
    else:
        return t_a


def MC_apply_t(t, P):
    P1 = P[:]
    if t["srcIP"] != "id":
        P1[0] = [[t["srcIP"], t["srcIP"]]]
    if t["srcPort"] != "id":
        P1[1] = [[t["srcPort"], t["srcPort"]]]
    if t["dstIP"] != "id":
        P1[2] = [[t["dstIP"], t["dstIP"]]]
    if t["dstPort"] != "id":
        P1[3] = [[t["dstPort"], t["dstPort"]]]
    return P1


def print_rules(rules):
    acceptrules = [rule for rule in rules if rule[1] != "DROP"]
    droprules = [rule for rule in rules if rule[1] == "DROP"]

    print_rules_accept(acceptrules)
    print_rules_drop(droprules)


def print_rules_accept(rules):
    rows = [[
                [["sIp"], ["sPort"], ["dIp"], ["dPort"], ["prot"],
                ["tr_src"], ["tr_dst"]], 
                1
            ]]

    width = [len(x[0]) for x in rows[0][0]]
    

    for rule in rules:
        # print(rule)
        row = [[] for x in range(7)]
        packets = rule[0]
        transformation = rule[1]

        src_segments = packets[0]
        dst_segments = packets[2]

        if packets[4] == [[18, 255], [0, 16]]:
            row[4].append("* \ {udp}")
        elif packets[4] == [[7, 255], [0, 5]]:
            row[4].append("* \ {tcp}")
        elif packets[4] == [[18, 255], [7, 16], [0, 5]]:
            row[4].append("* \ {tcp, udp}")
        else:
            row[4] += [print_prot_range(r) for r in packets[4]]

        # plus one because of the header line
        line_num = max([len(list_of_segments) + 1 for list_of_segments in
                    [packets[1]] + [packets[3]] + [row[4]] + [src_segments, dst_segments]])
        # print(row_num)
        # print(packets)
        # print(src_segments)
        # print(dst_segments)

        for line in range(line_num):
            # print(row)
            if len(src_segments) > line:
                row[0].append(print_ip_range(src_segments[line]))
            else:
                row[0].append("")

            if len(packets[1]) > line:
                row[1].append(print_port_range(packets[1][line]))
            else:
                row[1].append("")

            if len(dst_segments) > line:
                row[2].append(print_ip_range(dst_segments[line]))
            else:
                row[2].append("")

            if len(packets[3]) > line:
                row[3].append(print_port_range(packets[3][line]))
            else:
                row[3].append("")

            if len(row[4]) <= line:
                row[4].append("")

            if line == 0:
                tr_src_string = "" 
                if transformation["srcIP"] != "id":
                    tr_src_string += print_ip_range([transformation["srcIP"], transformation["srcIP"]])
                else:
                    tr_src_string += "id"
                tr_src_string += " : "
                if transformation["srcPort"] != "id":
                    tr_src_string += print_port_range([transformation["srcPort"], transformation["srcPort"]])
                else:
                    tr_src_string += "id"
                row[5].append(tr_src_string)

                tr_dst_string = ""
                if transformation["dstIP"] != "id":
                    tr_dst_string += print_ip_range([transformation["dstIP"], transformation["dstIP"]])
                else:
                    tr_dst_string += "id"
                tr_dst_string += " : "
                if transformation["dstPort"] != "id":
                    tr_dst_string += print_port_range([transformation["dstPort"], transformation["dstPort"]])
                else:
                    tr_dst_string += "id"
                row[6].append(tr_dst_string)
            else:
                for i in range(5, 7):
                    row[i].append("")

        for i in range(7):
            width[i] = max(width[i], max([len(field) + 2 for field in row[i]]))
        
        rows.append([row, line_num])

    # print(rows)
    print("=" * (sum(width) + 11))
    for rowlin in rows:
        row = rowlin[0]
        line_num = rowlin[1]
        for line in range(line_num):
            sys.stdout.write("||")
            for field in range(7):
                sys.stdout.write(row[field][line].center(width[field]))
                sys.stdout.write("|")
                if field == 4 or field == 6:
                    sys.stdout.write("|")
            print("")
        print("-" * (sum(width) + 11))



def print_rules_drop(rules):
    rows = [[
                [["sIp"], ["sPort"], ["dIp"], ["dPort"], ["prot"],
                ["tr"]], 
                1
            ]]

    width = [len(x[0]) for x in rows[0][0]]
    

    for rule in rules:
        # print(rule)
        row = [[] for x in range(6)]
        packets = rule[0]
        transformation = rule[1]

        src_segments = packets[0]
        dst_segments = packets[2]

        if packets[4] == [[18, 255], [0, 16]]:
            row[4].append("* \ {udp}")
        elif packets[4] == [[7, 255], [0, 5]]:
            row[4].append("* \ {tcp}")
        elif packets[4] == [[18, 255], [7, 16], [0, 5]]:
            row[4].append("* \ {tcp, udp}")
        else:
            row[4] += [print_prot_range(r) for r in packets[4]]

        # plus one because of the header line
        line_num = max([len(list_of_segments) + 1 for list_of_segments in
                    [packets[1]] + [packets[3]] + [row[4]] + [src_segments, dst_segments]])
        # print(row_num)
        # print(packets)
        # print(src_segments)
        # print(dst_segments)

        for line in range(line_num):
            # print(row)
            if len(src_segments) > line:
                row[0].append(print_ip_range(src_segments[line]))
            else:
                row[0].append("")

            if len(packets[1]) > line:
                row[1].append(print_port_range(packets[1][line]))
            else:
                row[1].append("")

            if len(dst_segments) > line:
                row[2].append(print_ip_range(dst_segments[line]))
            else:
                row[2].append("")

            if len(packets[3]) > line:
                row[3].append(print_port_range(packets[3][line]))
            else:
                row[3].append("")

            if len(row[4]) <= line:
                row[4].append("")

            if line == 0:
                row[5].append("DROP")
            else:
                row[5].append("")

        for i in range(6):
            width[i] = max(width[i], max([len(field) + 2 for field in row[i]]))
        
        rows.append([row, line_num])

    # print(rows)
    print("=" * (sum(width) + 11))
    for rowlin in rows:
        row = rowlin[0]
        line_num = rowlin[1]
        for line in range(line_num):
            sys.stdout.write("||")
            for field in range(6):
                sys.stdout.write(row[field][line].center(width[field]))
                sys.stdout.write("|")
                if field == 4:
                    sys.stdout.write("|")
            print("")
        print("-" * (sum(width) + 11))


def print_ip(ip):
    if ip < 0:
        ip = (4294967296 + ip) % 4294967296
    return integer_to_dot_ip(ip)