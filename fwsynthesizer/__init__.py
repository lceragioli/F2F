
import argparse
import re
import sys, os
import time
from datetime import timedelta

from parsers.utils import file_to_dict, Negate

from HaPy import FireWallSynthesizer as Synthesis

import pkgutil
import importlib
import frontends
import expressivity

################################################################################
# GLOBALS

FRONTENDS = [ x[1] for x in pkgutil.iter_modules(frontends.__path__) ]

################################################################################
# UTILS

def remove_escaped_newlines(contents):
    return contents.replace("\\\n", " ")

def remove_comments(contents):
    return re.sub("#.*?\n", "\n", contents)

def preprocess(contents):
    "Preprocess a configuration file removing comments and escaped newlines"
    return remove_comments(remove_escaped_newlines(contents))

def get_local_addresses(interface_map):
    "Get local addresses from the interfaces file map"
    return [ local_addr for ifc, (subnet, local_addr) in interface_map.items() ]

def enum(*sequential, **named):
    "Make a c-style enum"
    enums = dict(zip(sequential, range(len(sequential))), **named)
    return type('Enum', (), enums)

def constrain_interface(interfaces, variable, ifname):
    """
    Make a formula in the generic language to constrain a variable to be
    inside the range of the selected interface subnet
    """

    ext_constraint = lambda var, constraints: "not ({})".format(
        " || ".join("{} == {}".format(var, addr) for addr in constraints))

    negated = False
    if isinstance(ifname, Negate):
        ifname = ifname.value
        negated = True

    if interfaces[ifname][0] == '0.0.0.0/0':
        constraints = [ network for ifc, (network, _) in interfaces.items() if ifc != ifname ] \
                    + [ interfaces[ifname][1] ]
        out = ext_constraint(variable, constraints)
    else:
        out = "{} == {}".format(variable, interfaces[ifname][0])

    return "not ({})".format(out) if negated else out

def import_frontend(name):
    """
    Import a frontend from the frontend package. 
    Note: each frontend is a python script that must contain a `frontend` variable
          with the definition of the Frontend object
    """ 
    if name in FRONTENDS:
        return importlib.import_module('.'+name, package="fwsynthesizer.frontends").frontend
    elif os.path.exists(name) and os.path.isfile(name):
        return Frontend(name="Generic",
                        diagram=name,
                        language_converter=lambda x,_: x)
    else:
        raise RuntimeError("Invalid Frontend '{}'!".format(name))

################################################################################
# FRONTEND

class Frontend:
    "Frontend object"
    def __init__(self, name, diagram, language_converter,
                 query_configuration=None, interfaces_enabled=True):
        """
        Make a Frontend object
        
        Args:
            name (str): frontend name
            diagram (str): diagram file path
            language_converter (Callable[[str,dict], str]): converter callable
            query_configuration (callable): query configuration loop
            interfaces_enabled (bool): do or do not consider the interfaces
        """
        self.name = name
        self.diagram = diagram
        self.language_converter = language_converter
        self.query_configuration = query_configuration
        self.interfaces_enabled = interfaces_enabled

class LanguageConverter:
    "Callable object that converts a configuration file to the generic language"
    def __init__(self, parser, converter):
        self.parser = parser
        self.converter = converter

    def __call__(self, contents, interfaces):
        contents   = preprocess(contents)
        ast        = self.parser(contents)
        rules      = self.converter(ast, interfaces)
        return rules

def converter(parser, converter):
    "Make a LanguageConverter object"
    return LanguageConverter(parser, converter)

def query_configuration(get_lines, delete_rule):
    "Query a configuration and show all the rules that affect the selected packets"

    def query_loop(name, diagram, contents, interfaces, query,
                   languageconverter):
        contents = preprocess(contents)
        local_addresses = get_local_addresses(interfaces)
        lines = get_lines(contents)
        rules = languageconverter.parser(contents)
        rules_contents = languageconverter.converter(rules, interfaces)
        firewall = Firewall(name, diagram, rules_contents, local_addresses)

        for i in range(0, len(lines)):
            rules1 = delete_rule(rules, i)
            rules_contents1 = languageconverter.converter(rules1, interfaces)
            test = Firewall("{}_{}".format(name, i), diagram,rules_contents1, local_addresses)
            res = firewall.equivalence(test, query=query)
            if not res: print lines[i]

    return query_loop

################################################################################
# SYNTHESIS INTERFACE

LocalFlag  = enum('BOTH', 'LOCAL', 'NOLOCAL')
NatFlag    = enum('ALL', 'FILTER', 'NAT')
TableStyle = enum('UNICODE', 'ASCII', 'TEX')

class Firewall:
    "Firewall Object that can be synthesized and analyzed"

    def __init__(self, name, diagram, chains, local_addresses):
        """
        Make a Firewall Object

        Args:
            name (str): name of the firewall (displayed in parser error messages)
            diagram (str): diagram file path
            chains (str): chain file contents in the generic language
            local_addresses (List[str]): local addresses of the firewall
        """
        self.name = name
        self.locals = local_addresses
        self.__fw = Synthesis.make_firewall(diagram, name, chains, local_addresses)

    def synthesize(self, local_src=LocalFlag.BOTH, local_dst=LocalFlag.BOTH, query="true"):
        """
        Synthesize a specification

        Args:
            local_src (LocalFlag): constraint for the source address
            local_dst (LocalFlag): constraint for the destination address
            query (str): generic constraint expressed in the query language
        Returns:
            SynthesisOutput object
        """

        rules = Synthesis.synthesize(self.__fw, self.locals, local_src, local_dst, query)
        return SynthesisOutput(self, rules)

    def implication(self, other, local_src=LocalFlag.BOTH, local_dst=LocalFlag.BOTH, query="true"):
        """
        Check for implication between two firewalls

        Args:
            other (Firewall): other firewall to check
            local_src (LocalFlag): constraint for the source address
            local_dst (LocalFlag): constraint for the destination address
            query (str): generic constraint expressed in the query language
        Returns:
            boolean value if the second firewall is implied by `self`
        """

        return Synthesis.implication(self.__fw, other.__fw, self.locals, local_src, local_dst, query)

    def equivalence(self, other, local_src=LocalFlag.BOTH, local_dst=LocalFlag.BOTH, query="true"):
        """
        Check for equivalence between two firewalls

        Args:
            other (Firewall): other firewall to check
            local_src (LocalFlag): constraint for the source address
            local_dst (LocalFlag): constraint for the destination address
            query (str): generic constraint expressed in the query language
        Returns:
            boolean value if the second firewall is equivalent to `self`
        """
        return Synthesis.equivalence(self.__fw, other.__fw, self.locals, local_src, local_dst, query)

    def difference(self, other, local_src=LocalFlag.BOTH, local_dst=LocalFlag.BOTH, query="true"):
        """
        Synthesize the difference between two firealls

        Args:
            local_src (LocalFlag): constraint for the source address
            local_dst (LocalFlag): constraint for the destination address
            query (str): generic constraint expressed in the query language
        Returns:
            DiffOutput object
        """
        plus, minus = Synthesis.difference(self.__fw, other.__fw, self.locals, local_src, local_dst, query)
        return DiffOutput(self, other, plus, minus)


class SynthesisOutput:
    "Firewall synthesis output"

    def __init__(self, fw, rules):
        self.firewall = fw
        self.__rules = rules

    def get_rules(self):
        "Get the rules as lists of ints"
        return [ Synthesis.mrule_list(r) for r in self.__rules ]

    def print_table(self, table_style=TableStyle.UNICODE, local_src=LocalFlag.BOTH,
                    local_dst=LocalFlag.BOTH, nat=NatFlag.ALL):
        """
        Print the table showing the synthesis

        Args:
            table_style (TableStyle): select the style of the table
            local_src (LocalFlag): hide local addresses if explicitly removed from ranges in the source IP
            local_dst (LocalFlag): hide local addresses if explicitly removed from ranges in the destination IP
            nat (NatFlag): show only nat or filter rules
        """
        Synthesis.mrule_table(self.__rules, table_style,
                              self.firewall.locals, local_src, local_dst, nat)


class DiffOutput:
    "Firewall difference output"
    def __init__(self, fw, fw1, plus, minus):
        self.firewall  = fw
        self.firewall2 = fw1
        self.__plus = plus
        self.__minus = minus

    def get_rules(self):
        "Get the rules as list of lists of ints"
        return ([ Synthesis.mrule_list(r) for r in self.__plus ],
                [ Synthesis.mrule_list(r) for r in self.__minus ])

    def print_table(self, table_style=TableStyle.UNICODE,
                    local_src=LocalFlag.BOTH, local_dst=LocalFlag.BOTH):
        """
        Print the table showing the synthesis

        Args:
            table_style (TableStyle): select the style of the table
            local_src (LocalFlag): hide local addresses if explicitly removed from ranges in the source IP
            local_dst (LocalFlag): hide local addresses if explicitly removed from ranges in the destination IP
        """
        Synthesis.diff_table(table_style, self.firewall.name, self.firewall2.name,
                             self.__plus, self.__minus, self.firewall.locals, local_src, local_dst)

################################################################################
# MAIN


def main():

    # Argument Parsing
    parser = argparse.ArgumentParser(
        description="FireWall-Portability -- Check the Portability of a Given Policy in other Firewall Systems")

    parser.add_argument("frontend", metavar="FROM", help="Source firewall system"
                        .format(", ".join(FRONTENDS)))
    
    parser.add_argument('interfaces', metavar="INTERFACES", help='Interfaces specification file')
    parser.add_argument('file',  metavar="FILE", help='Configuration file')
    parser.add_argument('target',  metavar="TARGET", help='Target firewall system')

    # Argument Processing
    args = parser.parse_args()
    frontend = import_frontend(args.frontend)
        
    file_contents = open(args.file).read()
    diagram_file = os.path.join(os.path.dirname(__file__), frontend.diagram)

    if frontend.interfaces_enabled and not args.interfaces:
        raise RuntimeError(
            "No interfaces file specified! " +
            "The seleced frontend requires the (-i|--interfaces) parameter")
    interfaces = file_to_dict(args.interfaces) if frontend.interfaces_enabled else {}

    local_addresses = get_local_addresses(interfaces)
    chain_contents = frontend.language_converter(file_contents, interfaces)
    firewall = Firewall(name=args.file,
                        diagram=diagram_file,
                        chains=chain_contents,
                        local_addresses=local_addresses)

    if args.target not in ["iptables", "pf", "ipfw"]:
        raise RuntimeError(
            "Invalid target language; must be one of iptables, pf or ipfw")

    semantics = firewall.synthesize()

    # print("\n")
    # only for checking
    # semantics.print_table()

    expressivity.check(semantics, args.target, interfaces)


