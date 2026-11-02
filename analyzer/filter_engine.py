from __future__ import annotations

import re
from typing import Any

from analyzer.packet_parser import PacketRecord


class FilterError(ValueError):
    pass


_SUPPORTED_PROTOCOLS = {"tcp", "udp", "dns", "icmp", "arp"}


def parse_filter_expression(expression: str) -> str:
    if not expression or not expression.strip():
        raise FilterError("Filter expression cannot be empty")

    if re.search(r"(?i)(?:eval\s*\(|__import__|os\.system|subprocess|;|`)", expression):
        raise FilterError("Dangerous filter expression detected")

    text = expression.strip()
    return text


class _FilterParser:
    def __init__(self, text: str) -> None:
        self.text = text
        self.position = 0

    def parse(self) -> Any:
        node = self._parse_or()
        self._skip_whitespace()
        if self.position != len(self.text):
            raise FilterError(f"Unexpected token near: {self.text[self.position:]}")
        return node

    def _skip_whitespace(self) -> None:
        while self.position < len(self.text) and self.text[self.position].isspace():
            self.position += 1

    def _match_keyword(self, keyword: str) -> bool:
        self._skip_whitespace()
        end = self.position + len(keyword)
        if self.text[self.position:end].lower() != keyword:
            return False
        next_char = self.text[end:end + 1]
        if next_char and not next_char.isspace() and next_char not in ")":
            return False
        self.position = end
        return True

    def _parse_or(self) -> Any:
        left = self._parse_and()
        while self._match_keyword("or"):
            right = self._parse_and()
            left = ("or", left, right)
        return left

    def _parse_and(self) -> Any:
        left = self._parse_not()
        while self._match_keyword("and"):
            right = self._parse_not()
            left = ("and", left, right)
        return left

    def _parse_not(self) -> Any:
        if self._match_keyword("not"):
            return ("not", self._parse_not())
        return self._parse_primary()

    def _parse_primary(self) -> Any:
        self._skip_whitespace()
        if self.position >= len(self.text):
            raise FilterError("Unexpected end of expression")
        if self.text[self.position] == "(":
            self.position += 1
            node = self._parse_or()
            self._skip_whitespace()
            if self.position >= len(self.text) or self.text[self.position] != ")":
                raise FilterError("Mismatched parentheses in filter expression")
            self.position += 1
            return node

        match = re.match(
            r"(?is)(?P<field>ip\.addr|ip\.src|ip\.dst|tcp\.port|udp\.port|frame\.len|tcp\.flags\.syn)\s*(?P<op>==|!=|>=|<=|>|<)\s*(?P<value>[A-Za-z0-9.:-]+)",
            self.text[self.position :],
        )
        if match:
            self.position += match.end()
            return ("compare", match.group("field"), match.group("op"), match.group("value"))

        protocol_match = re.match(r"(?is)(?P<name>tcp|udp|dns|icmp|arp)\b", self.text[self.position :])
        if protocol_match:
            self.position += protocol_match.end()
            return ("protocol", protocol_match.group("name").lower())

        raise FilterError(f"Unsupported filter expression: {self.text[self.position:]}")


def _packet_field(packet: PacketRecord, field: str) -> Any:
    if field == "ip.addr":
        return [packet.source_address, packet.destination_address]
    if field == "ip.src":
        return packet.source_address
    if field == "ip.dst":
        return packet.destination_address
    if field == "tcp.port":
        ports = {packet.source_port, packet.destination_port}
        ports.discard(None)
        return list(ports)
    if field == "udp.port":
        ports = {packet.source_port, packet.destination_port}
        ports.discard(None)
        return list(ports)
    if field == "frame.len":
        return packet.packet_length
    if field == "tcp.flags.syn":
        return int(packet.metadata.get("tcp_flags_syn", 0))
    raise FilterError(f"Unsupported field: {field}")


def _compare(left: Any, op: str, right: Any) -> bool:
    if op == "==":
        if isinstance(left, list):
            return any(value == right for value in left)
        return left == right
    if op == "!=":
        if isinstance(left, list):
            return all(value != right for value in left)
        return left != right
    if op == ">":
        return left > right
    if op == ">=":
        return left >= right
    if op == "<":
        return left < right
    if op == "<=":
        return left <= right
    raise FilterError(f"Unsupported comparison operator: {op}")


def _evaluate_node(packet: PacketRecord, node: Any) -> bool:
    if not isinstance(node, tuple):
        raise FilterError(f"Unsupported filter node: {node}")

    kind = node[0]
    if kind == "and":
        return _evaluate_node(packet, node[1]) and _evaluate_node(packet, node[2])
    if kind == "or":
        return _evaluate_node(packet, node[1]) or _evaluate_node(packet, node[2])
    if kind == "not":
        return not _evaluate_node(packet, node[1])
    if kind == "protocol":
        proto = getattr(packet, "protocol", "")
        if proto is None:
            return False
        if isinstance(proto, int):
            try:
                from analyzer.packet_parser import PROTOCOL_MAP
                proto = PROTOCOL_MAP.get(proto, str(proto))
            except Exception:
                proto = str(proto)
        if isinstance(proto, str):
            return proto.lower() == node[1]
        return str(proto).lower() == node[1]
    if kind == "compare":
        field, op, raw_value = node[1], node[2], node[3]
        left = _packet_field(packet, field)
        try:
            right = int(raw_value) if field in {"tcp.port", "udp.port", "frame.len", "tcp.flags.syn"} else raw_value
            return _compare(left, op, right)
        except (TypeError, ValueError):
            return False

    raise FilterError(f"Unsupported filter node: {node}")


def _compile_node_sql(node: Any) -> tuple[str, list[Any]]:
    kind = node[0]
    if kind in {"and", "or"}:
        left_sql, left_params = _compile_node_sql(node[1])
        right_sql, right_params = _compile_node_sql(node[2])
        operator = "AND" if kind == "and" else "OR"
        return f"({left_sql} {operator} {right_sql})", left_params + right_params
    if kind == "not":
        child_sql, params = _compile_node_sql(node[1])
        return f"(NOT {child_sql})", params
    if kind == "protocol":
        return "(protocol = ? COLLATE NOCASE)", [node[1]]
    if kind != "compare":
        raise FilterError(f"Unsupported filter node: {node}")

    field, op, raw_value = node[1], node[2], node[3]
    if field in {"tcp.port", "udp.port", "frame.len", "tcp.flags.syn"}:
        try:
            value: Any = int(raw_value)
        except ValueError:
            return "(0)", []
    else:
        value = raw_value

    if field == "ip.addr":
        source = "COALESCE(source_address, '')"
        destination = "COALESCE(destination_address, '')"
        if op == "==":
            return f"({source} = ? OR {destination} = ?)", [value, value]
        if op == "!=":
            return f"({source} != ? AND {destination} != ?)", [value, value]
        return "(0)", []
    if field in {"ip.src", "ip.dst"}:
        column = "source_address" if field == "ip.src" else "destination_address"
        return f"(COALESCE({column}, '') {op} ?)", [value]
    if field in {"tcp.port", "udp.port"}:
        if op == "==":
            return (
                "(COALESCE(source_port = ?, 0) OR "
                "COALESCE(destination_port = ?, 0))",
                [value, value],
            )
        if op == "!=":
            return (
                "(COALESCE(source_port != ?, 1) AND "
                "COALESCE(destination_port != ?, 1))",
                [value, value],
            )
        return "(0)", []
    if field == "frame.len":
        return f"(COALESCE(packet_length, 0) {op} ?)", [value]
    if field == "tcp.flags.syn":
        return f"(COALESCE(tcp_flags_syn, 0) {op} ?)", [value]
    raise FilterError(f"Unsupported field: {field}")


def compile_filter_sql(expression: str) -> tuple[str, list[Any]]:
    """Compile the supported display-filter grammar to parameterized SQLite SQL."""
    if not expression or not expression.strip():
        return "(1)", []
    text = parse_filter_expression(expression)
    return _compile_node_sql(_FilterParser(text).parse())


def evaluate_filter(packet: PacketRecord, expression: str) -> bool:
    expr = parse_filter_expression(expression)
    if not expr:
        return True
    return _evaluate_node(packet, _FilterParser(expr).parse())
