#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""
Unpacks legacy V2Ray/v2fly/Loyalsoldier geoip.dat and geosite.dat Protobuf files
into Canonical Rule Source (.rules) format for compilation with daer-drb (ADR-0031).

Pure Python standard-library implementation: requires no external dependencies (zero pip packages).
"""

import argparse
import ipaddress
import os
import sys


def read_varint(data: bytes, offset: int) -> tuple[int, int]:
    """Reads a protobuf varint starting at offset, returning (value, new_offset)."""
    res = 0
    shift = 0
    while offset < len(data):
        b = data[offset]
        offset += 1
        res |= (b & 0x7F) << shift
        if not (b & 0x80):
            return res, offset
        shift += 7
        if shift > 64:
            raise ValueError("varint overflow (>64 bits)")
    raise ValueError("truncated varint at EOF")


def parse_protobuf_fields(data: bytes) -> list[tuple[int, int, bytes | int]]:
    """
    Parses raw Protobuf length-delimited wire messages into (field_number, wire_type, value).
    Wire types:
      0: Varint (int)
      1: 64-bit (bytes)
      2: Length-delimited (bytes)
      5: 32-bit (bytes)
    """
    offset = 0
    fields = []
    while offset < len(data):
        tag, offset = read_varint(data, offset)
        wire_type = tag & 0x07
        field_num = tag >> 3

        if wire_type == 0:
            val, offset = read_varint(data, offset)
            fields.append((field_num, wire_type, val))
        elif wire_type == 1:
            if offset + 8 > len(data):
                raise ValueError("truncated fixed64")
            val = data[offset : offset + 8]
            offset += 8
            fields.append((field_num, wire_type, val))
        elif wire_type == 2:
            length, offset = read_varint(data, offset)
            if offset + length > len(data):
                raise ValueError(
                    f"truncated length-delimited field {field_num} (needed {length} bytes)"
                )
            val = data[offset : offset + length]
            offset += length
            fields.append((field_num, wire_type, val))
        elif wire_type == 5:
            if offset + 4 > len(data):
                raise ValueError("truncated fixed32")
            val = data[offset : offset + 4]
            offset += 4
            fields.append((field_num, wire_type, val))
        else:
            raise ValueError(
                f"unsupported protobuf wire type {wire_type} for field {field_num}"
            )
    return fields


def parse_geoip_entry(entry_bytes: bytes) -> tuple[str, list[str]]:
    """
    Parses a single GeoIP message:
      field 1: country_code (string)
      field 2: cidr (message CIDR: field 1 ip [bytes], field 2 prefix [varint])
    """
    fields = parse_protobuf_fields(entry_bytes)
    country_code = ""
    cidrs = []

    for field_num, wire_type, val in fields:
        if field_num == 1 and wire_type == 2:
            country_code = val.decode("utf-8", errors="replace").strip()
        elif field_num == 2 and wire_type == 2:
            # Parse CIDR message
            cidr_fields = parse_protobuf_fields(val)
            ip_raw = b""
            prefix = 0
            for c_num, c_wire, c_val in cidr_fields:
                if c_num == 1 and c_wire == 2:
                    ip_raw = c_val
                elif c_num == 2 and c_wire == 0:
                    prefix = c_val

            if len(ip_raw) == 4 or len(ip_raw) == 16:
                try:
                    ip_obj = ipaddress.ip_address(ip_raw)
                    net = ipaddress.ip_network(f"{ip_obj}/{prefix}", strict=False)
                    cidrs.append(str(net))
                except ValueError:
                    pass

    return country_code, cidrs


def parse_geosite_entry(
    entry_bytes: bytes,
) -> tuple[str, list[tuple[str, str, list[str]]], int]:
    """
    Parses a single SiteGroup message:
      field 1: tag / country_code (string)
      field 2: domain (message Domain)
        Domain:
          field 1: type (0=Plain, 1=Regex, 2=RootDomain, 3=Full)
          field 2: value (string)
          field 3: attribute (message Attribute: field 1 key, field 2 bool_value)
    Returns:
      (tag, rules [(kind, pattern, attrs)], skipped_plain_regex_count)
    """
    fields = parse_protobuf_fields(entry_bytes)
    tag = ""
    rules = []
    skipped_count = 0

    for field_num, wire_type, val in fields:
        if field_num == 1 and wire_type == 2:
            tag = val.decode("utf-8", errors="replace").strip()
        elif field_num == 2 and wire_type == 2:
            # Parse Domain message
            d_fields = parse_protobuf_fields(val)
            d_type = 0
            d_val = ""
            attrs = []

            for df_num, df_wire, df_val in d_fields:
                if df_num == 1 and df_wire == 0:
                    d_type = df_val
                elif df_num == 2 and df_wire == 2:
                    d_val = df_val.decode("utf-8", errors="replace").strip()
                elif df_num == 3 and df_wire == 2:
                    # Attribute
                    a_fields = parse_protobuf_fields(df_val)
                    key = ""
                    for af_num, af_wire, af_val in a_fields:
                        if af_num == 1 and af_wire == 2:
                            key = af_val.decode("utf-8", errors="replace").strip()
                    if key:
                        attrs.append(key)

            if not d_val:
                continue

            d_val = d_val.lower().strip()
            # Allowed domain characters per ADR-0031 / daer-rule-ast: a-z, 0-9, '.', '-', '_', '^'
            allowed_chars = set("abcdefghijklmnopqrstuvwxyz0123456789.-_^")
            if any(ch not in allowed_chars for ch in d_val):
                skipped_count += 1
                continue

            # In CRS v1 (ADR-0031, ADR-0033):
            # 2: RootDomain -> suffix: <domain>
            # 3: Full -> full: <domain>
            # 0: Plain, 1: Regex -> not supported as routing predicates
            if d_type == 2:
                rules.append(("suffix", d_val, attrs))
            elif d_type == 3:
                rules.append(("full", d_val, attrs))
            else:
                skipped_count += 1

    return tag, rules, skipped_count


def unpack_geoip(
    dat_path: str, target_code: str | None, list_only: bool
) -> tuple[str, list[str]]:
    with open(dat_path, "rb") as f:
        data = f.read()

    root_fields = parse_protobuf_fields(data)
    available: dict[str, list[str]] = {}

    for field_num, wire_type, val in root_fields:
        if field_num == 1 and wire_type == 2:
            code, cidrs = parse_geoip_entry(val)
            if code:
                available.setdefault(code.lower(), []).extend(cidrs)

    if list_only:
        print(f"Available GeoIP codes in {dat_path}:")
        for code in sorted(available.keys()):
            print(f"  {code.upper():<12} ({len(available[code])} CIDRs)")
        sys.exit(0)

    if not target_code:
        raise ValueError("--code is required when --list is not specified")

    normalized = target_code.strip().lower()
    if normalized not in available:
        candidates = ", ".join(sorted(c.upper() for c in available.keys())[:15])
        raise KeyError(
            f"code '{target_code}' not found in {dat_path}. Available codes include: {candidates}..."
        )

    return normalized, available[normalized]


def unpack_geosite(
    dat_path: str, target_code: str | None, list_only: bool
) -> tuple[str, list[tuple[str, str, list[str]]], int]:
    with open(dat_path, "rb") as f:
        data = f.read()

    root_fields = parse_protobuf_fields(data)
    available: dict[str, list[tuple[str, str, list[str]]]] = {}
    total_skipped: dict[str, int] = {}

    for field_num, wire_type, val in root_fields:
        if field_num == 1 and wire_type == 2:
            tag, rules, skipped = parse_geosite_entry(val)
            if tag:
                normalized_tag = tag.lower()
                available.setdefault(normalized_tag, []).extend(rules)
                total_skipped[normalized_tag] = (
                    total_skipped.get(normalized_tag, 0) + skipped
                )

    if list_only:
        print(f"Available GeoSite categories in {dat_path}:")
        for tag in sorted(available.keys()):
            count = len(available[tag])
            skipped = total_skipped.get(tag, 0)
            suffix = f", {skipped} skipped plain/regex" if skipped else ""
            print(f"  {tag:<24} ({count} patterns{suffix})")
        sys.exit(0)

    if not target_code:
        raise ValueError("--code is required when --list is not specified")

    normalized = target_code.strip().lower()
    if normalized not in available:
        candidates = ", ".join(sorted(available.keys())[:15])
        raise KeyError(
            f"category '{target_code}' not found in {dat_path}. Available categories include: {candidates}..."
        )

    return normalized, available[normalized], total_skipped.get(normalized, 0)


def main():
    parser = argparse.ArgumentParser(
        description="Extract entries from legacy geoip.dat / geosite.dat into Canonical Rule Source (.rules)"
    )
    parser.add_argument(
        "--kind",
        choices=["geosite", "geoip"],
        required=True,
        help="Type of dat file to unpack",
    )
    parser.add_argument(
        "--dat",
        required=True,
        help="Path to the .dat file (e.g. geosite.dat or geoip.dat)",
    )
    parser.add_argument(
        "--code",
        help="Target category or country code to extract (e.g. cn, apple, google)",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available codes/categories in the dat file and exit",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="-",
        help="Output path for the .rules file, or '-' for stdout (default)",
    )

    args = parser.parse_args()

    if not os.path.isfile(args.dat):
        sys.stderr.write(f"error: file not found: {args.dat}\n")
        sys.exit(1)

    lines = []
    if args.kind == "geoip":
        try:
            code, cidrs = unpack_geoip(args.dat, args.code, args.list)
        except Exception as e:
            sys.stderr.write(f"error: {e}\n")
            sys.exit(1)

        lines.append(f"name: geoip-{code}")
        lines.append("")
        for cidr in cidrs:
            lines.append(f"ip: {cidr}")

    elif args.kind == "geosite":
        try:
            code, rules, skipped = unpack_geosite(args.dat, args.code, args.list)
        except Exception as e:
            sys.stderr.write(f"error: {e}\n")
            sys.exit(1)

        if skipped > 0:
            sys.stderr.write(
                f"note: skipped {skipped} plain/regex pattern(s) in '{code}' (ADR-0031/ADR-0033: domain routing accepts suffix: and full: only)\n"
            )

        lines.append(f"name: geosite-{code}")
        lines.append("")
        for kind, pattern, attrs in rules:
            attr_suffix = (
                (" " + " ".join(f"@{a.lower()}" for a in attrs)) if attrs else ""
            )
            lines.append(f"{kind}: {pattern}{attr_suffix}")

    content = "\n".join(lines) + "\n"
    if args.output == "-" or not args.output:
        sys.stdout.write(content)
    else:
        out_dir = os.path.dirname(os.path.abspath(args.output))
        os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(content)
        count = len(lines) - 2  # minus header and empty line
        sys.stderr.write(f"wrote {args.output} ({count} directives)\n")


if __name__ == "__main__":
    main()
