#!/usr/bin/env python3

import sys


def normalize_hierarchy(hierarchy: str) -> str:
    value = hierarchy.strip()
    if not value:
        raise ValueError("A hierarchy such as /configure service is required.")
    if not value.startswith("/configure"):
        raise ValueError("Hierarchy must start with /configure.")
    return value.rstrip()


def clean_config_lines(raw_text: str) -> list[str]:
    lines = []
    for line in raw_text.splitlines():
        stripped = line.rstrip()
        trimmed = stripped.strip()
        if not trimmed:
            continue
        if trimmed.startswith("[") and trimmed.endswith("]"):
            continue
        if trimmed.startswith("A:") and "# info" in trimmed:
            continue
        lines.append(trimmed)
    return lines


def flatten_sros_config(hierarchy: str, raw_text: str) -> list[str]:
    base = normalize_hierarchy(hierarchy)
    cleaned_lines = clean_config_lines(raw_text)
    path: list[str] = []
    flat_lines: list[str] = []

    for line in cleaned_lines:
        if line == "}":
            if path:
                path.pop()
            continue

        if line.endswith("{"):
            path.append(line[:-1].strip())
            continue

        flat_lines.append(" ".join([base] + path + [line]))

    return flat_lines


def read_pasted_config() -> str:
    print("Paste the SR OS hierarchical configuration block, then press Ctrl-D when finished:")
    return sys.stdin.read()


def main() -> int:
    try:
        hierarchy = input("Enter the current hierarchy (example: /configure service): ").strip()
    except EOFError:
        print("No hierarchy was provided.", file=sys.stderr)
        return 1

    try:
        raw_text = read_pasted_config()
        if not raw_text.strip():
            print("No configuration content was provided.", file=sys.stderr)
            return 1

        flat_lines = flatten_sros_config(hierarchy, raw_text)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if not flat_lines:
        print("No flat configuration lines were produced.", file=sys.stderr)
        return 1

    print("\nFlat configuration:\n")
    for line in flat_lines:
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
