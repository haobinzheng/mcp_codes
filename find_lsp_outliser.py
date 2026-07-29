import os
import json
import re

def analyze_lsp_outliers(folder="Json_lsp_folder"):
    if not os.path.exists(folder):
        raise FileNotFoundError(f"Folder {folder} does not exist.")

    json_paths = []
    for root, dirs, files in os.walk(folder):
        for file in files:
            if file.endswith(".json") or not "." in file:
                if not file.startswith("."):
                    json_paths.append((file, os.path.join(root, file)))

    if not json_paths:
        raise FileNotFoundError(f"No JSON files found in {folder}.")
    
    lsp_groups = {}

    for filename, json_path in json_paths:
        with open(json_path, "r") as f:
            data = json.load(f)

        default_router_name = filename.replace(".json", "")

        items_to_process = []
        if isinstance(data, dict):
            first_val = next(iter(data.values()), None)
            if first_val and isinstance(first_val, dict) and "details" in first_val:
                items_to_process.append((default_router_name, data))
            elif first_val and isinstance(first_val, dict):
                for r_name, sub_dict in data.items():
                    if isinstance(sub_dict, dict):
                        sub_first = next(iter(sub_dict.values()), None)
                        if sub_first and isinstance(sub_first, dict) and "details" in sub_first:
                            items_to_process.append((r_name, sub_dict))
                        elif isinstance(sub_first, dict):
                            for m_name, lsp_d in sub_dict.items():
                                if isinstance(lsp_d, dict):
                                    items_to_process.append((r_name, lsp_d))

        for router_name, lsp_dict in items_to_process:
            for lsp_name, lsp_info in lsp_dict.items():
                if not isinstance(lsp_info, dict) or "details" not in lsp_info:
                    continue
                parts = lsp_name.split("-")
                if len(parts) < 3:
                    continue
                full_ingress = parts[0]
                full_egress = parts[1]

                bw_val = lsp_info["details"].get("max_avg_bw_util", "0Gbps")
                if isinstance(bw_val, list) and bw_val:
                    bw_str = bw_val[-1]
                elif isinstance(bw_val, str):
                    bw_str = bw_val
                else:
                    bw_str = "0Gbps"

                match = re.match(r"([\d.]+)([GMK]bps)", bw_str)
                if not match:
                    continue

                value, unit = float(match.group(1)), match.group(2).lower()
                if unit == "kbps":
                    bw = value / 1_000_000
                elif unit == "mbps":
                    bw = value / 1_000
                elif unit == "gbps":
                    bw = value
                else:
                    continue  # unknown unit

                key = (router_name, full_ingress, full_egress)
                lsp_groups.setdefault(key, []).append((lsp_name, bw))

    outliers = []
    for (router_name, full_ingress, full_egress), lsp_list in lsp_groups.items():
        for i, (lsp_i_name, bw_i) in enumerate(lsp_list):
            others = [(name, bw) for j, (name, bw) in enumerate(lsp_list) if j != i]
            if not others:
                continue
            if all(bw_i >= 10 * bw for _, bw in others):
                outliers.append({
                    "router_name": router_name,
                    "router_pair": f"{full_ingress} → {full_egress}",
                    "outlier_lsp": lsp_i_name,
                    "outlier_util_gbps": round(bw_i, 4),
                    "other_lsps": [{"name": name, "util_gbps": round(bw, 4)} for name, bw in others]
                })

    return outliers

# Example usage
if __name__ == "__main__":
    results = analyze_lsp_outliers()
    print("\n=== Outlier Report (≥ 10× other LSPs) ===")
    if not results:
        print("No outliers found.")
    for entry in results:
        print(f"Router: {entry['router_name']}")
        print(f"  Ingress → Egress: {entry['router_pair']}")
        print(f"  Outlier LSP: {entry['outlier_lsp']} (util: {entry['outlier_util_gbps']} Gbps)")
        print("  Other LSPs:")
        for other in entry["other_lsps"]:
            print(f"    - {other['name']}: {other['util_gbps']} Gbps")
        print()
