import os
import json
import re
import pandas as pd
from collections import defaultdict

folder = "Json_lsp_folder_consolidated"
output_json = "consolidated_lsp_bandwidth.json"
output_excel = "consolidated_lsp_bandwidth.xlsx"

# Final consolidated structure
consolidated_data = {}

# Regex to extract timestamp from filename
timestamp_pattern = re.compile(r"(\d{4}_\d{2}_\d{2}_\d{2}_\d{2})")

if not os.path.exists(folder):
    print(f"Folder '{folder}' does not exist. Creating folder...")
    os.makedirs(folder, exist_ok=True)

# Step 1: Consolidate JSON files
for filename in os.listdir(folder):
    if not filename.endswith(".json"):
        continue

    match = timestamp_pattern.search(filename)
    if not match:
        print(f"Skipping file without timestamp: {filename}")
        continue

    timestamp = match.group(1)
    filepath = os.path.join(folder, filename)

    with open(filepath, 'r') as f:
        data = json.load(f)

    for site, site_data in data.items():
        for lsp_name, lsp_info in site_data.get("lsps", {}).items():
            router_name = lsp_name.split("-")[0]
            lsp_pair = "-".join(lsp_name.split("-")[0:2])
            bw_util = lsp_info["details"]["max_avg_bw_util"]
            bw_util_str = bw_util[-1] if isinstance(bw_util, list) and bw_util else str(bw_util)

            if router_name not in consolidated_data:
                consolidated_data[router_name] = {}
            if lsp_pair not in consolidated_data[router_name]:
                consolidated_data[router_name][lsp_pair] = {}
            if lsp_name not in consolidated_data[router_name][lsp_pair]:
                consolidated_data[router_name][lsp_pair][lsp_name] = {
                    "max_avg_bw_utils": [],
                    "timestamps": []
                }

            consolidated_data[router_name][lsp_pair][lsp_name]["max_avg_bw_utils"].append(bw_util_str)
            consolidated_data[router_name][lsp_pair][lsp_name]["timestamps"].append(timestamp)

# Step 2: Write to JSON
with open(output_json, 'w') as f:
    json.dump(consolidated_data, f, indent=2)

print(f"Consolidated data written to {output_json}")

# Step 3: Prepare Excel structure
router_data = {}

for router, lsp_pairs in consolidated_data.items():
    timestamp_set = set()
    structured = []

    for lsp_pair, lsps in lsp_pairs.items():
        first = True
        for lsp_name, details in lsps.items():
            row = {
                "LSP Pair": lsp_pair if first else "",
                "LSP Name": lsp_name
            }
            first = False
            for ts, bw in zip(details["timestamps"], details["max_avg_bw_utils"]):
                row[ts] = bw
                timestamp_set.add(ts)
            structured.append(row)
        # Append a blank row after each lsp_pair group
        structured.append({"LSP Pair": "", "LSP Name": ""})

    router_data[router] = (sorted(timestamp_set), structured)

# Step 4: Export to Excel (with blank row logic fixed)
with pd.ExcelWriter(output_excel, engine='xlsxwriter') as writer:
    for router, (timestamps, records) in router_data.items():
        columns = ["LSP Pair", "LSP Name"] + timestamps
        df = pd.DataFrame(records)

        # Identify blank rows
        is_blank_row = df["LSP Pair"].eq("") & df["LSP Name"].eq("")

        # Fill N/A only for non-blank rows
        df.loc[~is_blank_row, timestamps] = df.loc[~is_blank_row, timestamps].fillna("N/A")

        # Write to Excel
        df = df[columns]  # ensure column order
        df.to_excel(writer, sheet_name=router, index=False, startrow=0, startcol=0)

        # Formatting
        worksheet = writer.sheets[router]
        worksheet.freeze_panes(1, 2)
        worksheet.set_column('A:A', 20)
        worksheet.set_column('B:B', 35)
        worksheet.set_column(2, 2 + len(timestamps), 15)

print(f"Formatted Excel report with clean blank rows written to {output_excel}")

