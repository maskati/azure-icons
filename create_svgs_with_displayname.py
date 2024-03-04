import json
import re
import sys

# Check if the correct number of command-line arguments is provided
if len(sys.argv) != 3:
    print("Usage: python create_svgs_with_displayname.py <input_json_file> <output_folder>")
    sys.exit(1)

input_json_file = sys.argv[1]
output_folder = sys.argv[2]

with open(input_json_file, "r") as json_file:
    data = json.load(json_file)

print("Number of data items:", len(data))

# Loop through the JSON data
for item in data:
    svg_data = item["svg"]
    filename = re.sub(r'[/]', '_', item["singularDisplayName"]).strip()

    # If singularDisplayName is empty, use value from name property
    if not filename:
        filename = re.sub(r'[/]', '_', item["name"]).strip()

    # Write SVG data to a file
    temp_svg_file = f"{output_folder}/{filename}.svg"
    with open(temp_svg_file, "w") as f:
        f.write(svg_data)

print("Conversion complete.")
