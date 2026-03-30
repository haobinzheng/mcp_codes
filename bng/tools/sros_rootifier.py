import os 
import re
import argparse

try:
    from flask import Blueprint, jsonify, render_template, request
except ImportError:  # pragma: no cover - optional for CLI usage
    Blueprint = None
    jsonify = None
    render_template = None
    request = None


def rm_insignificant_lines(in_cfg):
    """
    Remove insignificant lines from input config file.
    These lines are starting with '#' or 'echo'
    :param in_cfg: cfg as a multiline string
    :return: cleanified array of config lines
    """
    cfg_arr = in_cfg.splitlines()
    # make a dup array for in-place deletion
    for line in list(cfg_arr):
        if not is_cfg_statement(line):
            cfg_arr.remove(line)
    return cfg_arr


def is_cfg_statement(line):
    # if line is empty, or first for elemets are not spaces
    # consider this line for deletion
    if line.strip() == '' or line[0:4] != '    ':
        return False
    else:
        return True


def rootify(clean_cfg):
    cfg_string = ['/configure']
    rootified_cfg = """"""
    # init previous indent level as 0 for /configure line
    prev_ind_level = 0

    for i, line in enumerate(clean_cfg):
        #print(line)
        if "------------------" in line or "echo" in line:
            continue
        if line.strip() == 'exit':
            if len(cfg_string) > 1:
                cfg_string.pop()
            prev_ind_level = max(0, prev_ind_level - 4)
            continue

        # calc current indent
        cur_ind_level = len(line) - len(line.lstrip())
        stripped_line = line.strip()
        if stripped_line == "configure":
            prev_ind_level = 0
            continue

        # trim the stack back to the current indentation depth
        target_depth = max(1, cur_ind_level // 4 + 1)
        while len(cfg_string) > target_depth:
            cfg_string.pop()

        # append a command if it is on a next level of indent
        if cur_ind_level > prev_ind_level:
            cfg_string.append(stripped_line)
        # if a command on the same level of indent
        # we delete the prev. command and append the new one to the base string
        elif cur_ind_level == prev_ind_level:
            if len(cfg_string) > 1:
                cfg_string.pop()
            # removing (if any) `customer xxx create` or `create` at the end of the line
            # since it was previously printed out
            if cfg_string:
                cfg_string[-1] = re.sub(r'\scustomer\s\d+\screate$|\screate$', '', cfg_string[-1])

            cfg_string.append(stripped_line)
        else:
            if cfg_string:
                cfg_string[-1] = re.sub(r'\scustomer\s\d+\screate$|\screate$', '', cfg_string[-1])
            cfg_string.append(stripped_line)

        prev_ind_level = cur_ind_level

        ## if we have a next line go check it's indent value
        if i < len(clean_cfg) - 1:
            next_ind_level = len(
                clean_cfg[i + 1]) - len(clean_cfg[i + 1].lstrip())
            # if a next ind level is depper (>) then we can continue accumulation
            # of the commands
            if next_ind_level > prev_ind_level:
                continue
            # if the next level is the same or lower, we must save a line
            else:
                rootified_cfg += ' '.join(cfg_string) + '\n'
        else:
            # otherwise we have a last line here, so print it
            rootified_cfg += ' '.join(cfg_string) + '\n'

    return rootified_cfg


###############
#### FLASK ####
###############


if Blueprint is not None:
    sros_rootifier_bp = Blueprint('sros_rootifier', __name__, template_folder='templates', static_folder='static',
                                  static_url_path='/sros_rootifier/static')


    @sros_rootifier_bp.route('/', methods=['GET', 'POST'])
    def sros_rootifier():
        if request.method == 'GET':
            return render_template('sros_rootifier.html')

        # handle POST method from JQuery (will be filled later)
        elif request.method == 'POST':
            result = {'output_data': '',
                      'error': ''}
            input_cfg = request.form['cfg']

            clean_cfg = rm_insignificant_lines(input_cfg)
            result['output_data'] = rootify(clean_cfg)
            return jsonify(result)


import os
import shutil

 
def clean_config(lines):
    """
    Remove all lines before the first real configuration block.
    This skips:
    - Everything before 'configure' if it's immediately followed by a header block.
    - Or everything before the header block itself.
    """
    start_index = 0
    for i in range(len(lines)):
        line = lines[i].strip().replace('\\"', '"')
        next_1 = lines[i + 1].strip().replace('\\"', '"') if i + 1 < len(lines) else ""
        next_2 = lines[i + 2].strip().replace('\\"', '"') if i + 2 < len(lines) else ""
        next_3 = lines[i + 3].strip().replace('\\"', '"') if i + 3 < len(lines) else ""

        # Case 1: header block
        if i + 2 < len(lines):
            if (line == "#--------------------------------------------------" and
                next_1 == 'echo "System Configuration"' and
                next_2 == "#--------------------------------------------------"):
                start_index = i + 3
                break

        # Case 2: 'configure' followed by header block
        if (line == "configure" and
            i + 3 < len(lines) and
            next_1 == "#--------------------------------------------------" and
            next_2 == 'echo "System Configuration"' and
            next_3 == "#--------------------------------------------------"):
            start_index = i + 4
            break

        # Fallback: just 'configure'
        if line == "configure":
            start_index = i
            break

    return lines[start_index:]


def _flat_output_path(input_path, output_dir):
    file_name = os.path.basename(input_path)
    base, ext = os.path.splitext(file_name)
    output_name = f"{base}_flat{ext or '.cfg'}"
    return os.path.join(output_dir, output_name)


def rootify_file(input_path, output_dir):
    os.makedirs(output_dir, exist_ok=True)

    with open(input_path, "r") as f:
        original_lines = f.readlines()

    cleaned_lines = clean_config(original_lines)
    rootified = rootify(cleaned_lines)
    output_path = _flat_output_path(input_path, output_dir)

    with open(output_path, "w") as f:
        for line in rootified.splitlines():
            if line.strip():
                f.write(f"{line.lstrip('/')}\n")

    return {
        "input_path": input_path,
        "output_path": output_path,
    }


def rootify_path(input_path, output_dir):
    if os.path.isdir(input_path):
        results = []
        for name in sorted(os.listdir(input_path)):
            full_path = os.path.join(input_path, name)
            if os.path.isfile(full_path):
                results.append(rootify_file(full_path, output_dir))
        return results
    return [rootify_file(input_path, output_dir)]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Rootify SR OS configs into flat format.")
    parser.add_argument(
        "input_path",
        nargs="?",
        default="bng_configs",
        help="Input file or directory containing original configs.",
    )
    parser.add_argument(
        "output_dir",
        nargs="?",
        default="bng_configs_flat",
        help="Output directory for flat configs.",
    )
    args = parser.parse_args()

    results = rootify_path(args.input_path, args.output_dir)
    for item in results:
        print(f'Finished rootifying {item["input_path"]} -> {item["output_path"]}')
