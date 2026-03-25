import re
import os 

from flask import Blueprint, jsonify, render_template, request


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
            cfg_string.pop()
            prev_ind_level -= 4
            continue

        # calc current indent
        cur_ind_level = len(line) - len(line.lstrip())
        # append a command if it is on a next level of indent
        if cur_ind_level > prev_ind_level:
            cfg_string.append(line.strip())
        # if a command on the same level of indent
        # we delete the prev. command and append the new one to the base string
        elif cur_ind_level == prev_ind_level:
            cfg_string.pop()
            # removing (if any) `customer xxx create` or `create` at the end of the line
            # since it was previously printed out
            cfg_string[-1] = re.sub(r'\scustomer\s\d+\screate$|\screate$', '', cfg_string[-1])

            cfg_string.append(line.strip())

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
        line = lines[i].strip()

        # Case 1: header block
        if i + 2 < len(lines):
            if (lines[i].strip() == "#--------------------------------------------------" and
                lines[i + 1].strip() == 'echo "System Configuration"' and
                lines[i + 2].strip() == "#--------------------------------------------------"):
                start_index = i + 3
                break

        # Case 2: 'configure' followed by header block
        if (line == "configure" and
            i + 3 < len(lines) and
            lines[i + 1].strip() == "#--------------------------------------------------" and
            lines[i + 2].strip() == 'echo "System Configuration"' and
            lines[i + 3].strip() == "#--------------------------------------------------"):
            start_index = i + 4
            break

        # Fallback: just 'configure'
        if line == "configure":
            start_index = i
            break

    return lines[start_index:]


if __name__ == "__main__":
    input_dir = "bng_configs"
    output_dir = "bng_configs_flat"

    # Ensure output directory exists and is empty
    if os.path.exists(output_dir):
        for f in os.listdir(output_dir):
            os.remove(os.path.join(output_dir, f))
    else:
        os.makedirs(output_dir)

    # Loop through all input files
    files = [f for f in os.listdir(input_dir) if os.path.isfile(os.path.join(input_dir, f))]

    for file in files:
        print(file)
        input_path = os.path.join(input_dir, file)
        base, ext = os.path.splitext(file)
        if file.endswith(".cfg"):
            output_filename = file[:-4] + "_flat.cfg"
        else:
            output_filename = file + "_flat"

        output_path = os.path.join(output_dir, output_filename)

        with open(input_path, 'r') as f:
            original_lines = f.readlines()

        # Clean and overwrite original
        cleaned_lines = clean_config(original_lines)
        with open(input_path, 'w') as f:
            f.writelines(cleaned_lines)

        # Apply rootify and write to output
        rootified = rootify(cleaned_lines)
        rootified_lines = rootified.split("\n")
        with open(output_path, 'w') as f:
            f.writelines(f"{line.lstrip('/')}\n" for line in rootified_lines if line.strip())

        print(f"Finished rootifying {file} → {output_path}")
