# common functions

import sys
import os
from .consle_width import getTerminalSize

#获取终端（控制台）的宽度，并将其减去 2
console_width = getTerminalSize()[0] - 2


def is_intranet(ip):
    ret = ip.split('.')
    if len(ret) != 4:
        return True
    if ret[0] == '10':
        return True
    if ret[0] == '172' and 16 <= int(ret[1]) <= 31:
        return True
    if ret[0] == '192' and ret[1] == '168':
        return True
    return False


def print_msg(msg=None, left_align=True, line_feed=False):
    '''
    msg: 要打印的消息字符串。默认为 None。
    left_align: 一个布尔值，用于控制对齐方式。True 表示左对齐（默认），False 表示右对齐。
    line_feed: 一个布尔值，用于控制是否在消息末尾添加换行符。False 表示不添加（默认），True 表示添加。
    '''
    if left_align:
        sys.stdout.write('\r' + msg + ' ' * (console_width - len(msg)))
    else:  # right align
        sys.stdout.write('\r' + ' ' * (console_width - len(msg)) + msg)
    if line_feed:
        sys.stdout.write('\n')
    #强制将缓冲区中的所有内容立即输出到屏幕上。
    sys.stdout.flush()


def load_next_sub(options):
    next_subs = []
    _file = 'dict/next_sub_full.txt' if options.full_scan else 'dict/next_sub.txt'
    with open(_file, encoding='utf-8') as f:
        for line in f:
            sub = line.strip()
            if sub and sub not in next_subs:  # 空行或已存在就跳过
                tmp_set = {sub}

                while tmp_set:
                    item = tmp_set.pop()
                    if item.find('{alphnum}') >= 0:
                        for _letter in 'abcdefghijklmnopqrstuvwxyz0123456789':
                            tmp_set.add(item.replace('{alphnum}', _letter, 1))
                    elif item.find('{alpha}') >= 0:
                        for _letter in 'abcdefghijklmnopqrstuvwxyz':
                            tmp_set.add(item.replace('{alpha}', _letter, 1))
                    elif item.find('{num}') >= 0:
                        for _letter in '0123456789':
                            tmp_set.add(item.replace('{num}', _letter, 1))
                    elif item not in next_subs:
                        next_subs.append(item)
    return next_subs


def get_out_file_name(target, options):
    if options.output:
        outfile = options.output
    else:
        _name = os.path.basename(options.file).replace('subnames', '')
        if _name != '.txt':
            _name = '_' + _name
        outfile = target + _name
    return outfile


def user_abort(sig, frame):
    exit(-1)


# check file existence
def get_sub_file_path(options):
    if options.full_scan and options.file == 'subnames.txt':
        sub_file_path = 'dict/subnames_full.txt'
    else:
        if os.path.exists(options.file):
            sub_file_path = options.file
        elif os.path.exists('dict/%s' % options.file):
            sub_file_path = 'dict/%s' % options.file
        else:
            print_msg('[ERROR] Names file not found: %s' % options.file)
            exit(-1)
    return sub_file_path