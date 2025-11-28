#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
    subDomainsBrute 1.4
    A simple and fast sub domains brute tool for pentesters
    my[at]lijiejie.com (http://www.lijiejie.com)
"""

import sys
import multiprocessing


import warnings
warnings.simplefilter("ignore", category=UserWarning)

import time
import signal
import os
import glob
from lib.cmdline import parse_args

# py版本
if sys.version_info.major >= 3 and sys.version_info.minor >= 5:
    from lib.scanner_py3 import SubNameBrute
    from lib.common_py3 import load_dns_servers, load_next_sub, print_msg, get_out_file_name, \
        user_abort, wildcard_test, get_sub_file_path
else:
    from lib.scanner_py2 import SubNameBrute
    from lib.common_py2 import load_dns_servers, load_next_sub, print_msg, get_out_file_name, \
        user_abort, wildcard_test, get_sub_file_path


def run_process(*params):
    #print(f"[{params[2]}] Process started at {time.time()}")  # params[2] 是 process_num
    #为当前进程注册一个信号处理器，使得当进程接收到 SIGINT 信号时，会自动调用 user_abort 这个函数。
    signal.signal(signal.SIGINT, user_abort)
    s = SubNameBrute(*params)
    s.run()



if __name__ == '__main__':
    options, args = parse_args()
    print('''SubDomainsBrute v1.4  https://github.com/lijiejie/subDomainsBrute''')
    # make tmp dirs
    tmp_dir = 'tmp/%s_%s' % (args[0], int(time.time()))
    if not os.path.exists(tmp_dir):
        os.makedirs(tmp_dir)

    # 关键步骤：在Windows上打包时，必须调用此函数
    # 它在非Windows系统或非打包环境下会安全地什么都不做
    multiprocessing.freeze_support()
    # DNS测试是否正常。
    dns_servers = load_dns_servers()
    # 返回子域名前缀列表
    next_subs = load_next_sub(options)
    # 创建 共享内存整数变量，用来实现 进程安全的计数器。
    # 全局统计扫描进度和命中数量 的线程/进程安全计数器。
    scan_count = multiprocessing.Value('i', 0)
    found_count = multiprocessing.Value('i', 0)
    queue_size_array = multiprocessing.Array('i', options.process)

    try:
        print('[+] Run wildcard test')
        if not options.w:
            # 泛解析检测
            domain = wildcard_test(args[0], dns_servers)
        else:
            domain = args[0]
        options.file = get_sub_file_path(options)
        print('[+] Start %s scan process' % options.process)
        print('[+] Please wait while scanning ... \n')

        start_time = time.time()
        all_process = []
        #根据用户指定的进程数，创建并启动多个子进程，用于并行执行一个名为 run_process 的任务。
        for process_num in range(options.process):
            #args=(...)：这是一个元组，包含了要传递给 run_process 函数的所有参数
            p = multiprocessing.Process(target=run_process,
                                        args=(domain, options, process_num, dns_servers, next_subs,
                                              scan_count, found_count, queue_size_array, tmp_dir)
                                        )
            all_process.append(p)
            p.start()

        char_set = ['\\', '|', '/', '-']
        count = 0
        while all_process:
            for p in all_process:
                if not p.is_alive():
                    all_process.remove(p)
            groups_count = 0
            for c in queue_size_array:
                groups_count += c
            msg = '[%s] %s found, %s scanned in %.1f seconds, %s groups left' % (
                char_set[count % 4], found_count.value, scan_count.value, time.time() - start_time, groups_count)
            print_msg(msg)
            count += 1
            time.sleep(0.3)
    except KeyboardInterrupt as e:
        print('[ERROR] User aborted the scan!')
        for p in all_process:
            p.terminate()
    except Exception as e:
        import traceback
        traceback.print_exc()
        print('[ERROR] %s' % str(e))

    out_file_name = get_out_file_name(domain, options)
    all_domains = set()
    domain_count = 0
    with open(out_file_name, 'w') as f:
        for _file in glob.glob(tmp_dir + '/*.txt'):
            with open(_file, 'r') as tmp_f:
                for domain in tmp_f:
                    if domain not in all_domains:
                        domain_count += 1
                        all_domains.add(domain)       # cname query can result in duplicated domains
                        f.write(domain)

    msg = 'All Done. %s found, %s scanned in %.1f seconds.' % (
        domain_count, scan_count.value, time.time() - start_time)
    print_msg(msg, line_feed=True)
    print('Output file is %s' % out_file_name)
