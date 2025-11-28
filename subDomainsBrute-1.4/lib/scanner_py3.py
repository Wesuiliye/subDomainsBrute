# -*- encoding: utf-8 -*-

import platform
import re
import time
import asyncio
import aiodns
from asyncio import PriorityQueue
from .common import is_intranet
import random


if platform.system() == 'Windows':
    if hasattr(asyncio, 'WindowsSelectorEventLoopPolicy'):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


class SubNameBrute(object):
    def __init__(self, *params):
        '''
        :param params:
            domain: 目标域名（例如 example.com）。
            options: 包含所有命令行选项的对象（可能包含端口、超时时间等）。
            process_num: 当前子进程的编号（从 0 开始）。这个编号非常重要，子进程可以利用它来实现任务分配（例如，进程 0 处理第 0、4、8... 个任务，进程 1 处理第 1、5、9... 个任务）。
            dns_servers: 用于解析的 DNS 服务器列表。
            next_subs: 返回子域名前缀列表
            scan_count, found_count: 共享内存计数器（如 multiprocessing.Value），用于在所有子进程之间同步统计信息（如 “已扫描总数”、“已发现总数”）。
            queue_size_array: 共享数组，用于跟踪队列大小或其他状态。
            tmp_dir: 临时目录路径，用于子进程存储临时文件。
        '''
        self.domain, self.options, self.process_num, self.dns_servers, self.next_subs, \
            self.scan_count, self.found_count, self.queue_size_array, tmp_dir = params
        self.dns_count = len(self.dns_servers)
        self.scan_count_local = 0
        self.found_count_local = 0

        self.resolvers = [aiodns.DNSResolver(tries=1) for _ in range(self.options.threads)]

        self.queue = PriorityQueue()
        self.ip_dict = {}
        self.found_subs = set()
        self.timeout_subs = {}
        self.count_time = time.time()
        self.outfile = open('%s/%s_part_%s.txt' % (tmp_dir, self.domain, self.process_num), 'w')
        self.normal_names_set = set()
        self.lock = asyncio.Lock()
        self.loop = None
        self.threads_status = ['1'] * self.options.threads
    async def load_sub_names(self):
        normal_lines = []   # 存储 “普通” 子域名（不包含任何占位符）。
        wildcard_lines = [] # 存储 “wildcard” 模式的子域名（包含 {...} 占位符）。
        wildcard_set = set() # 一个集合，用于存储转换后的、唯一的正则表达式字符串，防止重复。
        regex_list = [] # 存储由 wildcard 模式转换而来的正则表达式字符串。
        lines = set() # 一个集合，用于快速检测并去除输入文件中的重复行。

        # 读取文件阶段
        with open(self.options.file) as inFile:
            #for line in inFile.readlines():
            for line in inFile:  # 直接迭代文件对象，它是一个行迭代器
                sub = line.strip()
                if not sub or sub in lines:
                    continue
                lines.add(sub)

                #检查当前子域名中是否包含 { 字符，用于判断是否为 wildcard 模式。
                brace_count = sub.count('{')
                if brace_count > 0:
                    # 将原始的 wildcard 模式（如 img{num}）及其 { 的数量作为元组存入 wildcard_lines。
                    # brace_count 可能用于后续排序，让更复杂的模式（包含更多占位符）优先处理。
                    wildcard_lines.append((brace_count, sub))
                    sub = sub.replace('{alphnum}', '[a-z0-9]')
                    sub = sub.replace('{alpha}', '[a-z]')
                    sub = sub.replace('{num}', '[0-9]')
                    if sub not in wildcard_set:
                        wildcard_set.add(sub)
                        # 将这个正则表达式模式添加到 regex_list。^ 和 $ 确保了整个字符串必须完全匹配该模式。
                        regex_list.append('^' + sub + '$')
                else:
                    normal_lines.append(sub)
                    self.normal_names_set.add(sub)

        #去重
        if regex_list:
            # 将所有 wildcard 转换来的正则表达式用 | (或) 连接起来，形成一个巨大的正则表达式。
            pattern = '|'.join(regex_list)
            # 编译这个正则表达式，以提高匹配效率。
            _regex = re.compile(pattern)
            '''
            for line in normal_lines:
                #  如果一个普通子域名能够匹配任何一个 wildcard 模式。
                # 例如，普通子域名 img1 能够匹配 wildcard 模式 img[0-9]。
                if _regex.search(line):
                    #那么这个普通子域名就被从 normal_lines 列表中移除。
                    # 因为爆破 img[0-9] 已经包含了 img1 这个情况，再单独爆破 img1 就是重复劳动了。
                    normal_lines.remove(line)
            '''
            # 使用列表推导式创建一个新的、不包含冗余项的列表
            normal_lines = [line for line in normal_lines if not _regex.search(line)]

        # 分发普通子域名任务
        # 进程 0 (process_num=0) 会处理索引为 0, 6, 12, 18... 的任务。
        for _ in normal_lines[self.process_num::self.options.process]:
            # 将一个包含子域名 _ 的任务，以优先级 0 放入到 self.queue 这个优先级队列中
            await self.queue.put((0, _))    # priority set to 0
        # 分发 Wildcard 模式任务
        for _ in wildcard_lines[self.process_num::self.options.process]:
            await self.queue.put(_)


    async def scan(self, j):
        self.resolvers[j].nameservers = [self.dns_servers[j % self.dns_count]]
        if self.dns_count > 1:
            while True:
                s = random.choice(self.resolvers)
                if s != self.dns_servers[j % self.dns_count]:
                    self.resolvers[j].nameservers.append(s)
                    break
        while True:
            try:
                if time.time() - self.count_time > 1.0:
                    async with self.lock:
                        self.scan_count.value += self.scan_count_local
                        self.scan_count_local = 0
                        self.queue_size_array[self.process_num] = self.queue.qsize()
                        if self.found_count_local:
                            self.found_count.value += self.found_count_local
                            self.found_count_local = 0
                        self.count_time = time.time()

                try:
                    brace_count, sub = self.queue.get_nowait()
                    self.threads_status[j] = '1'
                except asyncio.queues.QueueEmpty as e:
                    self.threads_status[j] = '0'
                    await asyncio.sleep(0.5)
                    if '1' not in self.threads_status:
                        break
                    else:
                        continue

                if brace_count > 0:
                    brace_count -= 1
                    if sub.find('{next_sub}') >= 0:
                        for _ in self.next_subs:
                            await self.queue.put((0, sub.replace('{next_sub}', _)))
                    if sub.find('{alphnum}') >= 0:
                        for _ in 'abcdefghijklmnopqrstuvwxyz0123456789':
                            await self.queue.put((brace_count, sub.replace('{alphnum}', _, 1)))
                    elif sub.find('{alpha}') >= 0:
                        for _ in 'abcdefghijklmnopqrstuvwxyz':
                            await self.queue.put((brace_count, sub.replace('{alpha}', _, 1)))
                    elif sub.find('{num}') >= 0:
                        for _ in '0123456789':
                            await self.queue.put((brace_count, sub.replace('{num}', _, 1)))
                    continue
            except Exception as e:
                import traceback
                print(traceback.format_exc())
                break

            try:

                if sub in self.found_subs:
                    continue

                self.scan_count_local += 1
                cur_domain = sub + '.' + self.domain
                # print('Query %s' % cur_domain)
                answers = await self.resolvers[j].query(cur_domain, 'A')

                if answers:
                    self.found_subs.add(sub)
                    ips = ', '.join(sorted([answer.host for answer in answers]))
                    if ips in ['1.1.1.1', '127.0.0.1', '0.0.0.0', '0.0.0.1']:
                        continue
                    if self.options.i and is_intranet(answers[0].host):
                        continue

                    try:
                        self.scan_count_local += 1
                        answers = await self.resolvers[j].query(cur_domain, 'CNAME')
                        cname = answers[0].target.to_unicode().rstrip('.')
                        if cname.endswith(self.domain) and cname not in self.found_subs:
                            cname_sub = cname[:len(cname) - len(self.domain) - 1]    # new sub
                            if cname_sub not in self.normal_names_set:
                                self.found_subs.add(cname)
                                await self.queue.put((0, cname_sub))
                    except Exception as e:
                        pass

                    first_level_sub = sub.split('.')[-1]
                    max_found = 20

                    if self.options.w:
                        first_level_sub = ''
                        max_found = 3

                    if (first_level_sub, ips) not in self.ip_dict:
                        self.ip_dict[(first_level_sub, ips)] = 1
                    else:
                        self.ip_dict[(first_level_sub, ips)] += 1
                        if self.ip_dict[(first_level_sub, ips)] > max_found:
                            continue

                    self.found_count_local += 1

                    self.outfile.write(cur_domain.ljust(30) + '\t' + ips + '\n')
                    self.outfile.flush()
                    try:
                        self.scan_count_local += 1
                        await self.resolvers[j].query('lijiejie-test-not-existed.' + cur_domain, 'A')
                    except aiodns.error.DNSError as e:
                        if e.args[0] in [4]:
                            if self.queue.qsize() < 50000:
                                for _ in self.next_subs:
                                    await self.queue.put((0, _ + '.' + sub))
                            else:
                                await self.queue.put((1, '{next_sub}.' + sub))
                    except Exception as e:
                        pass

            except aiodns.error.DNSError as e:
                if e.args[0] in [1, 4]:
                    pass
                elif e.args[0] in [11, 12]:   # 12 timeout   # (11, 'Could not contact DNS servers')
                    # print('timed out sub %s' % sub)
                    self.timeout_subs[sub] = self.timeout_subs.get(sub, 0) + 1
                    if self.timeout_subs[sub] <= 1:
                        await self.queue.put((0, sub))  # Retry
                else:
                    print(e)
            except asyncio.TimeoutError as e:
                pass
            except Exception as e:
                import traceback
                traceback.print_exc()
                with open('errors.log', 'a') as errFile:
                    errFile.write('[%s] %s\n' % (type(e), str(e)))


    async def async_run(self):
        await self.load_sub_names()
        # t0 = time.time()
        # await self.load_sub_names()
        # t1 = time.time()
        # print(f"[DEBUG Process {self.process_num}] load_sub_names took {t1 - t0:.3f} seconds")
        # 在这里测试好久，当进程是6的时候，执行到这里已经过去了十七秒左右，排查了很多，也没用找到问题
        # AI说是程序启动、进程管理和环境初始化的总开销本身就要这么久了。
        # 原因应该找到了，应该是 self.resolvers = [aiodns.DNSResolver(tries=1) for _ in range(self.options.threads)] 这里的aiodns函数问题，本身启动忙
        # 在1.5版本中，用的是self.resolvers = [dns.asyncresolver.Resolver(configure=False) for _ in range(self.options.threads)]
        tasks = [self.scan(i) for i in range(self.options.threads)]
        await asyncio.gather(*tasks)

    def run(self):
        self.loop = asyncio.get_event_loop()
        #设置当前线程的事件循环
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self.async_run())
