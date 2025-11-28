# -*- encoding: utf-8 -*-

import re
import time
import asyncio
import random
import socket
import platform
import sys
import os
import dns.asyncresolver
from asyncio import PriorityQueue
from .common import is_intranet
from async_timeout import timeout


if platform.system() == 'Windows':
    try:
        def _call_connection_lost(self, exc):
            try:
                self._protocol.connection_lost(exc)
            finally:
                if hasattr(self._sock, 'shutdown'):
                    try:
                        if self._sock.fileno() != -1:
                            self._sock.shutdown(socket.SHUT_RDWR)
                    except Exception as e:
                        pass
                self._sock.close()
                self._sock = None
                server = self._server
                if server is not None:
                    server._detach()
                    self._server = None

        asyncio.proactor_events._ProactorBasePipeTransport._call_connection_lost = _call_connection_lost
    except Exception as e:
        pass

if sys.version_info.major == 3 and sys.version_info.minor == 6:
    # I'll do this first, mute stderr
    # Since python3.6 throws exception from inner function that can not be captured by except ...
    sys.stderr = open(os.devnull, 'w')


class SubNameBrute(object):
    def __init__(self, *params):
        self.domain, self.options, self.process_num, self.dns_servers, self.next_subs, \
            self.scan_count, self.found_count, self.queue_size_array, tmp_dir = params
        self.dns_count = len(self.dns_servers)
        self.scan_count_local = 0
        self.found_count_local = 0
        #configure=False， 不要使用系统默认的 DNS 配置。
        self.resolvers = [dns.asyncresolver.Resolver(configure=False) for _ in range(self.options.threads)]
        for r in self.resolvers:
            r.lifetime = 6.0 # 整个 DNS 查询过程的最大允许时间
            r.timeout = 10.0 # 与单个 DNS 服务器通信的超时时间
        self.queue = PriorityQueue()
        self.ip_dict = {}
        self.found_subs = set()
        self.cert_subs = set()
        self.timeout_subs = {}
        self.no_server_subs = {}
        self.count_time = time.time()
        self.outfile = open('%s/%s_part_%s.txt' % (tmp_dir, self.domain, self.process_num), 'w')
        self.normal_names_set = set()
        self.lock = asyncio.Lock()
        self.threads_status = ['1'] * self.options.threads

    async def load_sub_names(self):
        normal_lines = []
        wildcard_lines = []
        wildcard_set = set()
        regex_list = []
        lines = set()
        with open(self.options.file) as inFile:
            for line in inFile.readlines():
                sub = line.strip()
                if not sub or sub in lines:
                    continue
                lines.add(sub)

                brace_count = sub.count('{')
                if brace_count > 0:
                    wildcard_lines.append((brace_count, sub))
                    sub = sub.replace('{alphnum}', '[a-z0-9]')
                    sub = sub.replace('{alpha}', '[a-z]')
                    sub = sub.replace('{num}', '[0-9]')
                    if sub not in wildcard_set:
                        wildcard_set.add(sub)
                        regex_list.append('^' + sub + '$')
                else:
                    normal_lines.append(sub)
                    self.normal_names_set.add(sub)

        if regex_list:
            pattern = '|'.join(regex_list)
            _regex = re.compile(pattern)
            for line in normal_lines:
                if _regex.search(line):
                    normal_lines.remove(line)

        for _ in normal_lines[self.process_num::self.options.process]:
            await self.queue.put((0, _))    # priority set to 0
        for _ in wildcard_lines[self.process_num::self.options.process]:
            await self.queue.put(_)

    async def update_counter(self):
        while True:
            if '1' not in self.threads_status:
                return
            self.scan_count.value += self.scan_count_local
            self.scan_count_local = 0
            self.queue_size_array[self.process_num] = self.queue.qsize()
            if self.found_count_local:
                self.found_count.value += self.found_count_local
                self.found_count_local = 0
            self.count_time = time.time()
            await asyncio.sleep(0.5)

    async def check_https_alt_names(self, domain):
        '''
        通过检查目标域名的 HTTPS 证书，从其 “主题备用名称”（Subject Alternative Name, SAN）字段中发现新的子域名。
        :param domain:
        :return:
        '''
        try:
            reader, _ = await asyncio.open_connection(
                host=domain,
                port=443,
                ssl=True,
                server_hostname=domain,
            )
            # _transport 属性，它代表了底层的传输协议（在这里是 TLS 传输）。
            #get_extra_info('peercert'): 这是获取对等方（服务器）证书的关键方法。它返回一个包含证书信息的字典。
            #['subjectAltName']: 从证书信息字典中提取 subjectAltName 字段。这个字段是一个列表，包含了该证书所保护的所有域名（包括主域名和备用域名）。
            for item in reader._transport.get_extra_info('peercert')['subjectAltName']:
                if item[0].upper() == 'DNS':
                    name = item[1].lower()
                    if name.endswith(self.domain):
                        #从完整的域名 name 中提取出子域名部分。
                        sub = name[:len(name) - len(self.domain) - 1]    # new sub
                        sub = sub.replace('*', '')
                        sub = sub.strip('.')
                        #过滤掉无效或重复的子域名：
                        if sub and sub not in self.found_subs and \
                                sub not in self.normal_names_set and sub not in self.cert_subs:
                            self.cert_subs.add(sub)
                            await self.queue.put((0, sub))
        except Exception as e:
            pass

    # 执行一个带有严格超时控制的 DNS 查询。
    async def do_query(self, j, cur_domain):
        # 如果内部的代码块在 10.2 秒内成功完成，那么一切正常。
        # 如果超过了 10.2 秒代码块仍未完成，timeout 上下文管理器会抛出一个异常（通常是 asyncio.TimeoutError），从而中断代码的执行。
        async with timeout(10.2):
            return await self.resolvers[j].resolve(cur_domain, 'A')
        # asyncio.wait_for did not work properly
        # hang up in some cases, we use async_timeout instead
        # return await asyncio.wait_for(self.resolvers[j].resolve(cur_domain, 'A', lifetime=8), timeout=9)

    async def scan(self, j):
        #为当前扫描任务 j 分配了一个专属的 DNS 解析器，并为其设置了首选的 DNS 服务器
        self.resolvers[j].nameservers = [self.dns_servers[j % self.dns_count]]
        # 为当前 DNS 解析器添加一个备用 DNS 服务器
        if self.dns_count > 1:
            while True:
                s = random.choice(self.dns_servers)
                if s != self.dns_servers[j % self.dns_count]:
                    self.resolvers[j].nameservers.append(s)
                    break
        empty_counter = 0
        while True:
            try:
                # 获取待扫描的子域名任务
                # brace_count优先级，sub子域名
                brace_count, sub = self.queue.get_nowait()
                # 协程状态，如果成功获取到任务，说明当前这个协程（任务 j）正在忙碌地处理一个任务。
                self.threads_status[j] = '1'
                empty_counter = 0
            #当 get_nowait() 发现队列为空时，就会进入这个 except 块。
            except asyncio.queues.QueueEmpty as e:
                empty_counter += 1
                # 这个条件判断当前协程是否已经连续 10 次都没有获取到任务了。
                if empty_counter > 10:
                    self.threads_status[j] = '0'
                if '1' not in self.threads_status:
                    break
                else:
                    await asyncio.sleep(0.1)
                    continue

            # 生成子域名前缀列表
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

            try:
                # 避免对同一个子域名进行重复的 DNS 查询。
                if sub in self.found_subs:
                    continue

                self.scan_count_local += 1
                cur_domain = sub + '.' + self.domain
                # DNS 查询操作,有超时操作。
                answers = await self.do_query(j, cur_domain)
                if answers:
                    self.found_subs.add(sub)
                    ips = ', '.join(sorted([answer.address for answer in answers]))
                    invalid_ip_found = False
                    # 结果过滤
                    for answer in answers:
                        if answer.address in ['1.1.1.1', '127.0.0.1', '0.0.0.0', '0.0.0.1']:
                            invalid_ip_found = True
                    if invalid_ip_found:
                        continue
                    if self.options.i and is_intranet(answers[0].host):
                        continue

                    try:
                        #answers.canonical_name: 对于某些 DNS 查询（特别是当请求的域名是一个 CNAME 记录时），解析器会返回其规范名称（Canonical Name），也就是它所指向的另一个域名。
                        cname = str(answers.canonical_name)[:-1]
                        # 过滤出有价值的 CNAME 记录。
                        if cname != cur_domain and cname.endswith(self.domain):
                            # 从 CNAME 域名中提取出新的子域名。
                            cname_sub = cname[:len(cname) - len(self.domain) - 1]    # new sub
                            # 确保我们发现的是全新的、之前未被扫描过且不在常规字典中的子域名
                            if cname_sub not in self.found_subs and cname_sub not in self.normal_names_set:
                                # 作为一个新任务放入扫描队列 self.queue 中。
                                await self.queue.put((0, cname_sub))
                    except Exception as e:
                        pass
                    '''
                        这里是这个意思
                        假设目标域名是 api.example.com，泛域名解析配置为 *.api.example.com → 3.3.3.3，你扫描的子域名是：
                        a.api.example.com → sub = 'a.api'（子域名前缀是 a.api）；
                        b.api.example.com → sub = 'b.api'；
                        c.api.example.com → sub = 'c.api'；
                        ...
                        x.api.example.com → sub = 'x.api'。
                        此时 first_level_sub 的计算的：
                        a.api.split('.') → ['a', 'api'] → 取最后一个元素 → first_level_sub = 'api'；
                        b.api.split('.') → ['b', 'api'] → 取最后一个元素 → first_level_sub = 'api'；
                        所有 *.api 前缀的子域名，first_level_sub 都是 'api'。
                        IP 组合都是 '3.3.3.3'，所以 (first_level_sub, ips) 组合永远是 ('api', '3.3.3.3')：
                        第 1 个（a.api）：计数 = 1 → 输出；
                        第 2 个（b.api）：计数 = 2 → 输出；
                        ...
                        第 20 个（t.api）：计数 = 20 → 输出；
                        第 21 个（u.api）：计数 = 21 → 超过 max_found=20 → 击中阈值，跳过输出！
                    '''
                    first_level_sub = sub.split('.')[-1]
                    max_found = 20

                    #启用更严格的泛域名检测模式。
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

                    #是否跳过HTTPS
                    if not self.options.no_cert_check:
                        async with timeout(10.0):
                            await self.check_https_alt_names(cur_domain)

                    try:
                        self.scan_count_local += 1
                        # 请求一个失败的域名
                        await self.do_query(j, 'zen-me-ke-neng-cun-zai-de-yu-ming-a.' + cur_domain)
                    #这个异常表示域名不存在
                    except dns.resolver.NXDOMAIN as e:
                        '''
                        当你查询 a.b.example.com 并且得到 NXDOMAIN 时，这通常意味着 b.example.com 这个域名本身是存在的，只是 a 这个前缀不存在。
                        如果 b.example.com 根本不存在，DNS 服务器通常会返回 NXDOMAIN 给 b.example.com，而不是 a.b.example.com。
                        收到 NXDOMAIN 错误，说明 cur_domain（即 b.example.com）是一个有效的、可以接受子域名的域名。
                        因此，我们可以在它的基础上进一步爆破更深层次的子域名。
                                            '''
                        if self.queue.qsize() < 20000:
                            for _ in self.next_subs:
                                await self.queue.put((0, _ + '.' + sub))
                        else:
                            await self.queue.put((1, '{next_sub}.' + sub))
                    except Exception as e:
                        continue

            #dns.resolver.NXDOMAIN: 表示查询的域名不存在（Non-eXistent Domain）。
            #dns.resolver.NoAnswer: 表示 DNS 服务器对该查询没有返回任何记录（例如，查询一个存在的域名的 MX 记录，但该域名没有配置 MX 记录）。
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as e:
                pass
            #没有可用的 DNS 服务器能够响应当前的查询
            except dns.resolver.NoNameservers as e:
                #记录每个子域名因为此错误而重试的次数。
                self.no_server_subs[sub] = self.no_server_subs.get(sub, 0) + 1
                #如果重试次数不超过 3 次，则将该子域名重新放入队列尾部，等待再次尝试。
                if self.no_server_subs[sub] <= 3:
                    await self.queue.put((0, sub))    # Retry again
            #dns.exception.Timeout: 表示在查询过程中发生了超时。
            #dns.resolver.LifetimeTimeout: 表示整个查询的总生命周期超时（即尝试了所有可用的 DNS 服务器后，总耗时超过了设定的 lifetime）。
            except (dns.exception.Timeout, dns.resolver.LifetimeTimeout) as e:
                self.timeout_subs[sub] = self.timeout_subs.get(sub, 0) + 1
                if self.timeout_subs[sub] <= 3:
                    await self.queue.put((0, sub))    # Retry again
            except Exception as e:
                if str(type(e)).find('asyncio.exceptions.TimeoutError') < 0:
                    with open('errors.log', 'a') as errFile:
                        errFile.write('[%s] %s\n' % (type(e), str(e)))

    async def async_run(self):
        await self.load_sub_names()
        # t0 = time.time()
        # await self.load_sub_names()
        # t1 = time.time()
        # print(f"[DEBUG Process {self.process_num}] load_sub_names took {t1 - t0:.3f} seconds")
        tasks = [self.scan(i) for i in range(self.options.threads)]
        tasks.insert(0, self.update_counter())
        await asyncio.gather(*tasks)

    def run(self):
        loop = asyncio.get_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self.async_run())
