# common functions

import sys
import os
import asyncio
import aiodns
from .common import print_msg, load_next_sub, get_out_file_name, user_abort, get_sub_file_path


async def test_server_python3(server, dns_servers):
    '''
    测试一个 DNS 服务器是否能正常工作，还测试了它是否会进行 “DNS 投毒” 或返回虚假的 IP 地址。
    :param server:  DNS 服务器地址列表
    :param dns_servers: 存放结果
    :return:
    '''
    #设置超时时间
    timeout = 3
    #创建 DNS 解析器
    resolver = aiodns.DNSResolver(timeout=timeout, tries=1)# tries=1 表示不重试
    try:
        # 设置待测试的 DNS 服务器
        resolver.nameservers = [server]
        # 代码检查返回的 IP 地址是否正好是 180.76.76.76。
        # 如果不是，它会主动 raise Exception，这意味着该 DNS 服务器返回了错误或被篡改的结果，测试失败。
        answers = await resolver.query('public-dns-a.baidu.com', 'A')    # an existed domain
        if answers[0].host != '180.76.76.76':
            raise Exception('Incorrect DNS response')
        try:
            await resolver.query('test.bad.dns.lijiejie.com', 'A')    # non-existed domain
            # 如果代码执行到这里，说明查询没有抛出异常，即DNS服务器返回了某个IP
            with open('bad_dns_servers.txt', 'a') as f:
                f.write(server + '\n')
            print_msg('[+] Bad DNS Server found %s' % server)
        except aiodns.error.DNSError:
            # 如果查询抛出异常，说明DNS服务器正确地返回了NXDOMAIN错误
            dns_servers.append(server)
        #print_msg('[+] Server %s < OK >   Found %s' % (server.ljust(16), len(dns_servers)))
        print_msg('[+] Server %s < OK >' % (server.ljust(16)),line_feed=True)
    except Exception as e:
        #print_msg('[+] Server %s <Fail>   Found %s' % (server.ljust(16), len(dns_servers)))
        print_msg('[+] Server %s <Fail>' % (server.ljust(16)),line_feed=True)


async def async_load_dns_servers(servers_to_test, dns_servers):
    tasks = []
    for server in servers_to_test:
        '''
        #注意：这里并没有执行测试逻辑，只是创建了一个协程对象（任务）。
        #test_server_python3 必须是一个异步函数（async def 定义），否则这里会报错。
        tasks = [
            test_server_python3('8.8.8.8', dns_servers),
            test_server_python3('1.1.1.1', dns_servers),
            test_server_python3('223.5.5.5', dns_servers)
        ]
        '''
        task = test_server_python3(server, dns_servers)
        tasks.append(task)
    #并发执行所有任务
    await asyncio.gather(*tasks)


def load_dns_servers():
    print_msg('[+] Validate DNS servers',line_feed=True)

    dns_servers = []

    # DNS 服务器地址列表
    servers_to_test = []
    #for server in open('dict/dns_servers.txt').readlines():
    with open(r'dict/dns_servers.txt', encoding='utf-8') as f:
        for server in f:
            server = server.strip()
            if server and not server.startswith('#'):
                servers_to_test.append(server)

    #查找当前线程中是否已经存在一个事件循环，如果存在，就返回它；如果不存在，它会创建一个新的事件循环并返回。
    loop = asyncio.get_event_loop()
    #开始执行 async_load_dns_servers 这个异步任务，并让当前的主线程停下来等待，
    loop.run_until_complete(async_load_dns_servers(servers_to_test, dns_servers))
    # loop.close()

    server_count = len(dns_servers)
    print_msg('\n[+] %s DNS Servers found' % server_count, line_feed=True)
    if server_count == 0:
        print_msg('[ERROR] No valid DNS Server !', line_feed=True)
        sys.exit(-1)
    return dns_servers


def load_next_sub(options):
    """加载并展开 next_sub 模板，返回子域名前缀列表"""
    next_subs = []
    # 完整扫描，这里默认是否
    _file = 'dict/next_sub_full.txt' if options.full_scan else 'dict/next_sub.txt'
    with open(_file, encoding='utf-8') as f:
        for line in f:
            sub = line.strip()
            if sub and sub not in next_subs:
                tmp_set = {sub}
                # 把带有占位符的字符串批量替换成所有可能的组合，最终生成一批待爆破的子域名字符串。
                while tmp_set:
                    item = tmp_set.pop()
                    if '{alphnum}' in item:  # 比 find() 更直观
                        for ch in 'abcdefghijklmnopqrstuvwxyz0123456789':
                            tmp_set.add(item.replace('{alphnum}', ch, 1))
                    elif '{alpha}' in item:
                        for ch in 'abcdefghijklmnopqrstuvwxyz':
                            tmp_set.add(item.replace('{alpha}', ch, 1))
                    elif '{num}' in item:
                        for ch in '0123456789':
                            tmp_set.add(item.replace('{num}', ch, 1))
                    else:
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


async def async_wildcard_test(domain, dns_servers, level=1):
    '''
    :param domain:      要检测的目标域名（例如 example.com）。
    :param dns_servers: 用于解析的 DNS 服务器列表。
    :param level:       检测级别，用于控制递归深度。默认值为 1。
    :return:
    '''
    try:
        r = aiodns.DNSResolver()
        r.nameservers = dns_servers
        # 尝试解析一个非常不可能存在的子域名
        answers = await r.query('zen-me-ke-neng-cun-zai-de-yu-ming-a.%s' % domain, 'A')
        ips = ', '.join(sorted([answer.host for answer in answers]))
        if level == 1:
            #如果能调用，可能是碰巧，再递归调用自身，进入二级测试一下
            print('any-sub.%s\t%s' % (domain.ljust(30), ips))
            await async_wildcard_test('any-sub.%s' % domain, dns_servers, 2)
        elif level == 2:
            # 使用 -w 参数来强制扫描
            print('\n存在泛解析，使用 -w 参数来强制扫描')
            sys.exit(0)
    except Exception as e:
        return domain


def wildcard_test(domain, dns_servers):
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(asyncio.gather(async_wildcard_test(domain, dns_servers, level=1)))[0]

