import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from datetime import datetime, timedelta, timezone
import os
from urllib.parse import urlparse, quote, unquote
import socket
import json
import ssl
import re
from typing import List, Tuple, Optional, Dict, Any, Set
import logging
from collections import defaultdict
import statistics

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('stream_check.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# 配置参数
class Config:
    # UA配置
    USER_AGENT_URL = "PostmanRuntime-ApipostRuntime/1.1.0"
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    
    # 超时配置
    TIMEOUT_FETCH = 10          # 远程URL内容获取超时
    TIMEOUT_CHECK = 5           # 每个直播源检测超时
    TIMEOUT_CONNECT = 3         # 连接建立超时
    TIMEOUT_READ = 2            # 数据读取超时
    IPV6_TIMEOUT_FACTOR = 1.5   # IPv6超时倍数（相对TIMEOUT_CHECK）
    
    # 线程配置
    MAX_WORKERS = 30
    
    # 重试配置
    MAX_RETRIES = 0             # 重试次数（0表示不重试）
    RETRY_DELAY = 0             # 重试等待（秒）
    
    # 域名评估配置
    MIN_SUCCESS_RATE = 0.8      # 最低成功率（优秀域名）
    MIN_SAMPLES = 3             # 最少样本数
    MAX_RESPONSE_TIME = 2000    # 最大响应时间(ms)
    
    # 检测策略
    ENABLE_SMART_DETECTION = True  # 启用智能检测
    
    # 远程源质量评估
    REMOTE_SOURCE_FAILURE_THRESHOLD = 0.5  # 远程源失败率阈值（超过50%标记为差）


class RemoteSourceAnalyzer:
    """远程源质量分析器"""
    def __init__(self):
        self.source_stats: Dict[str, Dict] = defaultdict(lambda: {
            'total_lines': 0,
            'success_count': 0,
            'failed_count': 0,
            'timeout_count': 0,
            'urls': set()
        })
    
    def record_source_result(self, source_url: str, line: str, success: bool, timeout: bool = False):
        """记录远程源中每个链接的检测结果"""
        stats = self.source_stats[source_url]
        stats['total_lines'] += 1
        stats['urls'].add(line.split(',')[1] if ',' in line else line)
        
        if success:
            stats['success_count'] += 1
        else:
            stats['failed_count'] += 1
            if timeout:
                stats['timeout_count'] += 1
    
    def get_poor_sources(self, min_lines: int = 5) -> List[Dict[str, Any]]:
        """获取质量差的远程源（失败率高）"""
        poor_sources = []
        
        for source_url, stats in self.source_stats.items():
            if stats['total_lines'] < min_lines:
                continue
                
            total = stats['total_lines']
            failed = stats['failed_count']
            timeout = stats['timeout_count']
            
            failure_rate = failed / total if total > 0 else 1.0
            timeout_rate = timeout / total if total > 0 else 0
            
            if failure_rate >= Config.REMOTE_SOURCE_FAILURE_THRESHOLD:
                poor_sources.append({
                    'source_url': source_url,
                    'total_lines': total,
                    'failed_count': failed,
                    'success_count': stats['success_count'],
                    'timeout_count': timeout,
                    'failure_rate': round(failure_rate * 100, 1),
                    'timeout_rate': round(timeout_rate * 100, 1),
                    'unique_urls': len(stats['urls'])
                })
        
        # 按失败率排序
        poor_sources.sort(key=lambda x: x['failure_rate'], reverse=True)
        return poor_sources
    
    def get_source_summary(self) -> Dict[str, Any]:
        """获取远程源汇总统计"""
        total_sources = len(self.source_stats)
        total_lines = sum(s['total_lines'] for s in self.source_stats.values())
        total_failed = sum(s['failed_count'] for s in self.source_stats.values())
        total_timeout = sum(s['timeout_count'] for s in self.source_stats.values())
        
        poor_sources = self.get_poor_sources()
        
        return {
            'total_sources': total_sources,
            'total_lines': total_lines,
            'total_failed': total_failed,
            'total_timeout': total_timeout,
            'poor_sources_count': len(poor_sources),
            'poor_sources': poor_sources[:20]  # 只返回前20个最差的
        }


class DomainAnalyzer:
    """域名分析器"""
    def __init__(self):
        self.domain_stats: Dict[str, Dict] = defaultdict(lambda: {
            'success_count': 0,
            'total_count': 0,
            'response_times': [],
            'urls': set(),
            'last_check': None,
            'timeout_count': 0,
            'ipv4_count': 0,
            'ipv6_count': 0
        })
        self.excellent_domains: Set[str] = set()
        self.good_domains: Set[str] = set()
        self.poor_domains: Set[str] = set()
        self.unstable_domains: Set[str] = set()  # 超时率高的不稳定域名
    
    def record_domain_result(self, domain: str, url: str, success: Optional[bool], 
                           response_time: Optional[float], timeout: bool = False,
                           ip_version: Optional[str] = None):
        """记录域名检测结果"""
        if not domain:
            return
            
        stats = self.domain_stats[domain]
        stats['total_count'] += 1
        stats['urls'].add(url)
        
        if success is True:
            stats['success_count'] += 1
            if response_time:
                stats['response_times'].append(response_time)
            if ip_version == 'ipv4':
                stats['ipv4_count'] += 1
            elif ip_version == 'ipv6':
                stats['ipv6_count'] += 1
        elif timeout:
            stats['timeout_count'] += 1
        
        stats['last_check'] = datetime.now().isoformat()
    
    def calculate_domain_score(self, domain: str) -> Tuple[float, Dict[str, Any]]:
        """计算域名质量分数"""
        stats = self.domain_stats[domain]
        
        if stats['total_count'] < Config.MIN_SAMPLES:
            return 0.0, {'reason': '样本不足', 'total_count': stats['total_count']}
        
        # 计算超时率
        timeout_rate = stats['timeout_count'] / stats['total_count'] if stats['total_count'] > 0 else 0
        
        # 计算成功率（排除超时）
        valid_checks = stats['total_count'] - stats['timeout_count']
        if valid_checks == 0:
            return 0.0, {
                'reason': '无有效检测',
                'total_count': stats['total_count'],
                'timeout_rate': timeout_rate
            }
        
        success_rate = stats['success_count'] / valid_checks
        
        # 计算平均响应时间
        avg_response = 0
        if stats['response_times']:
            avg_response = statistics.mean(stats['response_times'])
        
        # 计算稳定性（响应时间标准差）
        stability = 1.0
        if len(stats['response_times']) > 1:
            std_dev = statistics.stdev(stats['response_times'])
            stability = max(0, 1 - (std_dev / 1000))
        
        # 计算覆盖率（URL数量）
        url_coverage = min(1.0, len(stats['urls']) / 20)
        
        # 超时惩罚
        timeout_penalty = timeout_rate * 0.3  # 超时率高的域名扣分
        
        # IPv6支持奖励（如果有IPv6成功记录）
        ipv6_bonus = 0.05 if stats['ipv6_count'] > 0 else 0
        
        # 综合评分
        score = (
            success_rate * 0.5 +          # 成功率权重50%
            (1 - min(1, avg_response / Config.MAX_RESPONSE_TIME)) * 0.2 +  # 速度权重20%
            stability * 0.15 +            # 稳定性权重15%
            url_coverage * 0.1 +          # 覆盖率权重10%
            ipv6_bonus -                   # IPv6支持奖励
            timeout_penalty               # 超时惩罚
        )
        
        # 确保分数在0-1之间
        score = max(0, min(1, score))
        
        metrics = {
            'success_rate': success_rate,
            'timeout_rate': timeout_rate,
            'avg_response': avg_response,
            'stability': stability,
            'url_count': len(stats['urls']),
            'total_checks': stats['total_count'],
            'timeout_checks': stats['timeout_count'],
            'valid_checks': valid_checks,
            'ipv4_success': stats['ipv4_count'],
            'ipv6_success': stats['ipv6_count']
        }
        
        return score, metrics
    
    def classify_domains(self):
        """分类域名质量"""
        self.excellent_domains.clear()
        self.good_domains.clear()
        self.poor_domains.clear()
        self.unstable_domains.clear()
        
        for domain in self.domain_stats.keys():
            score, metrics = self.calculate_domain_score(domain)
            
            # 检查是否有timeout_rate键
            if 'timeout_rate' in metrics:
                # 超时率超过30%标记为不稳定
                if metrics['timeout_rate'] > 0.3:
                    self.unstable_domains.add(domain)
            
            if score >= 0.8:
                self.excellent_domains.add(domain)
            elif score >= 0.6:
                self.good_domains.add(domain)
            else:
                self.poor_domains.add(domain)
    
    def get_excellent_domains_report(self) -> List[Dict[str, Any]]:
        """获取优秀域名报告"""
        report = []
        for domain in self.excellent_domains:
            score, metrics = self.calculate_domain_score(domain)
            report.append({
                'domain': domain,
                'score': round(score, 3),
                'success_rate': round(metrics.get('success_rate', 0) * 100, 1),
                'timeout_rate': round(metrics.get('timeout_rate', 0) * 100, 1),
                'avg_response': round(metrics.get('avg_response', 0), 1),
                'url_count': metrics.get('url_count', 0),
                'total_checks': metrics.get('total_checks', 0),
                'ipv4_success': metrics.get('ipv4_success', 0),
                'ipv6_success': metrics.get('ipv6_success', 0)
            })
        
        # 按分数排序
        report.sort(key=lambda x: x['score'], reverse=True)
        return report


class StreamChecker:
    def __init__(self):
        self.timestart = datetime.now()
        self.url_statistics: List[str] = []
        self.domain_analyzer = DomainAnalyzer()
        self.remote_source_analyzer = RemoteSourceAnalyzer()
        
        # 域名级缓存（用于智能检测）
        self.domain_quality_cache: Dict[str, float] = {}
        self.domain_last_check: Dict[str, datetime] = {}
        
        # IPv6环境检测
        self.ipv6_available = self._check_ipv6_support()
        logger.info(f"IPv6环境检测: {'可用' if self.ipv6_available else '不可用'}")
    
    def _check_ipv6_support(self) -> bool:
        """检测系统是否支持IPv6（尝试连接Google Public DNS IPv6）"""
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex(('2001:4860:4860::8888', 53))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def get_domain_from_url(self, url: str) -> str:
        """从URL提取域名（IPv6地址返回无括号形式）"""
        try:
            parsed = urlparse(url)
            return parsed.hostname.lower() if parsed.hostname else ""
        except:
            return ""
    
    def is_ipv6_address(self, host: str) -> bool:
        """判断是否为IPv6地址（不含括号）"""
        try:
            socket.inet_pton(socket.AF_INET6, host)
            return True
        except:
            return False
    
    def read_txt_to_array(self, file_name: str) -> List[str]:
        """读取文本文件到数组"""
        try:
            with open(file_name, 'r', encoding='utf-8') as file:
                return [line.strip() for line in file if line.strip()]
        except Exception as e:
            logger.error(f"读取文件失败 {file_name}: {e}")
            return []
    
    def read_txt_file(self, file_path: str) -> List[str]:
        """读取直播源文件，过滤无效行"""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                lines = []
                for line in file:
                    line = line.strip()
                    if line and '://' in line and ',' in line and '#genre#' not in line:
                        lines.append(line)
                return lines
        except Exception as e:
            logger.error(f"读取文件失败 {file_path}: {e}")
            return []
    
    def create_ssl_context(self):
        """创建SSL上下文"""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_ciphers('DEFAULT:@SECLEVEL=1')
        return context
    
    def check_http_url(self, url: str, timeout: int) -> Tuple[Optional[bool], Optional[float], Optional[str]]:
        """HTTP/HTTPS检测，返回(状态, 响应时间ms, IP版本)"""
        start_time = time.time()
        ip_version = None
        
        for retry in range(Config.MAX_RETRIES + 1):
            try:
                req = urllib.request.Request(
                    url,
                    headers={
                        "User-Agent": Config.USER_AGENT,
                        "Accept": "*/*",
                        "Connection": "close",
                        "Accept-Encoding": "gzip, deflate"
                    }
                )
                
                opener = urllib.request.build_opener(
                    urllib.request.HTTPSHandler(context=self.create_ssl_context())
                )
                
                with opener.open(req, timeout=timeout) as resp:
                    sock = resp.fp.raw._sock if hasattr(resp.fp, 'raw') else None
                    if sock:
                        peer_addr = sock.getpeername()[0]
                        ip_version = 'ipv6' if ':' in peer_addr else 'ipv4'
                    
                    resp.read(512)
                    elapsed = (time.time() - start_time) * 1000
                    return True, elapsed, ip_version
                    
            except urllib.error.HTTPError as e:
                elapsed = (time.time() - start_time) * 1000
                if e.code in [401, 403, 404]:
                    return False, elapsed, ip_version
                if retry == Config.MAX_RETRIES:
                    return None, elapsed, ip_version
                time.sleep(Config.RETRY_DELAY)
                
            except (socket.timeout, urllib.error.URLError) as e:
                elapsed = (time.time() - start_time) * 1000
                if retry == Config.MAX_RETRIES:
                    if isinstance(e, socket.timeout):
                        return None, elapsed, ip_version
                    else:
                        return False, elapsed, ip_version
                time.sleep(Config.RETRY_DELAY)
                
            except Exception as e:
                elapsed = (time.time() - start_time) * 1000
                if retry == Config.MAX_RETRIES:
                    logger.debug(f"HTTP检测异常 {url}: {e}")
                    return False, elapsed, ip_version
                time.sleep(Config.RETRY_DELAY)
        
        return None, None, None
    
    def check_rtmp_rtsp_url(self, url: str, timeout: int) -> Tuple[Optional[bool], Optional[float], Optional[str]]:
        """RTMP/RTSP检测，返回(状态, 响应时间ms, IP版本)"""
        start_time = time.time()
        ip_version = None
        
        for retry in range(Config.MAX_RETRIES + 1):
            try:
                parsed = urlparse(url)
                host = parsed.hostname
                port = parsed.port or (1935 if url.startswith('rtmp') else 554)
                
                if not host:
                    elapsed = (time.time() - start_time) * 1000
                    return False, elapsed, ip_version
                
                addr_info = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
                if self.ipv6_available:
                    addr_info = sorted(addr_info, key=lambda x: x[0] != socket.AF_INET6)
                
                sock = None
                for res in addr_info:
                    af, socktype, proto, canonname, sa = res
                    try:
                        sock = socket.socket(af, socktype, proto)
                        sock.settimeout(min(Config.TIMEOUT_CONNECT, timeout))
                        sock.connect(sa)
                        ip_version = 'ipv6' if af == socket.AF_INET6 else 'ipv4'
                        break
                    except Exception:
                        if sock:
                            sock.close()
                        sock = None
                        continue
                
                if sock is None:
                    elapsed = (time.time() - start_time) * 1000
                    return False, elapsed, ip_version
                
                if url.startswith('rtmp'):
                    sock.send(b'\x03')
                    sock.settimeout(2)
                    try:
                        data = sock.recv(1)
                        if data:
                            sock.close()
                            elapsed = (time.time() - start_time) * 1000
                            return True, elapsed, ip_version
                    except socket.timeout:
                        pass
                
                elif url.startswith('rtsp'):
                    request = f"OPTIONS {url} RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: {Config.USER_AGENT}\r\n\r\n"
                    sock.send(request.encode())
                    sock.settimeout(2)
                    try:
                        response = sock.recv(1024)
                        if b'RTSP/1.0' in response:
                            sock.close()
                            elapsed = (time.time() - start_time) * 1000
                            return True, elapsed, ip_version
                    except socket.timeout:
                        pass
                
                sock.close()
                elapsed = (time.time() - start_time) * 1000
                return True, elapsed, ip_version
                
            except (socket.timeout, ConnectionRefusedError, ConnectionResetError) as e:
                elapsed = (time.time() - start_time) * 1000
                if retry == Config.MAX_RETRIES:
                    if isinstance(e, socket.timeout):
                        return None, elapsed, ip_version
                    else:
                        return False, elapsed, ip_version
                time.sleep(Config.RETRY_DELAY)
                
            except Exception as e:
                elapsed = (time.time() - start_time) * 1000
                if retry == Config.MAX_RETRIES:
                    logger.debug(f"RTMP/RTSP检测异常 {url}: {e}")
                    return False, elapsed, ip_version
                time.sleep(Config.RETRY_DELAY)
        
        return None, None, None
    
    def check_url(self, url: str) -> Tuple[Optional[float], Optional[bool], Optional[str]]:
        """
        主检测函数
        返回: (响应时间ms, 状态, IP版本)
        """
        domain = self.get_domain_from_url(url)
        is_ipv6 = domain and self.is_ipv6_address(domain)
        
        if Config.ENABLE_SMART_DETECTION and domain:
            if domain in self.domain_analyzer.unstable_domains:
                check_timeout = min(Config.TIMEOUT_CHECK, 2)
            else:
                check_timeout = Config.TIMEOUT_CHECK
        else:
            check_timeout = Config.TIMEOUT_CHECK
        
        if is_ipv6 or self.ipv6_available:
            check_timeout = int(check_timeout * Config.IPV6_TIMEOUT_FACTOR)
        
        start_time = time.time()
        status = None
        response_time = None
        ip_version = None
        
        try:
            encoded_url = quote(unquote(url), safe=':/?&=#')
            
            if url.startswith(("http://", "https://")):
                status, response_time, ip_version = self.check_http_url(encoded_url, check_timeout)
            elif url.startswith(("rtmp://", "rtsp://")):
                status, response_time, ip_version = self.check_rtmp_rtsp_url(encoded_url, check_timeout)
            else:
                parsed = urlparse(url)
                host = parsed.hostname
                port = parsed.port or 80
                if host:
                    try:
                        addr_info = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
                        if self.ipv6_available:
                            addr_info = sorted(addr_info, key=lambda x: x[0] != socket.AF_INET6)
                        
                        sock = None
                        for res in addr_info:
                            af, socktype, proto, canonname, sa = res
                            try:
                                sock = socket.socket(af, socktype, proto)
                                sock.settimeout(Config.TIMEOUT_CONNECT)
                                sock.connect(sa)
                                ip_version = 'ipv6' if af == socket.AF_INET6 else 'ipv4'
                                break
                            except Exception:
                                if sock:
                                    sock.close()
                                sock = None
                                continue
                        
                        if sock:
                            sock.close()
                            response_time = (time.time() - start_time) * 1000
                            status = True
                        else:
                            response_time = (time.time() - start_time) * 1000
                            status = False
                    except Exception:
                        response_time = (time.time() - start_time) * 1000
                        status = False
        
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            logger.debug(f"检测异常 {url}: {e}")
            status = False
        
        timeout = (status is None)
        if domain:
            self.domain_analyzer.record_domain_result(
                domain, url, status, response_time, timeout, ip_version
            )
        
        return response_time, status, ip_version
    
    def process_m3u_content(self, text: str, source_url: str) -> List[str]:
        """处理M3U格式内容"""
        lines = []
        try:
            if "#EXTM3U" not in text:
                return lines
            
            current_name = ""
            for line in text.split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                if line.startswith("#EXTINF"):
                    match = re.search(r',(.+)$', line)
                    if match:
                        current_name = match.group(1).strip()
                elif line.startswith(('http://', 'https://', 'rtmp://', 'rtsp://')):
                    if current_name:
                        lines.append(f"{current_name},{line}")
                    else:
                        lines.append(f"Unknown,{line}")
            
            return lines
            
        except Exception as e:
            logger.error(f"解析M3U内容失败: {e}")
            return []
    
    def fetch_remote_urls(self, urls: List[str]):
        """获取远程URL内容"""
        all_lines = []
        source_line_mapping = []
        
        for url in urls:
            try:
                encoded_url = quote(unquote(url), safe=':/?&=#')
                req = urllib.request.Request(
                    encoded_url,
                    headers={"User-Agent": Config.USER_AGENT_URL}
                )
                
                with urllib.request.urlopen(req, timeout=Config.TIMEOUT_FETCH) as resp:
                    content = resp.read().decode('utf-8', errors='replace')
                    
                    if "#EXTM3U" in content:
                        lines = self.process_m3u_content(content, url)
                    else:
                        lines = []
                        for line in content.split('\n'):
                            line = line.strip()
                            if line and '://' in line and ',' in line and '#genre#' not in line:
                                lines.append(line)
                    
                    count = len(lines)
                    self.url_statistics.append(f"{count},{url}")
                    
                    for line in lines:
                        all_lines.append(line)
                        source_line_mapping.append(url)
                    
            except Exception as e:
                logger.error(f"获取远程URL失败 {url}: {e}")
        
        return all_lines, source_line_mapping
    
    def clean_and_deduplicate(self, lines: List[str]) -> List[str]:
        """清理和去重链接"""
        new_lines = []
        for line in lines:
            if ',' not in line or '://' not in line:
                continue
            
            name, urls = line.split(',', 1)
            name = name.strip()
            
            for url_part in urls.split('#'):
                url_part = url_part.strip()
                if '://' in url_part:
                    if '$' in url_part:
                        url_part = url_part[:url_part.rfind('$')]
                    new_lines.append(f"{name},{url_part}")
        
        unique_lines = []
        seen_urls = set()
        
        for line in new_lines:
            if ',' in line:
                _, url = line.split(',', 1)
                url = url.strip()
                if url not in seen_urls:
                    seen_urls.add(url)
                    unique_lines.append(line)
        
        return unique_lines
    
    def process_batch_urls(self, lines: List[str], source_mapping: List[str], whitelist: set) -> Tuple[List[str], List[str], List[str]]:
        """
        批量处理URL检测
        返回: (成功列表, 失败列表, 超时列表)
        """
        success_list = []
        failed_list = []
        timeout_list = []
        total = len(lines)
        
        if not lines:
            return success_list, failed_list, timeout_list
        
        logger.info(f"开始检测 {total} 个链接")
        
        with ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
            futures = {}
            for idx, line in enumerate(lines):
                if ',' in line:
                    name, url = line.split(',', 1)
                    url = url.strip()
                    futures[executor.submit(self.check_url, url)] = (idx, line, url)
            
            processed = 0
            success_count = 0
            timeout_count = 0
            failed_count = 0
            ipv6_success_count = 0
            
            for future in as_completed(futures):
                idx, line, url = futures[future]
                processed += 1
                
                try:
                    response_time, status, ip_version = future.result()
                    
                    if idx < len(source_mapping):
                        source_url = source_mapping[idx]
                        self.remote_source_analyzer.record_source_result(
                            source_url, line, status is True, status is None
                        )
                    
                    if url in whitelist:
                        elapsed_str = f"{response_time or 0:.2f}ms" if response_time else "0.00ms"
                        ip_tag = f"[{ip_version}]" if ip_version else ""
                        success_list.append(f"{elapsed_str}{ip_tag},{line}")
                        success_count += 1
                        if ip_version == 'ipv6':
                            ipv6_success_count += 1
                        continue
                    
                    if status is True:
                        elapsed_str = f"{response_time:.2f}ms" if response_time else "0.00ms"
                        ip_tag = f"[{ip_version}]" if ip_version else ""
                        success_list.append(f"{elapsed_str}{ip_tag},{line}")
                        success_count += 1
                        if ip_version == 'ipv6':
                            ipv6_success_count += 1
                    elif status is False:
                        failed_list.append(line)
                        failed_count += 1
                    elif status is None:
                        timeout_list.append(line)
                        timeout_count += 1
                        failed_list.append(line)
                        failed_count += 1
                    
                    if processed % 100 == 0 or processed == total:
                        logger.info(f"进度: {processed}/{total} | 成功: {success_count} (IPv6: {ipv6_success_count}) | 超时: {timeout_count} | 失败: {failed_count}")
                        
                except Exception as e:
                    logger.error(f"处理链接失败 {line}: {e}")
                    failed_list.append(line)
                    failed_count += 1
        
        # 修复：添加异常处理的排序函数
        def extract_response_time(line):
            """安全提取响应时间进行排序"""
            try:
                time_part = line.split(',')[0]
                if ']' in time_part:
                    time_part = time_part.split(']')[-1]
                time_str = time_part.replace('ms', '').strip()
                return float(time_str) if time_str else float('inf')
            except (ValueError, IndexError, AttributeError):
                return float('inf')
        
        success_list.sort(key=extract_response_time)
        
        logger.info(f"检测完成 - 成功: {len(success_list)} (IPv6: {sum(1 for s in success_list if '[ipv6]' in s)}), 失败: {len(failed_list)}, 超时: {len(timeout_list)}")
        return success_list, failed_list, timeout_list
    
    def print_excellent_domains_report(self):
        """打印优秀域名报告"""
        self.domain_analyzer.classify_domains()
        
        excellent_report = self.domain_analyzer.get_excellent_domains_report()
        
        if not excellent_report:
            logger.info("未找到优秀的域名")
            return
        
        logger.info("=" * 100)
        logger.info("优秀域名排行榜 (基于成功率、速度、稳定性和IPv6支持)")
        logger.info("=" * 100)
        logger.info(f"{'排名':<4} {'域名':<40} {'综合评分':<8} {'成功率':<8} {'超时率':<8} {'平均响应':<10} {'IPv6成功'}")
        logger.info("-" * 100)
        
        for idx, domain_info in enumerate(excellent_report[:20], 1):
            logger.info(
                f"{idx:<4} {domain_info['domain'][:38]:<40} "
                f"{domain_info['score']:<8.3f} "
                f"{domain_info['success_rate']:<7.1f}% "
                f"{domain_info['timeout_rate']:<7.1f}% "
                f"{domain_info['avg_response']:<9.1f}ms "
                f"{domain_info['ipv6_success']:<6}"
            )
        
        logger.info("=" * 100)
        
        total_domains = len(self.domain_analyzer.domain_stats)
        excellent_count = len(self.domain_analyzer.excellent_domains)
        good_count = len(self.domain_analyzer.good_domains)
        unstable_count = len(self.domain_analyzer.unstable_domains)
        
        logger.info("域名质量统计:")
        logger.info(f"  总域名数: {total_domains}")
        logger.info(f"  优秀域名: {excellent_count} ({excellent_count/max(1, total_domains)*100:.1f}%)")
        logger.info(f"  良好域名: {good_count} ({good_count/max(1, total_domains)*100:.1f}%)")
        logger.info(f"  较差域名: {total_domains - excellent_count - good_count} ({(total_domains - excellent_count - good_count)/max(1, total_domains)*100:.1f}%)")
        logger.info(f"  不稳定域名: {unstable_count} ({unstable_count/max(1, total_domains)*100:.1f}%)")
        
        self.generate_excellent_domains_config()
    
    def print_poor_remote_sources(self):
        """打印失败率高的远程源"""
        summary = self.remote_source_analyzer.get_source_summary()
        
        if summary['poor_sources_count'] == 0:
            logger.info("未发现失败率高的远程源")
            return
        
        logger.info("=" * 100)
        logger.info("失败率高的远程源列表 (失败率 >= 50%)")
        logger.info("=" * 100)
        logger.info(f"{'排名':<4} {'失败率':<8} {'超时率':<8} {'总行数':<8} {'失败数':<8} {'成功数':<8} {'超时数':<8} {'远程源地址'}")
        logger.info("-" * 100)
        
        for idx, source in enumerate(summary['poor_sources'][:20], 1):
            source_url = source['source_url']
            if len(source_url) > 50:
                source_url = source_url[:47] + "..."
            
            logger.info(
                f"{idx:<4} "
                f"{source['failure_rate']:<7.1f}% "
                f"{source['timeout_rate']:<7.1f}% "
                f"{source['total_lines']:<8} "
                f"{source['failed_count']:<8} "
                f"{source['success_count']:<8} "
                f"{source['timeout_count']:<8} "
                f"{source_url}"
            )
        
        logger.info("=" * 100)
        
        logger.info("远程源质量汇总:")
        logger.info(f"  总远程源数: {summary['total_sources']}")
        logger.info(f"  总链接数: {summary['total_lines']}")
        logger.info(f"  总失败数: {summary['total_failed']} ({summary['total_failed']/summary['total_lines']*100:.1f}%)")
        logger.info(f"  总超时数: {summary['total_timeout']} ({summary['total_timeout']/summary['total_lines']*100:.1f}%)")
        logger.info(f"  高失败率源数: {summary['poor_sources_count']} ({summary['poor_sources_count']/summary['total_sources']*100:.1f}%)")
    
    def generate_excellent_domains_config(self):
        """生成优秀域名配置文件"""
        excellent_domains = self.domain_analyzer.excellent_domains
        
        if not excellent_domains:
            return
        
        domains_list = sorted(excellent_domains)
        domains_content = "# 优秀域名列表 (自动生成)\n"
        domains_content += f"# 更新时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        domains_content += f"# 生成规则: 成功率>80%，响应时间<2000ms，超时率<30%，IPv6支持加分\n\n"
        
        for domain in domains_list:
            stats = self.domain_analyzer.domain_stats[domain]
            timeout_rate = stats['timeout_count'] / stats['total_count'] if stats['total_count'] > 0 else 0
            valid_checks = stats['total_count'] - stats['timeout_count']
            success_rate = stats['success_count'] / valid_checks if valid_checks > 0 else 0
            
            avg_response = 0
            if stats['response_times']:
                avg_response = statistics.mean(stats['response_times'])
            
            domains_content += f"# 成功率: {success_rate*100:.1f}% | "
            domains_content += f"超时率: {timeout_rate*100:.1f}% | "
            domains_content += f"平均响应: {avg_response:.1f}ms | "
            domains_content += f"URL数量: {len(stats['urls'])} | "
            domains_content += f"IPv6成功: {stats['ipv6_count']}\n"
            domains_content += f"{domain}\n\n"
        
        rules_content = "# 域名过滤规则 (用于其他工具)\n"
        rules_content += "# 格式: *域名* 表示匹配该域名的所有子域名\n\n"
        
        all_domains = list(self.domain_analyzer.excellent_domains) + \
                     list(self.domain_analyzer.good_domains)
        
        sorted_domains = []
        for domain in all_domains:
            stats = self.domain_analyzer.domain_stats[domain]
            valid_checks = stats['total_count'] - stats['timeout_count']
            if valid_checks > 0:
                success_rate = stats['success_count'] / valid_checks
                sorted_domains.append((domain, success_rate))
        
        sorted_domains.sort(key=lambda x: x[1], reverse=True)
        
        for domain, success_rate in sorted_domains[:100]:
            stats = self.domain_analyzer.domain_stats[domain]
            valid_checks = stats['total_count'] - stats['timeout_count']
            
            rules_content += f"# 成功率: {success_rate*100:.1f}% "
            rules_content += f"({stats['success_count']}/{valid_checks}) "
            rules_content += f"IPv6: {stats['ipv6_count']}\n"
            rules_content += f"*{domain}*\n\n"
        
        try:
            with open("excellent_domains.txt", "w", encoding="utf-8") as f:
                f.write(domains_content)
            
            with open("domain_filter_rules.txt", "w", encoding="utf-8") as f:
                f.write(rules_content)
            
            logger.info(f"已生成优秀域名配置文件: excellent_domains.txt ({len(domains_list)}个域名)")
            logger.info(f"已生成域名筛选规则: domain_filter_rules.txt")
            
        except Exception as e:
            logger.error(f"生成配置文件失败: {e}")
    
    def run(self):
        """主运行函数"""
        file_paths = self.get_file_paths()
        
        remote_urls = self.read_txt_to_array(file_paths["urls"])
        logger.info(f"从远程URL获取直播源...")
        all_lines, source_mapping = self.fetch_remote_urls(remote_urls)
        logger.info(f"从远程URL获取到 {len(all_lines)} 个链接")
        
        whitelist_lines = self.read_txt_file(file_paths.get("whitelist_manual", ""))
        whitelist_lines = self.clean_and_deduplicate(whitelist_lines)
        
        whitelist_set = set()
        for line in whitelist_lines:
            if ',' in line:
                _, url = line.split(',', 1)
                whitelist_set.add(url.strip())
        
        logger.info(f"白名单链接数: {len(whitelist_set)}")
        
        cleaned_lines = self.clean_and_deduplicate(all_lines)
        logger.info(f"清理去重后链接数: {len(cleaned_lines)}")
        
        success_list, failed_list, timeout_list = self.process_batch_urls(cleaned_lines, source_mapping, whitelist_set)
        
        self.print_excellent_domains_report()
        self.print_poor_remote_sources()
        self.save_results(success_list, failed_list, timeout_list)
        self.print_statistics(cleaned_lines, success_list, failed_list, timeout_list)
    
    def get_file_paths(self):
        """获取文件路径"""
        current_dir = os.path.dirname(os.path.abspath(__file__))
        parent_dir = os.path.dirname(current_dir)
        parent2_dir = os.path.dirname(parent_dir)
        
        return {
            "urls": os.path.join(parent_dir, 'urls.txt'),
            "live": os.path.join(parent2_dir, 'live.txt'),
            "blacklist_auto": os.path.join(current_dir, 'blacklist_auto.txt'),
            "whitelist_manual": os.path.join(current_dir, 'whitelist_manual.txt'),
            "whitelist_auto": os.path.join(current_dir, 'whitelist_auto.txt'),
            "whitelist_auto_tv": os.path.join(current_dir, 'whitelist_auto_tv.txt'),
            "timelist_auto": os.path.join(current_dir, 'timelist_auto.txt')
        }
    
    def save_results(self, success_list: List[str], failed_list: List[str], timeout_list: List[str]):
        """保存检测结果"""
        bj_time = datetime.now(timezone.utc) + timedelta(hours=8)
        version = f"{bj_time.strftime('%Y%m%d %H:%M')},url"
        
        success_output = [
            "更新时间,#genre#",
            version,
            "",
            "RespoTime[IP],whitelist,#genre#"
        ] + success_list
        
        success_tv = []
        for line in success_list:
            parts = line.split(',', 1)
            if len(parts) == 2:
                time_ip_part = parts[0]
                name_url = parts[1]
                if ']' in time_ip_part:
                    time_ip_part = time_ip_part.split(']')[-1]
                success_tv.append(name_url)
        
        success_tv_output = [
            "更新时间,#genre#",
            version,
            "",
            "whitelist,#genre#"
        ] + success_tv
        
        failed_output = [
            "更新时间,#genre#",
            version,
            "",
            "blacklist,#genre#"
        ] + failed_list

        timeout_output = [
            "更新时间,#genre#",
            version,
            "",
            "timeout,#genre#"
        ] + timeout_list
        
        file_paths = self.get_file_paths()
        self.write_list(file_paths["whitelist_auto"], success_output)
        self.write_list(file_paths["whitelist_auto_tv"], success_tv_output)
        self.write_list(file_paths["blacklist_auto"], failed_output)
        self.write_list(file_paths["timelist_auto"], timeout_output)
        
        logger.info(f"结果已保存:")
        logger.info(f"  - 成功列表: {len(success_list)}个链接 (IPv6: {sum(1 for s in success_list if '[ipv6]' in s)})")
        logger.info(f"  - 失败列表: {len(failed_list)}个链接")
        logger.info(f"  - 超时列表: {len(timeout_list)}个链接")
    
    def write_list(self, file_path: str, data_list: List[str]):
        """写入列表到文件"""
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(data_list))
        except Exception as e:
            logger.error(f"写入文件失败 {file_path}: {e}")
    
    def print_statistics(self, cleaned_lines: List[str], success_list: List[str], 
                        failed_list: List[str], timeout_list: List[str]):
        """打印统计信息"""
        end_time = datetime.now()
        elapsed = end_time - self.timestart
        mins, secs = int(elapsed.total_seconds() // 60), int(elapsed.total_seconds() % 60)
        
        total_detected = len(success_list) + len(failed_list)
        ipv6_success = sum(1 for s in success_list if '[ipv6]' in s)
        
        logger.info("=" * 60)
        logger.info("最终统计:")
        logger.info(f"  总耗时: {mins}分{secs}秒")
        logger.info(f"  清理后链接数: {len(cleaned_lines)}")
        logger.info(f"  检测链接数: {total_detected}")
        logger.info(f"  成功链接数: {len(success_list)} (IPv6: {ipv6_success})")
        logger.info(f"  失败链接数: {len(failed_list)}")
        logger.info(f"  超时链接数: {len(timeout_list)}")
        
        if total_detected > 0:
            success_rate = len(success_list) / total_detected * 100
            logger.info(f"  整体成功率: {success_rate:.1f}%")
            if ipv6_success:
                ipv6_rate = ipv6_success / len(success_list) * 100 if success_list else 0
                logger.info(f"  成功链接中IPv6占比: {ipv6_rate:.1f}%")
            
            if timeout_list:
                timeout_rate = len(timeout_list) / total_detected * 100
                logger.info(f"  超时率: {timeout_rate:.1f}%")
        
        if success_list:
            # 修复：添加异常处理的排序函数
            def extract_time(line):
                try:
                    time_part = line.split(',')[0]
                    if ']' in time_part:
                        time_part = time_part.split(']')[-1]
                    time_str = time_part.replace('ms', '').strip()
                    return float(time_str) if time_str else float('inf')
                except (ValueError, IndexError, AttributeError):
                    return float('inf')
            
            sorted_success = sorted(success_list, key=extract_time)
            
            if len(sorted_success) >= 5:
                logger.info(f"  最快5个链接:")
                for i, link in enumerate(sorted_success[:5]):
                    parts = link.split(',', 1)
                    time_ip = parts[0]
                    name = parts[1].split(',')[0] if ',' in parts[1] else "Unknown"
                    logger.info(f"    {i+1}. {time_ip} - {name[:30]}")
                
                logger.info(f"  最慢5个链接:")
                for i, link in enumerate(sorted_success[-5:][::-1]):
                    parts = link.split(',', 1)
                    time_ip = parts[0]
                    name = parts[1].split(',')[0] if ',' in parts[1] else "Unknown"
                    logger.info(f"    {i+1}. {time_ip} - {name[:30]}")
        
        logger.info("=" * 60)


def main():
    """主函数"""
    logger.info("开始直播源检测和域名质量分析...")
    logger.info(f"配置: 超时={Config.TIMEOUT_CHECK}s, IPv6超时倍数={Config.IPV6_TIMEOUT_FACTOR}, 线程={Config.MAX_WORKERS}, 重试={Config.MAX_RETRIES}")
    logger.info(f"智能检测: {'启用' if Config.ENABLE_SMART_DETECTION else '禁用'}")
    logger.info(f"远程源失败率阈值: {Config.REMOTE_SOURCE_FAILURE_THRESHOLD*100}%")
    
    checker = StreamChecker()
    
    try:
        checker.run()
    except KeyboardInterrupt:
        logger.info("检测被用户中断")
    except Exception as e:
        logger.error(f"检测过程发生错误: {e}", exc_info=True)
    finally:
        logger.info("检测结束")


if __name__ == "__main__":
    main()
