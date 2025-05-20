import sys
sys.stdout.reconfigure(encoding='utf-8')

import dns.resolver
import time
import requests
import socket
import os
import subprocess
import csv

def load_country_mapping(file_path):
    country_mapping = {}
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                parts = line.strip().split(',')
                if len(parts) == 2:
                    code, name = parts
                    country_mapping[code.strip()] = name.replace(" ", "")
    except FileNotFoundError:
        print(f"错误: 文件 {file_path} 未找到。")
    except Exception as e:
        print(f"加载国家信息时发生错误: {e}")
    return country_mapping

def check_tcp_connection(ip, port=443, timeout=5):
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.close()
        return True
    except (socket.timeout, socket.error):
        return False

def get_country_info(ip, country_mapping, retries=10, delay=1):
    attempt = 0
    while attempt < retries:
        if not check_tcp_connection(ip, port=443):
            print(f"IP {ip} 无法连接，跳过国家信息查询。")
            return "不可达"
        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
            if response.status_code == 200:
                data = response.json()
                code = data.get("country", "未知")
                name = country_mapping.get(code, "未知")
                print(f"检测到 IP {ip} 的国家: {code}{name}")
                return f"{code}{name}"
            else:
                print(f"API响应异常: {response.status_code}")
                return "未知"
        except requests.exceptions.RequestException as e:
            print(f"请求异常: {e}")
            attempt += 1
            if attempt < retries:
                print(f"重试 {attempt}/{retries} 中...")
                time.sleep(delay)
            else:
                print(f"无法获取 {ip} 的国家信息。")
                return "未知"

def collect_all_ips(manual_ip_file, domains_file, output_file):
    all_ips = set()
    if os.path.exists(manual_ip_file):
        with open(manual_ip_file, 'r', encoding='utf-8') as f:
            for line in f:
                ip = line.strip()
                if ip:
                    all_ips.add(ip)
    if os.path.exists(domains_file):
        with open(domains_file, 'r', encoding='utf-8') as f:
            domains = [line.strip() for line in f if line.strip()]
        for domain in domains:
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 10
                resolver.lifetime = 15
                print(f"开始检测 {domain}...")
                results = resolver.resolve(domain, 'A')
                for ip in results:
                    all_ips.add(ip.address)
            except Exception as e:
                print(f"域名 {domain} 解析失败: {e}")
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        for ip in sorted(all_ips):
            f.write(f"{ip}#未检测\n")
    print(f"所有采集的IP已保存到 {output_file}")

def detect_all_ip_country(input_file, output_file, country_mapping):
    ip_info = {}
    with open(input_file, 'r', encoding='utf-8') as f:
        for line in f:
            if '#' in line:
                ip, info = line.strip().split('#', 1)
                ip_info[ip] = info
    for ip, info in ip_info.items():
        if info == "未检测":
            country = get_country_info(ip, country_mapping)
            ip_info[ip] = country
    with open(output_file, 'w', encoding='utf-8') as f:
        for ip, info in sorted(ip_info.items(), key=lambda x: x[1]):
            f.write(f"{ip}#{info}\n")
    print(f"所有IP归属地检测完成，已更新到 {output_file}")

def extract_ips_from_file(input_file, output_file):
    try:
        with open(input_file, 'r', encoding='utf-8') as file:
            lines = file.readlines()
        ips = {line.strip().split('#')[0] for line in lines if '#' in line}
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as file:
            for ip in sorted(ips):
                file.write(f"{ip}\n")
        print(f"提取的IP已保存到 {output_file}")
    except FileNotFoundError:
        print(f"文件未找到: {input_file}")
    except Exception as e:
        print(f"提取出错: {e}")

def filter_ips_by_allowed_countries(
    input_file, allowed_countries_file, allowed_ip_file, blocked_ip_file,
    allowed_with_info_file, blocked_with_info_file,
    unreachable_ip_file,
    unreachable_with_info_file
):
    try:
        with open(allowed_countries_file, 'r', encoding='utf-8') as f:
            allowed = {line.strip().replace(" ", "") for line in f if line.strip()}

        allowed_ips, blocked_ips = [], []
        allowed_info, blocked_info = [], []
        unreachable_ips = []
        unreachable_info = []

        with open(input_file, 'r', encoding='utf-8') as file:
            for line in file:
                parts = line.strip().split('#')
                if len(parts) == 2:
                    ip, info = parts
                    if info in allowed:
                        allowed_ips.append(ip)
                        allowed_info.append(line.strip())
                    elif info == "不可达":
                        blocked_ips.append(ip)
                        blocked_info.append(line.strip())
                        unreachable_ips.append(ip)
                        unreachable_info.append(line.strip())
                    else:
                        blocked_ips.append(ip)
                        blocked_info.append(line.strip())

        for path, data in [
            (allowed_ip_file, sorted(allowed_ips)),
            (blocked_ip_file, sorted(blocked_ips)),
            (allowed_with_info_file, sorted(allowed_info, key=lambda x: x.split('#')[1])),
            (blocked_with_info_file, sorted(blocked_info, key=lambda x: x.split('#')[1]))
        ]:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'w', encoding='utf-8') as f:
                for item in data:
                    f.write(f"{item}\n")

        os.makedirs(os.path.dirname(unreachable_ip_file), exist_ok=True)
        with open(unreachable_ip_file, 'w', encoding='utf-8') as f:
            for ip in sorted(unreachable_ips):
                f.write(f"{ip}\n")
        os.makedirs(os.path.dirname(unreachable_with_info_file), exist_ok=True)
        with open(unreachable_with_info_file, 'w', encoding='utf-8') as f:
            for item in sorted(unreachable_info, key=lambda x: x.split('#')[1]):
                f.write(f"{item}\n")

        print("筛选完成：")
        print(f"✅ 允许: {len(allowed_ips)} 个IP → {allowed_ip_file}, {allowed_with_info_file}")
        print(f"❌ 拦截: {len(blocked_ips)} 个IP → {blocked_ip_file}, {blocked_with_info_file}")
        print(f"🚫 不可达: {len(unreachable_ips)} 个IP → {unreachable_ip_file}, {unreachable_with_info_file}")

    except FileNotFoundError as e:
        print(f"文件缺失: {e}")
    except Exception as e:
        print(f"筛选时发生错误: {e}")

def save_ip_txt_for_cloudflarescanner(allowed_ip_file, target_path):
    try:
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        with open(allowed_ip_file, 'r', encoding='utf-8') as fr:
            lines = fr.readlines()
        with open(target_path, 'w', encoding='utf-8') as fw:
            for line in lines:
                fw.write(line)
        print(f"已保存 {target_path}")
    except Exception as e:
        print(f"保存 {target_path} 时发生错误: {e}")

def run_cloudflarescanner_with_dn():
    exe_path = os.path.join("CloudflareScanner", "CloudflareScanner.exe")
    ip_txt_path = os.path.join("CloudflareScanner", "ip.txt")
    if not os.path.isfile(exe_path):
        print(f"未找到 {exe_path}")
        sys.exit(1)
    if not os.path.isfile(ip_txt_path):
        print(f"未找到 {ip_txt_path}")
        sys.exit(1)
    # 统计ip.txt行数
    ip_count = 0
    with open(ip_txt_path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                ip_count += 1
    try:
        # 传递参数-dn <数量>
        subprocess.Popen([exe_path, "-dn", str(ip_count)], cwd="CloudflareScanner")
        print(f"已启动 {exe_path} -dn {ip_count}")
    except Exception as e:
        print(f"运行 {exe_path} 时发生错误: {e}")
        sys.exit(1)

def wait_for_result_csv(result_csv_path, timeout=600, interval=2):
    """等待result.csv生成，超时时间单位为秒，默认10分钟。"""
    print(f"等待 {result_csv_path} 文件生成 ...")
    waited = 0
    while waited < timeout:
        if os.path.isfile(result_csv_path):
            print(f"{result_csv_path} 已生成，继续执行后续任务。")
            return True
        time.sleep(interval)
        waited += interval
    print(f"等待超时：{result_csv_path} 仍未生成。")
    return False

def process_result_csv(
    input_file='CloudflareScanner/result.csv',
    proxyip_file='proxyip.txt',
    with_country_file='proxyip_with_country.txt',
    countries_file='countries.txt',
    RETRY=10
):
    if not os.path.isfile(input_file):
        print('未找到 CloudflareScanner/result.csv，请确认 CloudflareScanner.exe 已成功运行并生成此文件。')
        sys.exit(1)
    # 加载国家代码-中文名字典
    country_dict = {}
    with open(countries_file, 'r', encoding='utf-8') as f:
        for line in f:
            parts = line.strip().split(',')
            if len(parts) >= 2:
                code = parts[0].strip()
                name = parts[1].strip()
                country_dict[code] = name

    # 步骤1：筛选Download Speed (MB/s) > 10的IP，保存到proxyip.txt，并记住速度
    valid_infos = []
    with open(input_file, 'r', encoding='utf-8') as csvfile:
        first_line = csvfile.readline()
        csvfile.seek(0)
        delimiter = '\t' if '\t' in first_line else ','
        reader = csv.DictReader(csvfile, delimiter=delimiter)
        for row in reader:
            try:
                speed = float(row.get('Download Speed (MB/s)', '0').strip())
                if speed > 10:
                    ip = row.get('IP Address', '').strip()
                    if ip:
                        valid_infos.append({'ip': ip, 'speed': speed})
            except Exception as e:
                print(f"Error parsing row: {row}, error: {e}")

    with open(proxyip_file, 'w', encoding='utf-8') as outfile:
        for info in valid_infos:
            outfile.write(info['ip'] + '\n')
    print(f"筛选完成，共输出 {len(valid_infos)} 个IP到 {proxyip_file}")

    # 步骤2：查询国家信息并根据字典格式化输出
    def get_country(ip):
        for attempt in range(RETRY):
            try:
                url = f'https://ipinfo.io/{ip}/json'
                resp = requests.get(url, timeout=5)
                data = resp.json()
                if 'country' in data:
                    return data['country']
                else:
                    print(f"{ip} 未返回国家，响应内容：{data}")
            except Exception as e:
                print(f"第 {attempt+1} 次获取 {ip} 国家信息失败，错误：{e}")
            time.sleep(1)  # 每次重试间隔
        return 'Unknown'

    with open(with_country_file, 'w', encoding='utf-8') as outfile:
        for info in valid_infos:
            ip = info['ip']
            speed = info['speed']
            country_code = get_country(ip)
            country_name = country_dict.get(country_code, country_code)
            # 输出格式：IP#速度(MB/s)国家代码国家中文名
            line = f"{ip}#{speed:.2f}(MB/s){country_code}{country_name}\n"
            outfile.write(line)
            print(line.strip())

    print(f"查询国家并格式化输出完成，共输出 {len(valid_infos)} 个IP到 {with_country_file}")

if __name__ == "__main__":
    os.makedirs("ips_with_country", exist_ok=True)
    os.makedirs("ips", exist_ok=True)

    country_mapping = load_country_mapping("countries.txt")
    if not country_mapping:
        print("未加载有效国家信息，程序退出。")
        exit()

    all_ips_with_country = "ips_with_country/all_ips_with_country.txt"

    collect_all_ips("Manual_input_IP.txt", "domains.txt", all_ips_with_country)
    detect_all_ip_country(all_ips_with_country, all_ips_with_country, country_mapping)
    extract_ips_from_file(all_ips_with_country, "ips/all_ips.txt")
    filter_ips_by_allowed_countries(
        input_file=all_ips_with_country,
        allowed_countries_file="allowed_countries.txt",
        allowed_ip_file="ips/allowed_ips.txt",
        blocked_ip_file="ips/blocked_ips.txt",
        allowed_with_info_file="ips_with_country/allowed_ips_with_country.txt",
        blocked_with_info_file="ips_with_country/blocked_ips_with_country.txt",
        unreachable_ip_file="ips/unreachable_ips.txt",
        unreachable_with_info_file="ips_with_country/unreachable_ips_with_country.txt",
    )
    save_ip_txt_for_cloudflarescanner(
        allowed_ip_file="ips/allowed_ips.txt",
        target_path="CloudflareScanner/ip.txt"
    )
    run_cloudflarescanner_with_dn()
    result_csv = 'CloudflareScanner/result.csv'
    if not wait_for_result_csv(result_csv, timeout=600, interval=2):
        sys.exit(1)
    process_result_csv(
        input_file='CloudflareScanner/result.csv',
        proxyip_file='proxyip.txt',
        with_country_file='proxyip_with_country.txt',
        countries_file='countries.txt',
        RETRY=10
    )
