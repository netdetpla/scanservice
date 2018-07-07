import base64
import os
import subprocess
import json
import traceback
import xml.etree.ElementTree as ET
import urllib.request as urllib2

import config
import log
import is_connect
import process
import utils

# 任务id
task_id = ''
# 子任务id
subtask_id = ''
# 获取进度id
pro_uuid = ''
# 任务名称
task_name = ''
# 是否需要探测os、服务版本
extra_info = ''
# 目标端口, 0为全部
target_port = ''
# 结果列表
host_list = {}
# 白名单(0) or 云平台(1)
platform = ''
# nmap探测策略
strategy = ''
# ip列表
ip_list = ''
# only nmap mode
mode = ''


# 端口类
class Port:
    def __init__(self, port, protocol, status):
        self.port = port
        # TCP or UDP
        self.protocol = protocol
        # 端口状态
        self.status = status
        # 端口服务
        self.service = ''
        # 软件名称
        self.product = ''
        # 软件版本
        self.version = ''

    def to_dict(self):
        return {
            'port': self.port,
            'protocol': self.protocol,
            #'status': self.status,
            'service': self.service,
            'product': self.product,
            'version': self.version
        }


# 目标类
class Host:
    def __init__(self, ip):
        self.ip = ip
        self.ports = {}
        # 设备类型
        self.hardware = ''
        # OS及版本
        self.os_version = ''

    def to_dict(self):
        temp_ports = []
        for port in self.ports:
            temp_ports.append(self.ports[port].to_dict())
        return {
            "ip": self.ip,
            "ports": temp_ports,
            "hardware": self.hardware,
            "os_version": self.os_version
        }


# 获取配置
def get_config():
    global task_id
    global task_name
    global pro_uuid
    global subtask_id
    global target_port
    global extra_info
    global platform
    global strategy
    global ip_list
    global mode
    with open(config.CONFIG_FILE, 'r') as f:
        task = str(base64.b64decode(f.read())).split(';')
        task_id = task[0][2:]
        pro_uuid = task[8][:-1]
        task_name = task[1]
        platform = task[2]
        target_port = task[3]
        extra_info = task[4]
        mode = task[5]
        strategy = task[6].split(',')
        ip_list = task[7]
        with open(config.TARGET_LIST, 'w') as f:
            f.write(ip_list)
        if os.path.getsize(config.TARGET_LIST) <= 0 or len(target_port) <= 0:
            e = 'No target IP or port.'
            log.get_conf_fail()
            log.write_error_to_appstatus(e, 3)


# 使用masscan扫描
def masscan():
    if platform == '1':
        process = os.popen("route | grep '172' | grep 'tap' |head -n 1| awk '{print $8}' ")  # return file
        output = process.read()
        output = ' -e ' + output[:-1]
        process.close()
    else:
        output = ''

    command = (
        '{masscan} -iL {target}{output} -p{ports} -pU:{ports} -oJ {mid_json} --rate 1000 --exclude 10.0.0.0/8,192.168.0.0/16,172.16.0.0/12,127.0.0.1/8,0.0.0.0/8'
    ).format(
        masscan=config.MASSCAN,
        target=config.TARGET_LIST,
        output=output,
        mid_json=config.MASSCAN_JSON,
        ports=target_port
    )
    subprocess.call([command], shell=True)
    try:
        with open(config.MASSCAN_JSON, 'r') as f:
            temp = f.read().replace(" ", "").replace("\n", "")
            print('temp: ' + temp)
    except FileNotFoundError:
        temp = ''
    if len(temp):
        masscan_json = json.loads(temp[:-2] + temp[-1])
    else:
        masscan_json = []

    for item in masscan_json:
        ip = item['ip']
        for item_port in item['ports']:
            port_ins = Port(item_port['port'], item_port['proto'], item_port['status'])
            try:
                host_list[ip].ports[str(item_port['port']) + '/' + item_port['proto']] = port_ins
            except KeyError:
                host_list[ip] = Host(ip)
                host_list[ip].ports[str(item_port['port']) + '/' + item_port['proto']] = port_ins


# 生成nmap需要文件
def generate_nmap_input():
    try:
        os.makedirs(config.NMAP_INPUT)
    except FileExistsError:
        pass
    for host in host_list:
        content = ''
        for port in host_list[host].ports:
            content += '{port} {proto}\n'.format(
                port=host_list[host].ports[port].port,
                proto=host_list[host].ports[port].protocol)
        with open(os.path.join(config.NMAP_INPUT, host), 'w') as f:
            f.write(content)


# nmap
def shell_nmap():
    own_command = 'chmod +777 {shell_file}'.format(shell_file=config.NMAP_SHELL)
    subprocess.call([own_command], shell=True)
    count = 0
    shell_command = './test.sh {extra}'.format(
        extra=extra_info
    )
    for host in host_list:
        if count >= config.NMAP_COUNT:
            subprocess.call([shell_command], shell=True)
            count = 0
        content = ''
        for port in host_list[host].ports:
            content += '{port} {proto}\n'.format(
                port=host_list[host].ports[port].port,
                proto=host_list[host].ports[port].protocol)
        count += 1
    subprocess.call([shell_command], shell=True)


# 含有扫描策略
def nmap():
    global nmap_ip
    nmap_ip = []   
    for ips in ip_list.split(','):
        nmap_ip += utils.ip_format(ips)
    if extra_info == '1':
        os_check = ' -O'
    else:
        os_check = ''
    if mode == '1':
        port_opt = ''
    else:
        port_opt = '-p ' + target_port
    command = 'nmap {target} {os_check} {ports} --open -oX {filename}'
    for ip in nmap_ip:
        subprocess.call([command.format(
            target=ip,
            os_check=os_check,
            ports=port_opt,
            filename=ip.replace('/', '-') + '.xml'
        )], shell=True)


# 策略nmap结果回收
def get_nmap_result():
    port_key = '{port_id}/{proto}'
    for ip in nmap_ip:
        filename = ip.replace('/', '-') + '.xml'
        with open(filename, 'r') as f:
            xml = ET.ElementTree(file=f)
        host_eles = xml.findall('.//host')
        for host_ele in host_eles:
            host = host_ele.find('./address').attrib['addr']
            host_ins = host_list[host] = Host(host)
            ports_ele = xml.findall('.//port')
            for port_ele in ports_ele:
                port_id = port_ele.attrib['portid']
                proto = port_ele.attrib['protocol']
                port = host_ins.ports[port_key.format(port_id=port_id, proto=proto)] = Port(port_id, proto, '')
                port.status = port_ele.find('./state').attrib['state']
                service_ele = port_ele.find('./service')
                try:
                    port.service = service_ele.attrib['name']
                except (KeyError, AttributeError):
                    port.service = 'unknown'
                try:
                    port.product = service_ele.attrib['product']
                    print('product: ' + port.product)
                except (KeyError, AttributeError):
                    port.product = 'unknown'
                try:
                    port.version = service_ele.attrib['version']
                    print('version: ' + port.version)
                except (KeyError, AttributeError):
                    port.version = 'unknown'
            if extra_info == '1':
                os_ele = xml.findall('.//osmatch')
                if os_ele is None:
                    return
                if host_ins.os_version == '':
                    try:
                        host_ins.os_version = os_ele[0].attrib['name']
                    except (KeyError, IndexError):
                        host_ins.os_version = 'unknown'
                if host_ins.hardware == '':
                    try:
                        host_ins.hardware = os_ele[0].find('./osclass').attrib['type']
                    except (KeyError, IndexError):
                        host_ins.hardware = 'unknown'

    result = []
    for host in host_list:
        result.append(host_list[host].to_dict())
    return {
        'task_id': task_id,
        'subtask_id': subtask_id,
        'task_name': task_name,
        'result': result
    }


# xml 解析
def xml_handle(host, proto):
    file_name = '{host}-{proto}.xml'.format(host=host, proto=proto)
    with open(file_name, 'r') as f:
        xml = ET.ElementTree(file=f)
    ports_ele = xml.findall('.//port')
    host_ins = host_list[host]
    port_key = '{port_id}/{proto}'
    for port_ele in ports_ele:
        port_id = port_ele.attrib['portid']
        port = host_ins.ports[port_key.format(port_id=port_id, proto=proto)]
        port.status = port_ele.find('./state').attrib['state']
        service_ele = port_ele.find('./service')
        try:
            port.service = service_ele.attrib['name']
        except (KeyError, AttributeError):
            port.service = 'unknown'
        try:
            port.product = service_ele.attrib['product']
            print('product: ' + port.product)
        except (KeyError, AttributeError):
            port.product = 'unknown'
        try:
            port.version = service_ele.attrib['version']
            print('version: ' + port.version)
        except (KeyError, AttributeError):
            port.version = 'unknown'
    if extra_info == '1':
        os_ele = xml.findall('.//osmatch')
        if os_ele is None:
            return
        if host_ins.os_version == '':
            try:
                host_ins.os_version = os_ele[0].attrib['name']
            except (KeyError, IndexError):
                host_ins.os_version = 'unknown'
        if host_ins.hardware == '':
            try:
                host_ins.hardware = os_ele[0].find('./osclass').attrib['type']
            except (KeyError, IndexError):
                host_ins.hardware = 'unknown'


# nmap结果回收
def get_result():
    for host in host_list:
        try:
            xml_handle(host, 'tcp')
        except FileNotFoundError:
            pass
        try:
            xml_handle(host, 'udp')
        except FileNotFoundError:
            pass
    result = []
    for host in host_list:
        result.append(host_list[host].to_dict())
    return {
        'task_id': task_id,
        'subtask_id': subtask_id,
        'task_name': task_name,
        'result': result
    }


if __name__ == '__main__':
    log.task_start()
    try:
        os.makedirs(config.LOG_FILE)
    except FileExistsError:
        pass
    try:
        os.makedirs(config.APP_STATUS)
    except FileExistsError:
        pass
    try:
        os.makedirs(config.RESULT_FILE)
    except FileExistsError:
        pass
    # 判断网络
    # if not is_connect.NetCheck('114.114.114.114'):
    #     log.task_fail()
    #     log.write_result_fail()
    #     e = 'Can not connect to the Internet.'
    #     print(e)
    #     write_error_to_appstatus(e)
    #     sys.exit(-1)
    is_connect.Update()
    log.get_conf()
    try:
        get_config()
        log.get_conf_success()
    except Exception as e:
        log.get_conf_fail()
        log.write_error_to_appstatus(str(e), -1)
    # 计次初始化
    processer = process.processManager()
    processer.set_taskid(task_id, pro_uuid)
    # 执行任务
    log.task_run()
    try:
        try:
            strategy_strs = ' '.join([config.NMAP_STRATEGY[int(si)] for si in strategy])
        except ValueError:
            strategy_strs = ''
        if strategy_strs == '' and mode == '0':
            masscan()
            generate_nmap_input()
            shell_nmap()
        else:
            nmap()
    except Exception as e:
        traceback.print_exc()
        result = ''
        log.task_fail()
        log.write_error_to_appstatus(str(e), -1)
        strategy_strs = ''

    # 计次结束
    processer.resultCreate()
    processer.final_send()
    # 写结果
    log.write_result()
    try:
        if strategy_strs == '' and mode == '0':
            result = get_result()
        else:
            result = get_nmap_result()
        with open(os.path.join(config.RESULT_FILE, task_id + '.result'), 'w') as f:
            json.dump(result, f)
        log.write_result_success()
    except Exception as e:
        traceback.print_exc()
        log.write_result_fail()
        log.write_error_to_appstatus(str(e), -1)
    log.task_success()
    log.write_success_to_appstatus()
