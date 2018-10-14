"""
配置信息
"""

# 任务位置文件
CONFIG_FILE = '/tmp/conf/busi.conf'
# 任务状态文件位置
APP_STATUS = '/tmp/appstatus'
# log位置
LOG_FILE = '/tmp/log'
# result位置
RESULT_FILE = '/tmp/result'
# 目标列表文件
TARGET_LIST = '/target'
# masscan位置
MASSCAN = '/masscan/bin/masscan'
# masscan输出
MASSCAN_JSON = 'mid_json'
# nmap输入文件路径
NMAP_INPUT = '/nmap_data'
# nmap shell脚本
NMAP_SHELL = '/test.sh'
# nmap 运行数量
NMAP_COUNT = 50
# 探测策略
NMAP_STRATEGY = [
    '-Pn -D192.168.128.64,10.85.123.44,172.168.13.15,ME',
    '--max-scan-delay 10s',
    '-sT',
    '-sS',
    '--scanflags RST',
    '-sA',
    '-sN',
    '-sF',
    '-sX',
    '-sU'
]
# 不兼容策略
TCP_STRATEGY = [2, 3, 5, 6, 7, 8]