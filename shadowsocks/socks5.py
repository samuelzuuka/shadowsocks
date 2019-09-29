# -*- coding: UTF-8 -*-
#
#  这个文件封装了 SOCK5 协议相关的
#

#
#
#    SOCK5 PROTOCAL PROCESS

#                   认证过程::
#
#    1. 客户端发出请求
#    +----+--------------+----------+
#    |VER | METHOD_COUNT | METHODS  |   -> 段定义
#    +----+--------------+----------+
#    | 1  |    1         | 1 to 255 |   -> 字节长度
#    +----+--------------+----------+
#
#    举例:
#    \x05 \x02 \x00 \x02
#
#    VER:
#       固定  X'05'
#    METHOD_COUNT:
#       方法的数量,二进制格式
#    METHODS:
#       客户端支持的认证方式列表,可填写多个，每个占用1个字节，具体方式参照下面定义
#
#
#    2. 服务端回复认证方式
#
#     +----+--------+
#     |VER | METHOD |
#     +----+--------+
#     | 1  |   1    |
#     +----+--------+
#    举例:
#     \x05 \x00
#
#    VER
#    固定  X'05'
#    METHOD
#    o  X'00' NO AUTHENTICATION REQUIRED
#    o  X'01' GSSAPI
#    o  X'02' USERNAME/PASSWORD
#    o  X'03' to X'7F' IANA ASSIGNED
#    o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
#    o  X'FF' NO ACCEPTABLE METHODS

import common

SOCKS5_AUTH_METHODS = {
    'NO_AUTH': '\x00',
    'AUTH_GSSAPI': '\x01',
    'AAUTH_USER_PASS': '\x02',
    'AUTH_IANA': 'AUTH_IANA',
    'AUTH_PRIVATE': 'AUTH_PRIVATE',
    'AUTH_NON_SUPPORTS': 0xff
}

SOCKS5_VERSION = '\x05'

# socks5 规范的命令
SOCKS5_COMMANDS = {
    'COMMAND_CONNECT': '\x01',
    'COMMAND_BIND' : '\x02',
    'COMMAND_UDP_ASSOCIATE' : '\x03'
}

# socks5 规范的回复
SOCKS5_COMMAND_RESPONSES = {
    'RESPONSE_SUCCESS': '\x00',
    'RESPONSE_PROXY_ERR': '\x01',
    'RESPONSE_PROXY_AUTH_ERR': '\x02',
    'RESPONSE_NET_ERR': '\x03',
    'RESPONSE_DST_UNREACHABLE_ERR': '\x04',
    'RESPONSE_DST_DENIED_ERR': '\x05',
    'RESPONSE_TTL_INVALID_ERR': '\x06',
    'RESPONSE_INVALID_COMMAND_ERR': '\x07',
    'RESPONSE_INVALID_DST_ADDR_TYPE_ERR': '\x08',
    'RESPONSE_COMMON_ERR': '\xff',
}

# socks5 规范的地址类型
SOCKS5_ADDR_TYPES = {
    'ATYPE_IPV4' : '\x01',
    'ATYPE_DOMAIN' : '\x03',
    'ATYPE_IPV6' : '\x04'
}

class SOCKS5(object):


    # 10进制整型数字转换成 二进制的打印字符串
    @staticmethod
    def oct_to_socks5_hex(oct_num):
        hs = hex(int(oct_num))[2:]
        if len(hs) % 2 == 1:
            hs = '0' + hs
        return r'\x' + hs

    # 10进制整型数字转换成 传输的二进制表示
    @staticmethod
    def oct_to_socks5_hexbin(oct_num, bit=1):
        # hs = hex(int(oct_num))[2:]
        # if len(hs) % 2 == 1:
        #     hs = '0' + hs
        # return hs
        return str(oct_num).encode()

    # 将任意的字符串转换为 二进制的打印字符串
    @staticmethod
    def string_to_socks5_hex(ss):
        return ''.join([(SOCKS5.oct_to_socks5_hexbin(ord(c))) for c in ss])

    # 将 16进制的字符串转换成 socks5格式的hex字符串
    # 0x 0x -> \x
    @staticmethod
    def hexstr_to_socks5_hex(hexstr):
        if hexstr is not None:
            if hexstr[:2] == '0x' or hexstr[:2] == '0X':
                return r'\x' + hexstr[2:]
            else:
                return r'\x' + hexstr

    # 将从socket中读取的字符串（可能是二进制）转换成 二进制字符串的打印格式
    @staticmethod
    def socks5_data_to_bin_str(data=''):
        ss = ''
        for v in bytearray(data):
            s = format(v)
            ss = ss + SOCKS5.oct_to_socks5_hex(int(s))
        return ss

    @staticmethod
    def client_auth_req(method_count=0, methods='\x00'):
        return SOCKS5_VERSION + SOCKS5.oct_to_socks5_hex(method_count) + methods

    # +-----+--------+
    # | VER | METHOD |
    # +-----+--------+
    # | 1   | 1      |
    # +-----+--------+
    #
    @staticmethod
    def client_auth_resp(method_list=[SOCKS5_AUTH_METHODS['NO_AUTH']]):
        return SOCKS5_VERSION + ''.join(method_list)

    # +----+-----+-------+------+----------+----------+
    # |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    # +----+-----+-------+------+----------+----------+
    # | 1  |  1  | X'00' |  1   | Variable |    2     |
    # +----+-----+-------+------+----------+----------+
    # @param command SOCKS5_COMMANDS
    # @param addr_type SOCKS5_ADDR_TYPES
    # @param addr ipv4: 127.0.0.1 ; domain: google.com ; ipv6: 12.23.45.67.12.23.45.67.12.23.45.67.12.23.45.67
    @staticmethod
    def client_command_req(command, addr_type, addr, port):
        addr_str = ''
        if addr_type == SOCKS5_ADDR_TYPES['ATYPE_IPV4'] or addr_type == SOCKS5_ADDR_TYPES['ATYPE_IPV6']:
            addr_arr = addr.split('.')
            for s in addr_arr:
                addr_str = addr_str + SOCKS5.oct_to_socks5_hex(s)
        elif addr_type == SOCKS5_ADDR_TYPES['ATYPE_DOMAIN']:
            addr_str = SOCKS5.string_to_socks5_hex(addr)
        port_str = SOCKS5.oct_to_socks5_hex(port)
        return SOCKS5_VERSION + command + '\x00' \
               + addr_type + addr_str + port_str

    # +-----+-----+-------+------+----------+----------+
    # | VER | REP | RSV   | ATYP | BND.ADDR | BND.PORT |
    # +-----+-----+-------+------+----------+----------+
    # | 1   | 1   | X'00' | 1    | Variable | 2        |
    # +----+-----+-------+------+----------+-----------+
    @staticmethod
    def client_command_resp(addr, port, response=SOCKS5_COMMAND_RESPONSES['RESPONSE_SUCCESS']):

        addr_str = common.pack_addr(addr)
        # addr_str = ''
        # if addr_type == SOCKS5_ADDR_TYPES['ATYPE_IPV4'] or addr_type == SOCKS5_ADDR_TYPES['ATYPE_IPV6']:
        #     addr_arr = addr.split('.')
        #     # for s in addr_arr:
        #     #     addr_str = addr_str + SOCKS5.oct_to_socks5_hexbin
        #     addr_arr = [int(s) for s in addr_arr]
        #     addr_str = bytearray(addr_arr)
        # elif addr_type == SOCKS5_ADDR_TYPES['ATYPE_DOMAIN']:
        #     addr_str = addr.encode()

        port = hex(port)
        port_str = bytearray.fromhex(port.replace('0x', ''))
        return SOCKS5_VERSION + response + '\x00' + addr_str + port_str
