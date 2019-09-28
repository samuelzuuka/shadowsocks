# 
#  这个文件封装了 SOCK5 协议相关的
# 



SOCKS5_AUTH_METHODS = {
    NO_AUTH: 'POLL_NULL',
    AUTH_GSSAPI: 'POLL_IN',
    AAUTH_USER_PASS: 'POLL_OUT',
    AUTH_IANA : 'POLL_ERR',
    AUTH_PRIVATE: 'POLL_HUP',
    AUTH_NON_SUPPORTS : 'POLL_NVAL',
}

SOCKS5_VERSION = '\x05'

class SOCKS5(object):

    @staticmethod
    def client_send_auth(self, method_count=0, methods = '\x00'):
        return SOCKS5_VERSION + '\x' + hex(method_count) + methods

    @staticmethod
    def to_socks5_hex(self, oct_num):
        return '\x' + hex(oct_num)[2:]

    @staticmethod
    def socks5_data_to_str(self, data):
        pass