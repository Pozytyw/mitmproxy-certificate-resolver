import logging

from OpenSSL import SSL
from OpenSSL.crypto import X509

from mitmproxy.net import tls as net_tls
from mitmproxy import tls
from mitmproxy import ctx
from mitmproxy import addonmanager

def load(loader: addonmanager.Loader): 
    addon_manager = ctx.master.addons
    for addon in addon_manager.chain:
        if _type_check(addon, CertificateResolver._ID):
            logging.info('remove old instant - ' + type(addon).__name__)
            addon_manager.remove(addon) 
    logging.info('loading tls certificate resolver')
    addon_manager.chain.append(addon_manager.register(CertificateResolver()))

def _type_check(a, id):
    return hasattr(a, '_ID') and a._ID == id

class CertificateResolver:
    _ID = 7048979731245

    def tls_start_client(self, tls_ctx: tls.TlsData):
        logging.info('---------------------------------------------------------')
        logging.warn('SSL connection with client started')
        ssl = tls_ctx.ssl_conn
        if ssl is None:
            logging.warn('SSL connection should be initialized')
            return
        ssl.set_verify(net_tls.Verify.VERIFY_PEER.value, accept_all)

    def tls_established_client(self, tls_ctx: tls.TlsData):
        logging.info(self.get_cn_data(tls_ctx.ssl_conn.get_certificate()))
        logging.info(self.get_cn_data(tls_ctx.ssl_conn.get_peer_certificate()))
        logging.warn('SSL connection was established with client')
        logging.info('---------------------------------------------------------')

    def tls_start_server(self, tls_ctx: tls.TlsData):
        logging.info('---------------------------------------------------------')
        logging.warn('SSL connection with server started')

    def tls_established_server(self, tls_ctx: tls.TlsData): 
        logging.info(self.get_cn_data(tls_ctx.ssl_conn.get_certificate()))
        logging.info(self.get_cn_data(tls_ctx.ssl_conn.get_peer_certificate()))
        logging.warn('SSL connection was established with server')
        logging.info('---------------------------------------------------------')

    def get_cn_data(self, cert):
        if cert is None:
            return None
        return str(cert.get_subject())


def accept_all(
    conn_: SSL.Connection,
    x509: X509,
    errno: int,
    err_depth: int,
    is_cert_verified: int,
) -> bool:
    # Return true to prevent cert verification error
    return True
