import os
from enum import Enum

from pydantic import field_validator, ValidationInfo

from wazuh.core.config.models.base import WazuhConfigBaseModel


class SSLProtocol(str, Enum):
    """Enum representing supported SSL/TLS protocols."""
    tls = "TLS"
    tls_v1 = "TLSv1"
    tls_v1_1 = "TLSv1.1"
    tls_v1_2 = "TLSv1.2"
    auto = "auto"


class SSLConfig(WazuhConfigBaseModel):
    """Configuration for SSL settings specific to the server.

    Parameters
    ----------
    key : str
        The path to the SSL key file.
    cert : str
        The path to the SSL certificate file.
    ca : str
        The path to the CA certificate file.
    keyfile_password : str
        The password for the SSL key file. Default is an empty string.
    """
    key: str
    cert: str
    ca: str
    keyfile_password: str = ""


class IndexerSSLConfig(WazuhConfigBaseModel):
    """Configuration for SSL settings specific to the indexer.

    Parameters
    ----------
    use_ssl : bool
        Whether to use SSL for the indexer. Default is False.
    key : str
        The path to the SSL key file. Default is an empty string.
    cert : str
        The path to the SSL certificate file. Default is an empty string.
    ca : str
        The path to the CA certificate file. Default is an empty string.
    verify_certificates : bool
        Whether to verify the server TLS certificates or not. Default is True.
    """
    use_ssl: bool = False
    key: str = ''
    cert: str = ''
    ca: str = ''
    verify_certificates: bool = True

    @field_validator('key', 'cert', 'ca')
    @classmethod
    def validate_ssl_files(cls, path: str, info: ValidationInfo) -> str:
        """Validate that the SSL files exist.
        
        Parameters
        ----------
        path : str
            Path to the SSL certificate/key.
        info : ValidationInfo
            Validation context information.
        
        Raises
        ------
        ValueError
            Invalid SSL file path.

        Returns
        ------
        str
            SSL certificate/key path.
        """
        if info.data['use_ssl']:
            if path == '':
                raise ValueError(f'{info.field_name}: missing certificate file')

            if not os.path.isfile(path):
                raise ValueError(f"{info.field_name}: the file '{path}' does not exist")
        
        return path


class APISSLConfig(WazuhConfigBaseModel):
    """Configuration for API SSL settings.

    Parameters
    ----------
    key : str
        The path to the SSL key file.
    cert : str
        The path to the SSL certificate file.
    use_ca : bool
        Whether to use a CA certificate. Default is False.
    ca : str
        The path to the CA certificate file. Default is an empty string.
    ssl_protocol : Literal["TLS", "TLSv1", "TLSv1.1", "TLSv1.2", "auto"]
        The SSL protocol to use. Default is "auto".
    ssl_ciphers : str
        The SSL ciphers to use. Default is an empty string.
    """
    key: str
    cert: str
    use_ca: bool = False
    ca: str = ""
    ssl_protocol: SSLProtocol = SSLProtocol.auto
    ssl_ciphers: str = ""

