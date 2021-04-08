import json
import logging
import time
import warnings
import requests

# from ..exceptions import (
#     ConnectionError,
#     ImproperlyConfigured,
#     ConnectionTimeout,
#     SSLError,
# )

from urllib.parse import quote, quote_plus, urlencode, urlparse, unquote
string_types = str, bytes

logger = logging.getLogger("opensearch")

class OpenSearch:
    """
    Connection using the `requests` library.

    :arg http_auth: optional http auth information as either ':' separated
        string or a tuple. Any value will be passed into requests as `auth`.
    :arg use_ssl: use ssl for the connection if `True`
    :arg verify_certs: whether to verify SSL certificates
    :arg ssl_show_warn: show warning when verify certs is disabled
    :arg ca_certs: optional path to CA bundle. By default standard requests'
        bundle will be used.
    :arg client_cert: path to the file containing the private key and the
        certificate, or cert only if using client_key
    :arg client_key: path to the file containing the private key if using
        separate cert and key files (client_cert will contain only the cert)
    :arg headers: any custom http headers to be add to requests
    :arg cloud_id: The Cloud ID from ElasticCloud. Convient way to connect to cloud instances.
    :arg api_key: optional API Key authentication as either base64 encoded string or a tuple.
        Other host connection params will be ignored.
    """

    def __init__(
            self,
            host="localhost",
            port=9200,
            http_auth=None,
            use_ssl=False,
            verify_certs=True,
            ssl_show_warn=True,
            ca_certs=None,
            client_cert=None,
            client_key=None,
            headers=None,
            cloud_id=None,
            api_key=None,
            **kwargs
    ):
        # if not REQUESTS_AVAILABLE:
        #     raise ImproperlyConfigured(
        #         "Please install requests to use OpenSearch."
        #     )

        # super(OpenSearch, self).__init__(
        #     host=host, port=port, use_ssl=use_ssl, **kwargs
        # )
        self.session = requests.Session()
        self.session.headers = headers or {}
        self.session.headers.setdefault("content-type", "application/json")
        # self.session.headers.setdefault("user-agent", self._get_default_user_agent())
        if http_auth is not None:
            if isinstance(http_auth, (tuple, list)):
                http_auth = tuple(http_auth)
            elif isinstance(http_auth, string_types):
                http_auth = tuple(http_auth.split(":", 1))
            self.session.auth = http_auth

        self.base_url = "http%s://%s:%d%s" % (
            "s" if use_ssl else "",
            host,
            port,
            "",  # TODO
        )
        self.session.verify = verify_certs
        if not client_key:
            self.session.cert = client_cert
        elif client_cert:
            # cert is a tuple of (certfile, keyfile)
            self.session.cert = (client_cert, client_key)
        if ca_certs:
            if not verify_certs:
                raise ConnectionError(
                    "You cannot pass CA certificates when verify SSL is off."
                )
            self.session.verify = ca_certs

        if not ssl_show_warn:
            requests.packages.urllib3.disable_warnings()

        # if self.use_ssl and not verify_certs and ssl_show_warn:
        #     warnings.warn(
        #         "Connecting to %s using SSL with verify_certs=False is insecure."
        #         % self.base_url
        #     )

    def perform_request(
            self, method, url, params=None, body=None, timeout=10, ignore=(), headers=None
    ):
        url = self.base_url + url
        if params:
            url = "%s?%s" % (url, urlencode(params or {}))

        start = time.time()
        request = requests.Request(method=method, headers=headers, url=url, data=body)
        prepared_request = self.session.prepare_request(request)
        settings = self.session.merge_environment_settings(
            prepared_request.url, {}, None, None, None
        )
        send_kwargs = {"timeout": timeout}
        send_kwargs.update(settings)
        try:
            response = self.session.send(prepared_request, **send_kwargs)
            duration = time.time() - start
            raw_data = response.text
        except Exception as e:
            # self.log_request_fail(
            #     method,
            #     url,
            #     prepared_request.path_url,
            #     body,
            #     time.time() - start,
            #     exception=e,
            # )
            if isinstance(e, requests.exceptions.SSLError):
                raise requests.exceptions.SSLError("N/A", str(e), e)
            if isinstance(e, requests.Timeout):
                raise requests.Timeout("TIMEOUT", str(e), e)
            raise ConnectionError("N/A", str(e), e)

        # raise errors based on http status codes, let the client handle those if needed
        if (
                not (200 <= response.status_code < 300)
                and response.status_code not in ignore
        ):
            # self.log_request_fail(
            #     method,
            #     url,
            #     response.request.path_url,
            #     body,
            #     duration,
            #     response.status_code,
            #     raw_data,
            # )
            self._raise_error(response.status_code, raw_data)

        # self.log_request_success(
        #     method,
        #     url,
        #     response.request.path_url,
        #     body,
        #     response.status_code,
        #     raw_data,
        #     duration,
        # )

        return response.status_code, response.headers, raw_data

    def close(self):
        """
        Explicitly closes connections
        """
        self.session.close()

    def _raise_error(self, status_code, raw_data):
        """ Locate appropriate exception and raise it. """
        error_message = raw_data
        additional_info = None
        try:
            if raw_data:
                additional_info = json.loads(raw_data)
                error_message = additional_info.get("error", error_message)
                if isinstance(error_message, dict) and "type" in error_message:
                    error_message = error_message["type"]
        except (ValueError, TypeError) as err:
            logger.warning("Undecodable raw error response from server: %s", err)

        raise ConnectionError(
            status_code, error_message, additional_info
        )