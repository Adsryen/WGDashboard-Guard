import os


def get_tls_files(base_directory: str) -> dict[str, str]:
    ssl_directory = os.path.join(base_directory, "ssl")
    certificate_path = os.path.join(ssl_directory, "dashboard.crt")
    private_key_path = os.path.join(ssl_directory, "dashboard.key")
    certificate_exists = os.path.isfile(certificate_path)
    private_key_exists = os.path.isfile(private_key_path)

    if certificate_exists != private_key_exists:
        raise RuntimeError("Dashboard TLS certificate and private key must be configured together.")
    if not certificate_exists:
        return {}
    return {"certfile": certificate_path, "keyfile": private_key_path}
