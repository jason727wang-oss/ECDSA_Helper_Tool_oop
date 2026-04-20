import re
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature


def get_curve_settings(curve_name):
    if curve_name == "P-256":
        return ec.SECP256R1(), hashes.SHA256(), 32
    elif curve_name == "P-384":
        return ec.SECP384R1(), hashes.SHA384(), 48
    return ec.SECP256R1(), hashes.SHA256(), 32


def only_hex_filter(text):
    return re.sub(r'[^0-9a-fA-F]', '', text)


def convert_sig(sig_hex, target_fmt, curve_name):
    """轉換簽章格式，若失敗則拋出異常"""
    sig_bytes = bytes.fromhex(only_hex_filter(sig_hex))
    curve, _, bl = get_curve_settings(curve_name)

    if target_fmt == "RS Raw":
        # 原本是 DER -> 轉 Raw
        r, s = decode_dss_signature(sig_bytes)
        return (r.to_bytes(bl, "big") + s.to_bytes(bl, "big")).hex()
    else:
        # 原本是 Raw -> 轉 DER
        if len(sig_bytes) != 2 * bl:
            raise ValueError("Length mismatch")
        r = int.from_bytes(sig_bytes[:bl], "big")
        s = int.from_bytes(sig_bytes[bl:], "big")
        return encode_dss_signature(r, s).hex()