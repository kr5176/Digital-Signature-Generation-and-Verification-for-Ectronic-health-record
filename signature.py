# signature.py
"""
High-level signing operations used by app.py. All real cryptography lives in
crypto_core.py (real elliptic-curve point math, not modular-multiplication-
mod-N, which made the original project's private keys trivially recoverable).
"""
import crypto_core as cc


def generate_user_keypair():
    """
    Called once at registration time. Returns (private_scalar_int, public_key_hex).
    The caller is responsible for encrypting the private scalar before storing it
    (see crypto_core.encrypt_private_scalar) and storing the public key in the clear.
    """
    priv, pub_point = cc.generate_keypair()
    return priv, cc.point_to_hex(pub_point)


def sign_file(user_id, file_id, file_content, user_priv_int, app_priv_int, app_pub_hex):
    """
    Signs `file_content` on behalf of `user_id` for `file_id`, using the
    user's real persistent private key and the app's real persistent
    keypair. A fresh ephemeral nonce keypair is generated internally for
    this call only and is never returned or persisted.

    Returns a dict of public values safe to store and to send to the client:
      file_content_hash, R, R_blinded, final_hash, user_pub, app_pub
    """
    if not isinstance(file_content, (bytes, bytearray)):
        raise TypeError("file_content must be bytes")

    file_hash_hex = cc.sha256_hex(file_content)
    app_pub_point = cc.hex_to_point(app_pub_hex)

    result = cc.create_signature(
        user_id=user_id,
        file_id=file_id,
        file_hash_hex=file_hash_hex,
        user_priv=user_priv_int,
        app_priv=app_priv_int,
        app_pub=app_pub_point,
    )
    result["file_content_hash"] = file_hash_hex
    return result
