
import crypto_core as cc


def generate_user_keypair():
  
    priv, pub_point = cc.generate_keypair()
    return priv, cc.point_to_hex(pub_point)


def sign_file(user_id, file_id, file_content, user_priv_int, app_priv_int, app_pub_hex):
  
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
