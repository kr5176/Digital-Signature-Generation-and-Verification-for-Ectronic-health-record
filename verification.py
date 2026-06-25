# verification.py
import crypto_core as cc


def verify_digital_signature(file_content, user_id, file_id, user_pub_hex, app_pub_hex,
                              R_hex, R_blinded_hex, final_hash):
    
 
    if not isinstance(file_content, (bytes, bytearray)):
        raise TypeError("file_content must be bytes")

    file_hash_hex = cc.sha256_hex(file_content)

    try:
        return cc.verify_signature(
            user_id=user_id,
            file_id=file_id,
            file_hash_hex=file_hash_hex,
            user_pub_hex=user_pub_hex,
            app_pub_hex=app_pub_hex,
            R_hex=R_hex,
            R_blinded_hex=R_blinded_hex,
            final_hash=final_hash,
        )
    except (ValueError, TypeError):
     
        return False
