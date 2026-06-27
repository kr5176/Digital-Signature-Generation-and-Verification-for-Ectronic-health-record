SET FOREIGN_KEY_CHECKS = 0;

DROP DATABASE IF EXISTS signatureehr;
CREATE DATABASE signatureehr CHARACTER SET utf8mb4;
USE signatureehr;

CREATE TABLE users (
    user_id              VARCHAR(50)  NOT NULL,
    password_hash        VARCHAR(255) NOT NULL,
    role                 VARCHAR(20)  NOT NULL,
    user_public_key      VARCHAR(66)  NULL,   -- compressed secp256k1 point, hex
    user_private_key_enc TEXT         NULL,   -- Fernet-encrypted private scalar
    created_at           TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id),
    CONSTRAINT chk_role CHECK (role IN ('admin', 'patient'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE applications (
    app_id          VARCHAR(50) NOT NULL,
    app_public_key  VARCHAR(66) NOT NULL,
    PRIMARY KEY (app_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE files (
    file_id            VARCHAR(50)  NOT NULL,
    file_name          VARCHAR(255) NOT NULL,
    file_content_hash  VARCHAR(64)  NOT NULL,  -- sha256 of the actual file bytes
    user_public_key    VARCHAR(66)  NOT NULL,  -- signer's public key at time of signing
    app_id             VARCHAR(50)  NOT NULL,
    app_public_key     VARCHAR(66)  NOT NULL,  -- app's public key at time of signing
    r_value            VARCHAR(66)  NOT NULL,  -- Schnorr nonce commitment R, compressed point hex
    r_blinded          VARCHAR(66)  NOT NULL,  -- tamper-binding blinded R, compressed point hex
    final_hash         VARCHAR(64)  NOT NULL,  -- the actual "signature" check value
    uploaded_by        VARCHAR(50)  NULL,
    signed_at          TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (file_id),
    CONSTRAINT fk_files_uploaded_by
        FOREIGN KEY (uploaded_by) REFERENCES users (user_id)
        ON DELETE SET NULL
        ON UPDATE CASCADE,
    CONSTRAINT fk_files_app
        FOREIGN KEY (app_id) REFERENCES applications (app_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

SET FOREIGN_KEY_CHECKS = 1;

SHOW TABLES;
