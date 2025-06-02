CREATE TABLE signature_verification (
    verification_id INT AUTO_INCREMENT PRIMARY KEY,
    signature_gen_id INT NOT NULL, -- Links to the signature being verified
    verified_by_user_id INT NOT NULL, -- User who performed verification
    
    -- Verification intermediate values (recalculated during verification)
    verify_first_intermediate_value int NOT NULL,
    verify_second_intermediate_value int NOT NULL,
    verify_third_intermediate_value int NOT NULL,
    verify_fourth_intermediate_value int NOT NULL,
    
    -- Verification hash and comparison values
    verify_z_value int NOT NULL,
    verify_h1_value int NOT NULL,
   
    
    -- Verification results
    verification_result ENUM('valid', 'invalid', 'error') NOT NULL,
    confidence_score DECIMAL(5,4) DEFAULT 1.0000, -- 0.0000 to 1.0000
    

    -- Error handling
    error_code VARCHAR(20) NULL,
    error_description TEXT NULL,
    
    -- Foreign keys
    FOREIGN KEY (signature_gen_id) REFERENCES signature_generation(signature_gen_id) ON DELETE CASCADE,
    FOREIGN KEY (verified_by_user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    
    -- Indexes
    INDEX idx_signature_gen_id (signature_gen_id),
    INDEX idx_verified_by (verified_by_user_id),
    INDEX idx_verification_result (verification_result)
);