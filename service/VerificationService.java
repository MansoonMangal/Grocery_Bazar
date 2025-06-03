package com.groceryBazar.service;

import com.groceryBazar.model.VerificationCode;

public interface VerificationService {

    VerificationCode createVerificationCode(String otp, String email);
}
