package com.groceryBazar.service;

import com.groceryBazar.exception.SellerException;
import com.groceryBazar.exception.UserException;
import com.groceryBazar.request.LoginRequest;
import com.groceryBazar.request.ResetPasswordRequest;
import com.groceryBazar.request.SignupRequest;
import com.groceryBazar.response.ApiResponse;
import com.groceryBazar.response.AuthResponse;

import jakarta.mail.MessagingException;

public interface AuthService {

    void sentLoginOtp(String email) throws UserException, MessagingException;
    String createUser(SignupRequest req) throws SellerException;
    AuthResponse signin(LoginRequest req) throws SellerException;

}
