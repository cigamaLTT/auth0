package com.cigama.auth0.service;

import com.cigama.auth0.dto.request.LoginRequest;
import com.cigama.auth0.dto.request.RegisterRequest;
import com.cigama.auth0.entity.ClientApp;
import com.cigama.auth0.entity.RefreshToken;
import com.cigama.auth0.entity.User;

public interface ValidationService {

    // --- Core Methods ---

    ClientApp validateRegistration(RegisterRequest request, String apiKey);

    User validateLogin(LoginRequest request);

    ClientApp validateApiKey(String apiKey);

    RefreshToken validateRefreshToken(String token);
}
