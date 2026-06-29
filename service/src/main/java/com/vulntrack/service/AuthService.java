package com.vulntrack.service;

import com.vulntrack.domain.User;
import com.vulntrack.enums.UserRole;
import com.vulntrack.dto.LoginRequest;
import com.vulntrack.dto.LoginResponse;
import com.vulntrack.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenService jwtTokenService;

    public AuthService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtTokenService jwtTokenService
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenService = jwtTokenService;
    }

    @Transactional(readOnly = true)
    public LoginResponse login(LoginRequest request) {
        User user = userRepository.findByUsername(request.username())
                .orElseThrow(() -> new AuthenticationException("Invalid username or password."));

        if (!user.isEnabled() || !passwordEncoder.matches(request.password(), user.getPassword())) {
            throw new AuthenticationException("Invalid username or password.");
        }

        String token = jwtTokenService.generateToken(user);
        return new LoginResponse(token, "Bearer", user.getUsername(), user.getRole());
    }

    @Transactional(readOnly = true)
    public User requireUser(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new AuthenticationException("User not found."));
    }

    @Transactional(readOnly = true)
    public User requireEngineer(Long engineerId) {
        User engineer = userRepository.findById(engineerId)
                .orElseThrow(() -> new IllegalArgumentException("Engineer not found."));

        if (engineer.getRole() != UserRole.ENGINEER) {
            throw new IllegalArgumentException("Assigned user must have ENGINEER role.");
        }

        return engineer;
    }
}
