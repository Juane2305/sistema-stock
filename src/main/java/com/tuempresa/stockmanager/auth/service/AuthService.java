package com.tuempresa.stockmanager.auth.service;


import com.tuempresa.stockmanager.auth.dto.AuthRequest;
import com.tuempresa.stockmanager.auth.dto.AuthResponse;
import com.tuempresa.stockmanager.auth.dto.RegisterRequest;
import com.tuempresa.stockmanager.auth.model.Role;
import com.tuempresa.stockmanager.auth.model.User;
import com.tuempresa.stockmanager.auth.security.jwt.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private AuthenticationManager authenticationManager;
    private final CustomUserDetailsService customUserDetailsService;


    public AuthResponse register(RegisterRequest request) {
        var user = User.builder()
                .name(request.name())
                .email(request.email())
                .password(request.password())
                .role(Role.CLIENT)
                .build();
        userRepository.save(user);
        var userDetails = customUserDetailsService.loadUserByUsername(user.getEmail());
        var jwt = jwtService.generateToken(userDetails);

        return new AuthResponse(jwt);
    }

    public AuthResponse login(AuthRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.email(), request.password())
        );
        var user = userRepository.findByEmail(request.email())
                .orElseThrow(() -> new UsernameNotFoundException("User not found."));
        var jwt = jwtService.generateToken(user);
        return new AuthResponse(jwt);
    }
}
