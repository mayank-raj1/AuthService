package com.example.auth.service;

import com.example.auth.dto.*;
import com.example.auth.entity.Token;
import com.example.auth.entity.User;
import com.example.auth.entity.enums.AuthProvider;
import com.example.auth.entity.enums.TokenType;
import com.example.auth.entity.enums.UserRole;
import com.example.auth.exception.BadRequestException;
import com.example.auth.exception.ResourceNotFoundException;
import com.example.auth.repository.TokenRepository;
import com.example.auth.repository.UserRepository;
import com.example.auth.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider tokenProvider;
    private final EmailService emailService;

    @Value("${app.security.maxFailedAttempts}")
    private int maxFailedAttempts;

    @Value("${app.security.lockDuration}")
    private long lockDuration;

    @Value("${app.jwt.expiration}")
    private long jwtExpirationMs;

    @Transactional
    public AuthResponse login(LoginRequest loginRequest) {
        try {
            User user = userRepository.findByEmail(loginRequest.getEmail())
                    .orElseThrow(() -> new BadRequestException("Invalid email or password"));

            if (user.isLocked()) {
                if (user.getLockTime().plusMillis(lockDuration).isBefore(LocalDateTime.now())) {
                    userRepository.unlockUser(user.getEmail());
                } else {
                    throw new LockedException("Account is locked. Please try again later or contact support.");
                }
            }

            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getEmail(),
                            loginRequest.getPassword()
                    )
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);

            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            String accessToken = tokenProvider.generateToken(authentication);
            String refreshToken = tokenProvider.generateRefreshToken(userDetails);

            // Reset failed attempts after successful login
            if (user.getFailedAttempts() > 0) {
                userRepository.updateFailedAttempts(0, user.getEmail());
            }

            return AuthResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .expiresIn(jwtExpirationMs / 1000)
                    .user(mapUserToDto(user))
                    .build();
        } catch (LockedException ex) {
            throw ex;
        } catch (Exception ex) {
            processFailedLogin(loginRequest.getEmail());
            throw new BadRequestException("Invalid email or password");
        }
    }

    @Transactional
    public AuthResponse register(RegisterRequest registerRequest) {
        if (userRepository.existsByEmail(registerRequest.getEmail())) {
            throw new BadRequestException("Email is already taken");
        }

        User user = User.builder()
                .firstName(registerRequest.getFirstName())
                .lastName(registerRequest.getLastName())
                .email(registerRequest.getEmail())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .provider(AuthProvider.LOCAL)
                .enabled(true)
                .emailVerified(false)
                .locked(false)
                .failedAttempts(0)
                .roles(Set.of(UserRole.ROLE_USER))
                .build();

        User savedUser = userRepository.save(user);

        // Create verification token and send email
        String verificationToken = createAndSaveToken(savedUser, TokenType.VERIFICATION, 24);
        emailService.sendVerificationEmail(savedUser, verificationToken);

        // Authenticate the user
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        registerRequest.getEmail(),
                        registerRequest.getPassword()
                )
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Generate tokens
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String accessToken = tokenProvider.generateToken(authentication);
        String refreshToken = tokenProvider.generateRefreshToken(userDetails);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .expiresIn(jwtExpirationMs / 1000)
                .user(mapUserToDto(savedUser))
                .build();
    }

    @Transactional
    public void verifyEmail(String token) {
        Token verificationToken = tokenRepository.findByToken(token)
                .orElseThrow(() -> new BadRequestException("Invalid verification token"));

        if (verificationToken.isExpired()) {
            tokenRepository.delete(verificationToken);
            throw new BadRequestException("Verification token has expired");
        }

        User user = verificationToken.getUser();
        userRepository.verifyEmail(user.getId());
        tokenRepository.delete(verificationToken);
    }

    @Transactional
    public void requestPasswordReset(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User", "email", email));

        // Delete any existing password reset tokens
        tokenRepository.deleteByUserAndTokenType(user, TokenType.PASSWORD_RESET);

        // Create new password reset token and send email
        String resetToken = createAndSaveToken(user, TokenType.PASSWORD_RESET, 1);
        emailService.sendPasswordResetEmail(user, resetToken);
    }

    @Transactional
    public void resetPassword(String token, String newPassword) {
        Token resetToken = tokenRepository.findByToken(token)
                .orElseThrow(() -> new BadRequestException("Invalid password reset token"));

        if (resetToken.isExpired()) {
            tokenRepository.delete(resetToken);
            throw new BadRequestException("Password reset token has expired");
        }

        User user = resetToken.getUser();
        user.setPassword(passwordEncoder.encode(newPassword));

        userRepository.save(user);
        tokenRepository.delete(resetToken);
    }

    @Transactional
    public AuthResponse refreshToken(String refreshToken) {
        if (!tokenProvider.validateToken(refreshToken)) {
            throw new BadRequestException("Invalid refresh token");
        }

        String username = tokenProvider.extractUsername(refreshToken);
        User user = userRepository.findByEmail(username)
                .orElseThrow(() -> new ResourceNotFoundException("User", "email", username));

        UserDetails userDetails = org.springframework.security.core.userdetails.User
                .withUsername(user.getEmail())
                .password(user.getPassword())
                .authorities(user.getRoles().stream()
                        .map(role -> new org.springframework.security.core.authority.SimpleGrantedAuthority(role.name()))
                        .toList())
                .build();

        String accessToken = tokenProvider.generateToken(new HashMap<>(), userDetails);
        String newRefreshToken = tokenProvider.generateRefreshToken(userDetails);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(newRefreshToken)
                .expiresIn(jwtExpirationMs / 1000)
                .user(mapUserToDto(user))
                .build();
    }

    @Transactional
    protected void processFailedLogin(String email) {
        userRepository.findByEmail(email).ifPresent(user -> {
            if (!user.isLocked()) {
                if (user.getFailedAttempts() + 1 >= maxFailedAttempts) {
                    userRepository.lockUser(user.getEmail(), LocalDateTime.now());
                } else {
                    userRepository.updateFailedAttempts(user.getFailedAttempts() + 1, user.getEmail());
                }
            }
        });
    }

    private String createAndSaveToken(User user, TokenType tokenType, int expiryHours) {
        Token token = Token.builder()
                .token(UUID.randomUUID().toString())
                .tokenType(tokenType)
                .expiryDate(LocalDateTime.now().plusHours(expiryHours))
                .user(user)
                .build();

        return tokenRepository.save(token).getToken();
    }

    private UserDto mapUserToDto(User user) {
        return UserDto.builder()
                .id(user.getId())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .profileImageUrl(user.getProfileImageUrl())
                .provider(user.getProvider())
                .roles(user.getRoles())
                .emailVerified(user.isEmailVerified())
                .build();
    }
}