package com.example.auth.service;

import com.example.auth.dto.PasswordChangeRequest;
import com.example.auth.dto.ProfileUpdateRequest;
import com.example.auth.dto.UserDto;
import com.example.auth.entity.User;
import com.example.auth.exception.BadRequestException;
import com.example.auth.exception.ResourceNotFoundException;
import com.example.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;

    @Transactional(readOnly = true)
    public UserDto getCurrentUser(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User", "email", email));
        
        return mapUserToDto(user);
    }

    @Transactional(readOnly = true)
    public UserDto getUserById(UUID id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", id.toString()));
        
        return mapUserToDto(user);
    }

    @Transactional
    public UserDto updateProfile(String email, ProfileUpdateRequest updateRequest) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User", "email", email));
        
        user.setFirstName(updateRequest.getFirstName());
        user.setLastName(updateRequest.getLastName());
        
        if (updateRequest.getProfileImageUrl() != null) {
            user.setProfileImageUrl(updateRequest.getProfileImageUrl());
        }
        
        User updatedUser = userRepository.save(user);
        return mapUserToDto(updatedUser);
    }

    @Transactional
    public void changePassword(String email, PasswordChangeRequest passwordChangeRequest) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User", "email", email));
        
        // Check if the current password is correct
        if (!passwordEncoder.matches(passwordChangeRequest.getCurrentPassword(), user.getPassword())) {
            throw new BadRequestException("Current password is incorrect");
        }
        
        // Check if the new password is the same as the old one
        if (passwordEncoder.matches(passwordChangeRequest.getNewPassword(), user.getPassword())) {
            throw new BadRequestException("New password must be different from the current password");
        }
        
        // Update password
        user.setPassword(passwordEncoder.encode(passwordChangeRequest.getNewPassword()));
        userRepository.save(user);
    }

    @Transactional
    public void deactivateAccount(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User", "email", email));
        
        user.setEnabled(false);
        userRepository.save(user);
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
