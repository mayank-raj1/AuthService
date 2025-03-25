package com.example.auth.dto;

import com.example.auth.entity.enums.AuthProvider;
import com.example.auth.entity.enums.UserRole;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserDto {
    private UUID id;
    private String email;
    private String firstName;
    private String lastName;
    private String profileImageUrl;
    private AuthProvider provider;
    private Set<UserRole> roles;
    private boolean emailVerified;
}
