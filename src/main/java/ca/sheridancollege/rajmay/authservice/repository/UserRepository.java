package com.example.auth.repository;

import com.example.auth.entity.User;
import com.example.auth.entity.enums.AuthProvider;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByEmail(String email);
    
    boolean existsByEmail(String email);
    
    Optional<User> findByProviderAndProviderId(AuthProvider provider, String providerId);
    
    @Modifying
    @Query("UPDATE User u SET u.failedAttempts = :failedAttempts WHERE u.email = :email")
    void updateFailedAttempts(@Param("failedAttempts") int failedAttempts, @Param("email") String email);
    
    @Modifying
    @Query("UPDATE User u SET u.locked = true, u.lockTime = :lockTime WHERE u.email = :email")
    void lockUser(@Param("email") String email, @Param("lockTime") LocalDateTime lockTime);
    
    @Modifying
    @Query("UPDATE User u SET u.locked = false, u.failedAttempts = 0, u.lockTime = NULL WHERE u.email = :email")
    void unlockUser(@Param("email") String email);
    
    @Modifying
    @Query("UPDATE User u SET u.emailVerified = true WHERE u.id = :userId")
    void verifyEmail(@Param("userId") UUID userId);
}
