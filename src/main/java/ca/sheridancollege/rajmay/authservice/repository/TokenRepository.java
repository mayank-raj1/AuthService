package com.example.auth.repository;

import com.example.auth.entity.Token;
import com.example.auth.entity.User;
import com.example.auth.entity.enums.TokenType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface TokenRepository extends JpaRepository<Token, UUID> {

    Optional<Token> findByToken(String token);
    
    List<Token> findByUserAndTokenType(User user, TokenType tokenType);
    
    Optional<Token> findByUserAndTokenTypeAndExpiryDateAfter(User user, TokenType tokenType, LocalDateTime now);
    
    @Modifying
    @Query("DELETE FROM Token t WHERE t.expiryDate < :now")
    void deleteExpiredTokens(@Param("now") LocalDateTime now);
    
    @Modifying
    @Query("DELETE FROM Token t WHERE t.user = :user AND t.tokenType = :tokenType")
    void deleteByUserAndTokenType(@Param("user") User user, @Param("tokenType") TokenType tokenType);
}
