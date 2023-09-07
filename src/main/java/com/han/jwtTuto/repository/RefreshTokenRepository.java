package com.han.jwtTuto.repository;

import com.han.jwtTuto.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken,Long> {
    Optional<RefreshToken> findByToken(String token);
    void saveByToken(String token);
    Optional<RefreshToken> findByUsername(String name);
}
