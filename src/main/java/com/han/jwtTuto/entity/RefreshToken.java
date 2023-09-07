package com.han.jwtTuto.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.Reference;

@Entity
@Getter
@Setter
@Table(name = "refreshToken")
public class RefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "refreshTokenId")
    private Long id;
    @Column(name = "username", length = 50, unique = true)
    private String username;
    @Column(name = "token")
    private String token;

    public RefreshToken(String refreshToken, String name) {
        this.username = name;
        this.token = refreshToken;
    }
}
