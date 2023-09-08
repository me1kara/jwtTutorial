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
    @OneToOne
    @JoinColumn(name="userId")
    private User user;
    @Column(name = "token")
    private String token;

    @Column(name ="expiresTime")
    private Long expiresTime;

    public RefreshToken(String refreshToken, String userId) {
        this.token = refreshToken;
    }
}
