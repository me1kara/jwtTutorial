package com.han.jwtTuto.service;


import com.han.jwtTuto.entity.RefreshToken;
import com.han.jwtTuto.entity.User;
import com.han.jwtTuto.jwt.TokenProvider;
import com.han.jwtTuto.repository.RefreshTokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@Transactional
public class TokenService {
    private final RefreshTokenRepository refreshTokenRepository;
    private final TokenProvider tokenProvider;

    private final long refreshTokenValidityMilliseconds;


    @Autowired
    public TokenService(RefreshTokenRepository refreshTokenRepository, TokenProvider tokenProvider, @Value("${jwt.refresh-token-validity-in-seconds}") long refreshTokenValidityMilliseconds) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.tokenProvider = tokenProvider;
        this.refreshTokenValidityMilliseconds = refreshTokenValidityMilliseconds;
    }
    public void saveToken(String refreshToken, User user) {
        Optional<RefreshToken> pastToken = refreshTokenRepository.findByUserId(user.getId());
        //기존게 있다면 토큰만 재갱신 해준다
        if(pastToken.isPresent()){
            pastToken.get().setToken(refreshToken);
            refreshTokenRepository.save(pastToken.get());
        }else{
            refreshTokenRepository.save(new RefreshToken(refreshToken,user,refreshTokenValidityMilliseconds));
        }
    }

    @Transactional
    public RefreshToken matches(String refreshToken) {

        //db에 해당 토큰이 있는지 확인하는 작업
        RefreshToken savedToken = refreshTokenRepository.findByToken(refreshToken)
                .orElseThrow(()->new RuntimeException("token not found in db"));

        //리프레쉬 토큰의 만료기한이 끝났다면
        if (!tokenProvider.validateToken(savedToken.getToken())) {
            refreshTokenRepository.delete(savedToken);
            throw new RuntimeException("만료된 토큰입니다");
        }

        return savedToken;

    }
}
