package com.han.jwtTuto.service;


import com.han.jwtTuto.entity.RefreshToken;
import com.han.jwtTuto.jwt.TokenProvider;
import com.han.jwtTuto.repository.RefreshTokenRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@Transactional
public class TokenService {
    private final RefreshTokenRepository refreshTokenRepository;
    private final TokenProvider tokenProvider;

    public TokenService(RefreshTokenRepository refreshTokenRepository, TokenProvider tokenProvider){
        this.refreshTokenRepository = refreshTokenRepository;
        this.tokenProvider = tokenProvider;
    }
    public void saveToken(String refreshToken, String name) {
        Optional<RefreshToken> pastToken = refreshTokenRepository.findByUsername(name);
        //기존게 있다면 덮어쓰기
        if(pastToken.isPresent()){
            pastToken.get().setToken(refreshToken);
            refreshTokenRepository.save(pastToken.get());
        }else{
            refreshTokenRepository.save(new RefreshToken(name, refreshToken));
        }
    }

    @Transactional
    public String matches(String refreshToken) {

        //db에 해당 토큰이 있는지 확인하는 작업
        RefreshToken savedToken = refreshTokenRepository.findByToken(refreshToken)
                .orElseThrow(()->new RuntimeException("token not found in db"));

        //리프레쉬 토큰의 만료기한이 끝났다면
        if (!tokenProvider.validateToken(savedToken.getToken())) {
            refreshTokenRepository.delete(savedToken);
            throw new RuntimeException("만료된 토큰입니다");
        }

        return savedToken.getUsername();

    }
}
