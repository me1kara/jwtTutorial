package com.han.jwtTuto.controller;


import com.han.jwtTuto.dto.LoginDTO;
import com.han.jwtTuto.dto.TokenDTO;
import com.han.jwtTuto.dto.UserDTO;
import com.han.jwtTuto.entity.RefreshToken;
import com.han.jwtTuto.entity.User;
import com.han.jwtTuto.jwt.JwtFilter;
import com.han.jwtTuto.jwt.TokenProvider;
import com.han.jwtTuto.service.TokenService;
import com.han.jwtTuto.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Objects;

@RestController
@RequestMapping("/api")
@Slf4j
public class AuthController {
    private final TokenProvider tokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    private final TokenService tokenService;

    private final UserService userService;

    public AuthController(TokenProvider tokenProvider, AuthenticationManagerBuilder authenticationManagerBuilder
    , TokenService tokenService
    , UserService userService) {
        this.tokenProvider = tokenProvider;
        this.authenticationManagerBuilder = authenticationManagerBuilder;
        this.tokenService = tokenService;
        this.userService = userService;
    }

    @PostMapping("/authenticate")
    public ResponseEntity<TokenDTO> authorize(@Valid @RequestBody LoginDTO loginDto) {
        //db에 인증목적으로 사용할 객체 생성
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());

        //!! userDetailsService 인증 로직 및 시큐리티 콘텍스트에 등록
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        //유저에게 보낼 암호화된 토큰 만듦
        String jwt = tokenProvider.createToken(authentication);
        String refreshToken = tokenProvider.createRefreshToken();

        User user = userService.getUser(authentication.getName());

        tokenService.saveToken(refreshToken,user);

        //유저에게 전달
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(JwtFilter.AUTHORIZATION_HEADER, "Bearer " + jwt);
        httpHeaders.add("Refresh-Token", "Bearer " + refreshToken);

        return new ResponseEntity<>(new TokenDTO(jwt), httpHeaders, HttpStatus.OK);
    }

    //확인용으로 냅둠
//    @GetMapping("/refresh")
//    public ResponseEntity<Void> refresh(HttpServletRequest request) {
//        validateExistHeader(request);
//        String refreshJwt = request.getHeader("Refresh-Token").substring(7);
//
//        //db에 토큰과 매칭되는지 확인, 유효시간 등등
//        RefreshToken savedRefreshToken = tokenService.matches(refreshJwt);
//
//        //db에 인증목적으로 사용할 객체 생성
//        UsernamePasswordAuthenticationToken authenticationToken =
//                new UsernamePasswordAuthenticationToken(savedRefreshToken.getUser().getUsername(), savedRefreshToken.getUser().getPassword());
//
//        //!! userDetailsService 인증 로직 및 시큐리티 콘텍스트에 등록
//        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
//        SecurityContextHolder.getContext().setAuthentication(authentication);
//
//        //유저에게 보낼 암호화된 토큰 만듦,
//        String accessToken = tokenProvider.createToken(authentication);
//        String refreshToken = tokenProvider.createRefreshToken(savedRefreshToken.getExpiresTime());
//
//        tokenService.saveToken(refreshToken,savedRefreshToken.getUser());
//
//        return ResponseEntity.noContent()
//                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
//                .build();
//    }

    private void validateExistHeader(HttpServletRequest request) {
        String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        String refreshTokenHeader = request.getHeader("Refresh-Token");
        if (Objects.isNull(authorizationHeader) || Objects.isNull(refreshTokenHeader)) {
            throw new RuntimeException("token not found");
        }
    }
}
