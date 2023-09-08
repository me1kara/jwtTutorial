package com.han.jwtTuto.jwt;

import com.han.jwtTuto.service.TokenService;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public class JwtSecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {
    private TokenProvider tokenProvider;
    private TokenService tokenService;

    private AuthenticationManagerBuilder authenticationManagerBuilder;
    public JwtSecurityConfig(TokenProvider tokenProvider, TokenService tokenService, AuthenticationManagerBuilder authenticationManagerBuilder) {
        this.tokenProvider = tokenProvider;
        this.tokenService = tokenService;
        this.authenticationManagerBuilder = authenticationManagerBuilder;
    }

    @Override
    public void configure(HttpSecurity http) {
        http.addFilterBefore(
                //필터추가
                new JwtFilter(tokenProvider,tokenService, authenticationManagerBuilder),
                UsernamePasswordAuthenticationFilter.class
        );
    }
}
