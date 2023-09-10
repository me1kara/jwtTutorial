package com.han.jwtTuto.jwt;

import com.han.jwtTuto.entity.RefreshToken;
import com.han.jwtTuto.entity.User;
import com.han.jwtTuto.service.TokenService;
import com.han.jwtTuto.service.UserService;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Collection;
import java.util.stream.Collectors;

public class JwtFilter extends GenericFilterBean {

    private static final Logger logger = LoggerFactory.getLogger(JwtFilter.class);
    public static final String AUTHORIZATION_HEADER = "Authorization";
    private TokenProvider tokenProvider;

    private AuthenticationManagerBuilder authenticationManagerBuilder;

    private TokenService tokenService;


    @Autowired
    public JwtFilter(TokenProvider tokenProvider, TokenService tokenService,AuthenticationManagerBuilder authenticationManagerBuilder) {
        this.tokenProvider = tokenProvider;
        this.tokenService = tokenService;
        this.authenticationManagerBuilder = authenticationManagerBuilder;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        //요청을 받고
        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;

        //헤더에 담긴 토큰을 추출함
        String jwt = resolveToken(httpServletRequest);
        //요청 uri
        String requestURI = httpServletRequest.getRequestURI();

        //토큰검증
        if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
            Authentication authentication = tokenProvider.getAuthentication(jwt);

            SecurityContextHolder.getContext().setAuthentication(authentication);
            logger.debug("Security Context에 '{}' 인증 정보를 저장했습니다, uri: {}", authentication.getName(), requestURI);
        } else {
            //리프레쉬 토큰이 있는지 확인 로직
            String refreshHeader = ((HttpServletRequest) servletRequest).getHeader("Refresh-Token");

            if(refreshHeader !=null ){
                String refreshJwt = refreshHeader;
                System.out.println(refreshJwt);
                if(StringUtils.hasText(refreshJwt) && tokenProvider.validateToken(refreshJwt)) {
                    // 리프레시 토큰이 유효하면 새로운 엑세스 토큰 생성
                    //db에 토큰과 매칭되는지 확인, 유효시간 등등
                    RefreshToken savedRefreshToken = tokenService.matches(refreshJwt);

                    Collection<? extends GrantedAuthority> authorities = savedRefreshToken.getUser().getAuthorities().stream().map(authority->new SimpleGrantedAuthority(authority.getAuthorityName())).collect(Collectors.toList());

                    //db에 인증목적으로 사용할 객체 생성
                    UsernamePasswordAuthenticationToken authenticationToken =
                            new UsernamePasswordAuthenticationToken(savedRefreshToken.getUser().getUsername(),"",authorities);
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);

                    //유저에게 보낼 암호화된 토큰 만듦,
                    String accessToken = tokenProvider.createToken(authenticationToken);
                    String refreshToken = tokenProvider.createRefreshToken(savedRefreshToken.getExpiresTime());

                    tokenService.saveToken(refreshToken,savedRefreshToken.getUser());

                    HttpServletResponse httpServletResponse = (HttpServletResponse) servletResponse;
                    httpServletResponse.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
                    httpServletResponse.setHeader("Refresh-Token", "Bearer " + refreshToken);

                }else{
                    logger.debug("유효한 JWT 토큰이 없습니다, uri: {}", requestURI);

                }
            }


        }
        //저장했으니 다음 필터 실행
        filterChain.doFilter(servletRequest, servletResponse);
    }

    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }

        return null;
    }
}
