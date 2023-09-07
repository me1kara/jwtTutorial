package com.han.jwtTuto.controller;

import com.han.jwtTuto.dto.UserDTO;
import com.han.jwtTuto.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api")
public class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/test-redirect")
    public void testRedirect(HttpServletResponse response) throws IOException {
        response.sendRedirect("/api/user");
    }

    @PostMapping("/signup")
    public ResponseEntity<UserDTO> signup(
            @Valid @RequestBody UserDTO userDto
    ) {
        return ResponseEntity.ok(userService.signup(userDto));
    }

    @GetMapping("/user")
    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    public ResponseEntity<UserDTO> getMyUserInfo(HttpServletRequest request) {
        return ResponseEntity.ok(userService.getMyUserWithAuthorities());
    }

    @GetMapping("/user/{username}")
    @PreAuthorize("hasAnyRole('ADMIN')")
    public ResponseEntity<UserDTO> getUserInfo(@PathVariable String username) {
        return ResponseEntity.ok(userService.getUserWithAuthorities(username));
    }


    //확인용응로
    @GetMapping("/allAuth")
    public ResponseEntity<List<Authentication>> getAllAuth(){

        // 현재 컨텍스트의 모든 사용자 목록 가져오기
        Authentication[] authList = new Authentication[]{SecurityContextHolder.getContext().getAuthentication()};

        // 인증된 사용자 목록만 필터링
        List<Authentication> authenticatedUsers = Arrays.stream(authList)
                .filter(auth -> !(auth instanceof AnonymousAuthenticationToken))
                .collect(Collectors.toList());
        return ResponseEntity.ok(authenticatedUsers);
        //로그인을 헀는데도 아무도 안 뜸.왜냐면 헤더에 토큰을 보내지 않았으니까
        //하지만 인증이 안 된 상태라도 지금 인증된 유저를 볼 수 있게 해놨는데...아무것도 안 뜸
        //이건 context에 유저정보를 저장하되 요청이 끝난뒤 그 상태를 기억하지 않기떄문으로 보임
        //즉 session 방식과 결정적인 차이가 여기서 옴

    }
}
