package com.han.jwtTuto.service;

import com.han.jwtTuto.Util.SecurityUtil;
import com.han.jwtTuto.dto.UserDTO;
import com.han.jwtTuto.entity.Authority;
import com.han.jwtTuto.entity.User;
import com.han.jwtTuto.exception.DuplicateMemberException;
import com.han.jwtTuto.exception.NotFoundMemberException;
import com.han.jwtTuto.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public UserDTO findById(Long id){
        return UserDTO.from(userRepository.findById(id).orElseThrow(()->new NotFoundMemberException("Member not found")));
    }

    @Transactional
    public UserDTO signup(UserDTO
                                      userDto) {
        if (userRepository.findOneWithAuthoritiesByUsername(userDto.getUsername()).orElse(null) != null) {
            throw new DuplicateMemberException("이미 가입되어 있는 유저입니다.");
        }

        Authority authority = Authority.builder()
                .authorityName("ROLE_USER")
                .build();

        User user = User.builder()
                .username(userDto.getUsername())
                .password(passwordEncoder.encode(userDto.getPassword()))
                .nickname(userDto.getNickname())
                .authorities(Collections.singleton(authority))
                .activated(true)
                .build();

        return UserDTO.from(userRepository.save(user));
    }

    @Transactional(readOnly = true)
    public UserDTO getUserWithAuthorities(String username) {
        return UserDTO.from(userRepository.findOneWithAuthoritiesByUsername(username).orElse(null));
    }

    @Transactional(readOnly = true)
    public UserDTO getMyUserWithAuthorities() {
        return UserDTO.from(
                SecurityUtil.getCurrentUsername()
                        .flatMap(userRepository::findOneWithAuthoritiesByUsername)
                        .orElseThrow(() -> new NotFoundMemberException("Member not found"))
        );
    }


}
