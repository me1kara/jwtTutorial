package com.han.jwtTuto.dto;


import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.*;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginDTO {

    @NotNull
    @Size(min=3,max=50)
    private String username;
    @NotNull
    @Size(min=3, max=50)
    private String password;

}
