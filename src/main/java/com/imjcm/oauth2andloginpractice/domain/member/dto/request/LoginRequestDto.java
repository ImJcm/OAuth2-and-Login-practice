package com.imjcm.oauth2andloginpractice.domain.member.dto.request;

import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
public class LoginRequestDto {
    private String email;
    private String password;
}
