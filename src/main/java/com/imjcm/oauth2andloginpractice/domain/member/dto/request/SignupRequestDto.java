package com.imjcm.oauth2andloginpractice.domain.member.dto.request;

import lombok.Getter;

@Getter
public class SignupRequestDto {
    private String email;
    private String nickname;
    private String password;
}
