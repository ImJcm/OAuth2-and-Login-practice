package com.imjcm.oauth2andloginpractice.domain.member.dto.request;

import lombok.Getter;

@Getter
public class PasswordRequestDto {
    private String password;
    private String changedPassword;
}
