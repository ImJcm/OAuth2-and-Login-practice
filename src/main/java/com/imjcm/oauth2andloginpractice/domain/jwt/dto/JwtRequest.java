package com.imjcm.oauth2andloginpractice.domain.jwt.dto;

import lombok.Getter;

@Getter
public class JwtRequest {
    private String refreshToken;
}