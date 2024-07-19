package com.imjcm.oauth2andloginpractice.domain.jwt;

import com.imjcm.oauth2andloginpractice.global.common.Role;
import com.imjcm.oauth2andloginpractice.global.config.jwt.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/jwt")
public class JwtController {
    private final JwtService jwtService;

    @GetMapping("/get-token")
    public String getJwtToken() {
        String email = "testEmail@email.com";
        Role role = Role.USER;

        return jwtService.createAccessToken(email, role);
    }
}
