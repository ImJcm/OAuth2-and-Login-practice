package com.imjcm.oauth2andloginpractice.domain.jwt;

import com.imjcm.oauth2andloginpractice.global.common.Role;
import com.imjcm.oauth2andloginpractice.global.config.jwt.service.JwtService;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

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

    @GetMapping("/reissue-token")
    public void reIssueRefreshToken() {
        /*
            AccessToken 유효성 검사 또는 만료 시, 예외발생하면 클라이언트에서 Header에 RefreshToken을 담아서
            API 호출 시, JwtAuthenticationFilter에서 재발급 여부를 검사하고 재발급 수행한다.

            따라서, 해당 API는 Jwt 재발급 호출용이다.
         */
    }
}
