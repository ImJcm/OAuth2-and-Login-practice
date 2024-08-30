package com.imjcm.oauth2andloginpractice.domain.jwt;

import com.imjcm.oauth2andloginpractice.domain.jwt.dto.JwtRequest;
import com.imjcm.oauth2andloginpractice.global.config.jwt.service.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/jwt")
public class JwtController {
    private final JwtService jwtService;

    @GetMapping("/get-token")
    public String getJwtToken() {
        String email = "testEmail@email.com";

        return jwtService.createAccessToken(email);
    }

    /*
        AccessToken 유효성 검사 또는 만료 시, 예외발생하면 클라이언트에서 Header에 RefreshToken을 담아서
        API 호출 시, JwtAuthenticationFilter에서 재발급 여부를 검사하고 재발급 수행한다.

        따라서, 해당 API는 Jwt 재발급 호출용이다.
     */
    @PostMapping("/reissue-token")
    public ResponseEntity<Object> reIssueToken(@RequestBody JwtRequest jwtRequest, HttpServletRequest request, HttpServletResponse response) {
        String token = URLDecoder.decode(jwtRequest.getRefreshToken(), StandardCharsets.UTF_8)
                .replace(JwtService.BEARER_PREFIX,"");

        if(jwtService.validateToken(token) && jwtService.isEqualsRefreshToken(token)) {
            String email = jwtService.extractEmailFromToken(token).orElse(null);

            String accessToken = jwtService.createAccessToken(email);
            String refreshToken = jwtService.createRefreshToken(email);

            jwtService.sendAccessTokenByHeader(response, accessToken);
            jwtService.sendRefreshTokenByCookie(request, response, refreshToken);

            return ResponseEntity.status(HttpStatus.CREATED).body(null);
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
    }
}
