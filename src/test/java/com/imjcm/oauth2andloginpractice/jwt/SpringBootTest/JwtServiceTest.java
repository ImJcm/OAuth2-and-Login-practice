package com.imjcm.oauth2andloginpractice.jwt.SpringBootTest;

import com.imjcm.oauth2andloginpractice.global.common.Role;
import com.imjcm.oauth2andloginpractice.global.config.jwt.service.JwtService;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.crypto.SecretKey;
import java.util.Optional;

@SpringBootTest
public class JwtServiceTest {
    @Autowired
    private JwtService jwtService;

    @Value("${jwt.secret.key}")
    private String secretKey;

    @Value("${jwt.access.expiration}")
    private Long accessTokenExpirationsPeriod;

    @Value("${jwt.access.header}")
    private String accessTokenHeader;

    private SecretKey key;
    public static final String BEARER_PREFIX = "Bearer ";
    public static final String EMAIL_CLAIMS = "email";

    @PostConstruct
    void init() {
        key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));
    }

    @DisplayName("createAccessToken : accessToken 생성 성공")
    @Test
    public void createAccessTokenSuccess() throws Exception {
        // given
        String email = "testEmail";
        Role role = Role.USER;

        // when
        String token = jwtService.createAccessToken(email, role);

        String jwt = token.split(" ")[1];

        String emailFromAccessToken = Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(jwt)
                .getPayload()
                .get(EMAIL_CLAIMS,String.class);

        // then
        Assertions.assertThat(email).isEqualTo(emailFromAccessToken);
    }

    @DisplayName("sendAccessToken : AccessToken send 성공")
    @Test
    public void sendAccessTokenSuccess() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        String token = "Test Token";
        String accessTokenHeader = "Authorization";

        // when
        jwtService.sendAccessToken(response, token);

        // then
        Assertions.assertThat(response.getStatus()).isEqualTo(MockHttpServletResponse.SC_OK);
        Assertions.assertThat(response.getHeader(accessTokenHeader)).isEqualTo(token);
    }

    @DisplayName("getAccessTokenFromHeader : HttpServletRequest에서 token 가져오기 성공")
    @Test
    public void getAccessTokenFromHeaderSuccess() throws Exception {
        // given
        MockHttpServletRequest request = new MockHttpServletRequest();
        String accessTokenHeader = "Authorization";
        String jwt_token = jwtService.createAccessToken("testEmail@email.com",Role.USER);
        String jwt_token_value = jwt_token.replace(BEARER_PREFIX, "");

        request.addHeader(accessTokenHeader, jwt_token);

        // when
        Optional<String> token = jwtService.getAccessTokenFromHeader(request);

        // then
        Assertions.assertThat(token).isNotEmpty();
        Assertions.assertThat(token.get()).isEqualTo(jwt_token_value);
    }

    @DisplayName("validateToken : jwt token 검증 성공")
    @Test
    public void validateTokenSuccess() throws Exception {
        // given
        String jwt_token_value = jwtService.createAccessToken("testEmail@email.com",Role.USER).replace(BEARER_PREFIX, "");

        // when
        boolean valid = jwtService.validateToken(jwt_token_value);

        // then
        Assertions.assertThat(valid).isEqualTo(true);
    }

    @DisplayName("extractEmailFromToken : token에서 Email 값 추출 성공")
    @Test
    public void extractEmailFromTokenSuccess() throws Exception {
        // given
        String origin_email = "testEmail@email.com";
        String jwt_token_value = jwtService.createAccessToken(origin_email,Role.USER).replace(BEARER_PREFIX, "");

        // when
        Optional<String> email = jwtService.extractEmailFromToken(jwt_token_value);

        // then
        Assertions.assertThat(email.get()).isEqualTo(origin_email);
    }
}
