package com.imjcm.oauth2andloginpractice.jwt.Mockito;

import com.imjcm.oauth2andloginpractice.global.common.Role;
import com.imjcm.oauth2andloginpractice.global.config.jwt.service.JwtService;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletResponse;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;

import javax.crypto.SecretKey;

@ExtendWith(MockitoExtension.class)
public class JwtServiceTest {
    @InjectMocks
    private JwtService jwtService;

    private SecretKey key;
    private String secretKey;
    private Long accessTokenExpirationsPeriod;
    private String accessTokenHeader;
    public String BEARER_PREFIX;
    public String EMAIL_CLAIMS;

    @BeforeEach
    void init() {
        // Mocking한 jwtService의 @Value로 설정된 변수에 값을 전달
        ReflectionTestUtils.setField(jwtService, "secretKey","amNtLW9hdXRoMi9jdXN0b21Mb2dpbkZpbHRlciBQcm9qZWN0");
        ReflectionTestUtils.setField(jwtService, "accessTokenHeader","Authorization");
        ReflectionTestUtils.setField(jwtService, "accessTokenExpirationsPeriod",1800000L);
        ReflectionTestUtils.setField(jwtService, "key", Keys.hmacShaKeyFor(Decoders.BASE64.decode("amNtLW9hdXRoMi9jdXN0b21Mb2dpbkZpbHRlciBQcm9qZWN0")));

        // hard coding
        secretKey = "amNtLW9hdXRoMi9jdXN0b21Mb2dpbkZpbHRlciBQcm9qZWN0";
        key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));
        accessTokenExpirationsPeriod = 1800000L;
        accessTokenHeader = "Authorization";
        BEARER_PREFIX = "Bearer ";
        EMAIL_CLAIMS = "email";
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
        Assertions.assertThat(token).startsWith("Bearer ");
        Assertions.assertThat(email).isEqualTo(emailFromAccessToken);
    }

    @DisplayName("sendAccessToken : AccessToken send 성공")
    @Test
    public void sendAccessTokenSuccess() throws Exception {
        // given
        HttpServletResponse response = new MockHttpServletResponse();
        String token = "Test Token";
        String accessTokenHeader = "Authorization";

        // when
        jwtService.sendAccessToken(response, token);

        // then
        Assertions.assertThat(response.getStatus()).isEqualTo(MockHttpServletResponse.SC_OK);
        Assertions.assertThat(response.getHeader(accessTokenHeader)).isEqualTo(token);
    }
}
