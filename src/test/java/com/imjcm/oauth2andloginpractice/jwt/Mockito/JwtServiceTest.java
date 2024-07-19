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
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;

import javax.crypto.SecretKey;
import java.util.Optional;

@ExtendWith(MockitoExtension.class)
public class JwtServiceTest {
    @InjectMocks
    private JwtService jwtService;

    //private String jwt_token;
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

        // jwt.io 생성 - email:testEmail.com, role:USER, iat:1721385588, exp:1721387388
        //jwt_token = "eyJhbGciOiJIUzI1NiJ9.eyJlbWFpbCI6InRlc3RFbWFpbEBlbWFpbC5jb20iLCJyb2xlIjoiVVNFUiIsImlhdCI6MTcyMTM4NTU4OCwiZXhwIjoxNzIxMzg3Mzg4fQ.MGpZOZUONukpWkbUvPt1H8oLgmLewlb7002ZCJVakU8";
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
