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
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;
import org.w3c.dom.ls.LSOutput;

import javax.crypto.SecretKey;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class JwtServiceTest {
    @InjectMocks
    private JwtService jwtService;

    @Mock
    RedisTemplate<String, String> redisTemplate;

    @Mock
    private ValueOperations<String, String> valueOperations;

    //private String jwt_token;
    private SecretKey key;
    private String secretKey;
    private Long accessTokenExpirationsPeriod;
    private Long refreshTokenExpirationsPeriod;
    private String accessTokenHeader;
    private String refreshTokenHeader;
    public String BEARER_PREFIX;
    public String EMAIL_CLAIMS;

    @BeforeEach
    void init() {
        // Mocking한 jwtService의 @Value로 설정된 변수에 값을 전달
        ReflectionTestUtils.setField(jwtService, "secretKey","amNtLW9hdXRoMi9jdXN0b21Mb2dpbkZpbHRlciBQcm9qZWN0");
        ReflectionTestUtils.setField(jwtService, "accessTokenHeader","Authorization");
        ReflectionTestUtils.setField(jwtService, "refreshTokenHeader", "Refresh Authorization");
        ReflectionTestUtils.setField(jwtService, "accessTokenExpirationsPeriod",1800000L);
        ReflectionTestUtils.setField(jwtService, "refreshTokenExpirationsPeriod",3600000L);
        ReflectionTestUtils.setField(jwtService, "key", Keys.hmacShaKeyFor(Decoders.BASE64.decode("amNtLW9hdXRoMi9jdXN0b21Mb2dpbkZpbHRlciBQcm9qZWN0")));

        // hard coding
        secretKey = "amNtLW9hdXRoMi9jdXN0b21Mb2dpbkZpbHRlciBQcm9qZWN0";
        key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));
        accessTokenExpirationsPeriod = 1800000L;
        refreshTokenExpirationsPeriod = 3600000L;
        accessTokenHeader = "Authorization";
        refreshTokenHeader = "Refresh Authorization";
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

    @DisplayName("createRefreshToken : refreshToken 생성 성공")
    @Test
    public void createRefreshTokenSuccess() throws Exception{
        // given
        String email = "testEmail";

        // when
        String token = jwtService.createRefreshToken(email);

        String rjwt = token.split(" ")[1];

        //String emailFromRefreshToken = String.valueOf(jwtService.extractEmailFromToken(rjwt));
        String emailFromRefreshToken = Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(rjwt)
                .getPayload()
                .get(EMAIL_CLAIMS, String.class);

        // then
        Assertions.assertThat(token).startsWith("Bearer ");
        Assertions.assertThat(email).isEqualTo(emailFromRefreshToken);
    }

    @DisplayName("reIssuedRefreshToken : refreshToken 재발급 성공")
    @Test
    public void reIssuedRefreshTokenSuccess() throws Exception {
        // given
        String email = "test Email";

        // when
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        doNothing().when(valueOperations).set(anyString(), anyString());

        String result = jwtService.reIssuedRefreshToken(email);

        // then
        verify(valueOperations, times(1)).set(anyString(), anyString());
        Assertions.assertThat(result).startsWith(BEARER_PREFIX);
    }

    @DisplayName("sendAccessToken : AccessToken send 성공")
    @Test
    public void sendAccessTokenSuccess() throws Exception {
        // given
        HttpServletResponse response = new MockHttpServletResponse();
        String token = "Test Token";

        // when
        jwtService.sendAccessToken(response, token);

        // then
        Assertions.assertThat(response.getStatus()).isEqualTo(MockHttpServletResponse.SC_OK);
        Assertions.assertThat(response.getHeader(accessTokenHeader)).isEqualTo(token);
    }

    @DisplayName("sendRefreshToken : Header에 refreshToken 전송 성공")
    @Test
    public void sendRefreshTokenSuccess() throws Exception {
        // given
        HttpServletResponse response = new MockHttpServletResponse();
        String token = "Test Token";

        // when
        jwtService.sendRefreshToken(response, token);

        // then
        Assertions.assertThat(response.getStatus()).isEqualTo(MockHttpServletResponse.SC_OK);
        Assertions.assertThat(response.getHeader(refreshTokenHeader)).isEqualTo(token);
    }

    @DisplayName("sendAccessTokenAndRefreshToken : accessToken, refreshToken Header로 전송 성공")
    @Test
    public void sendAccessTokenAndRefreshToken() throws Exception {
        // given
        HttpServletResponse response = new MockHttpServletResponse();
        String accessToken = "Test AccessToken";
        String refreshToken = "Test RefreshToken";

        // when
        jwtService.sendAccessTokenAndRefreshToken(response, accessToken, refreshToken);

        // then
        Assertions.assertThat(response.getStatus()).isEqualTo(MockHttpServletResponse.SC_OK);
        Assertions.assertThat(response.getHeader(accessTokenHeader)).isEqualTo(accessToken);
        Assertions.assertThat(response.getHeader(refreshTokenHeader)).isEqualTo(refreshToken);
    }

    @DisplayName("getAccessTokenFromHeader : HttpServletRequest에서 accesstoken 가져오기 성공")
    @Test
    public void getAccessTokenFromHeaderSuccess() throws Exception {
        // given
        MockHttpServletRequest request = new MockHttpServletRequest();
        String jwt_token = jwtService.createAccessToken("testEmail@email.com",Role.USER);
        String jwt_token_value = jwt_token.replace(BEARER_PREFIX, "");

        request.addHeader(accessTokenHeader, jwt_token);

        // when
        Optional<String> token = jwtService.getAccessTokenFromHeader(request);

        // then
        Assertions.assertThat(token).isNotEmpty();
        Assertions.assertThat(token.get()).isEqualTo(jwt_token_value);
    }

    @DisplayName("getRefreshTokenFromHeader : HttpServletRequest에서 refreshToken 가져오기 성공")
    @Test
    public void getRefreshTokenFromHeaderSuccess() throws Exception {
        // given
        MockHttpServletRequest request = new MockHttpServletRequest();
        String rjwt_token = jwtService.createRefreshToken("testEmail@email.com");
        String rjwt_token_value = rjwt_token.replace(BEARER_PREFIX, "");

        request.addHeader(refreshTokenHeader, rjwt_token);

        // when
        Optional<String> token = jwtService.getRefreshTokenFromHeader(request);

        // then
        Assertions.assertThat(token).isNotEmpty();
        Assertions.assertThat(token.get()).isEqualTo(rjwt_token_value);
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

    @DisplayName("updateRefreshToken : refreshToken 업데이트 성공")
    @Test
    public void updateRefreshToken() throws Exception {
        // given
        String email = "testEmail@email.com";
        String refreshToken = "test RefreshToken";

        // when
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        doNothing().when(valueOperations).set(any(String.class), any(String.class));

        jwtService.updateRefreshToken(email, refreshToken);

        // then
        verify(valueOperations,times(1)).set(any(String.class), any(String.class));
    }

    @DisplayName("getRefreshTokenFromRedisThroughEmail : redis DB에서 Email에 해당하는 value(refreshToken)값 가져오기 성공")
    @Test
    public void getRefreshTokenFromRedisThroughEmail() throws Exception {
        // given
        String email = "testEmail@email.com";
        String refreshToken = "refreshToken";

        // when
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        doReturn(refreshToken).when(valueOperations).get(anyString());

        String result = jwtService.getRefreshTokenFromRedisThroughEmail(email).get();

        // then
        Assertions.assertThat(result).isEqualTo(refreshToken);
    }

    @DisplayName("deleteRefreshTokenByEmail : redis Email에 해당하는 데이터 삭제 성공")
    @Test
    public void deleteRefreshTokenByEmail() throws Exception {
        // given
        String email = "testEmail@email.com";

        // when
        doReturn(true).when(redisTemplate).delete(anyString());

        jwtService.deleteRefreshTokenByEmail(email);

        // then
        verify(redisTemplate,times(1)).delete(anyString());
    }

    @DisplayName("deleteRefreshTokenByRefreshToken : redis refreshToken에서 email추출하여 해당하는 데이터 삭제 성공 ")
    @Test
    public void deleteRefreshTokenByRefreshTokenSuccess() throws Exception {
        // given
        String email = "testEmail@email.com";
        String refreshToken = jwtService.createRefreshToken(email).split(" ")[1];

        // when
        doReturn(true).when(redisTemplate).delete(email);

        jwtService.deleteRefreshTokenByRefreshToken(refreshToken);

        // then
        verify(redisTemplate,times(1)).delete(anyString());
    }

    @DisplayName("isEqualsRefreshToken : Header의 RefreshToken과 Redis의 RefreshToken이 동일한지 비교 성공")
    @Test
    public void isEqualsRefreshToken() throws Exception {
        // given
        String email = "testEmail@email.com";
        String refreshToken = jwtService.createRefreshToken(email).split(" ")[1];

        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        given(valueOperations.get(anyString())).willReturn(refreshToken);

        // when
        String curRefreshToken = jwtService.getRefreshTokenFromRedisThroughEmail(email).get();

        boolean check = jwtService.isEqualsRefreshToken(refreshToken);

        // then
        Assertions.assertThat(check).isEqualTo(true);
        Assertions.assertThat(curRefreshToken).isEqualTo(refreshToken);
    }
}
