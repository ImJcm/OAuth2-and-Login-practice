package com.imjcm.oauth2andloginpractice.jwt.SpringBootTest;

import com.imjcm.oauth2andloginpractice.global.common.Role;
import com.imjcm.oauth2andloginpractice.global.config.jwt.service.JwtService;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.crypto.SecretKey;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;

@SpringBootTest
public class JwtServiceTest {
    @Autowired
    private JwtService jwtService;

    @Autowired
    private RedisTemplate<String, String> redisTemplate;

    @Value("${jwt.secret.key}")
    private String secretKey;

    @Value("${jwt.access.expiration}")
    private int accessTokenExpirationsPeriod;

    @Value("${jwt.refresh.expiration}")
    private int refreshTokenExpirationsPeriod;

    @Value("${jwt.access.header}")
    private String accessTokenHeader;

    @Value("${jwt.refresh.header}")
    private String refreshTokenHeader;

    private SecretKey key;
    public static final String BEARER_PREFIX = "Bearer ";
    public static final String EMAIL_CLAIMS = "email";

    @PostConstruct
    void init() {
        key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));
    }

    @AfterEach
    void clear_data() {
        String[] keys = {"testEmail@email.com"};

        for(String k : keys) {
            redisTemplate.delete(k);
        }
    }

    @DisplayName("createAccessToken : accessToken 생성 성공")
    @Test
    public void createAccessTokenSuccess() throws Exception {
        // given
        String email = "testEmail";

        // when
        String token = jwtService.createAccessToken(email);

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

    @DisplayName("createRefreshToken : refreshToken 생성 성공")
    @Test
    public void createRefreshTokenSuccess() throws Exception {
        // given
        String email = "testEmail@email.com";

        // when
        String token = jwtService.createRefreshToken(email);

        String jwt = token.split(" ")[1];

        String emailFromRefreshToken = Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(jwt)
                .getPayload()
                .get(EMAIL_CLAIMS, String.class);

        // then
        Assertions.assertThat(emailFromRefreshToken).isEqualTo(email);
    }

    @DisplayName("sendAccessTokenByHeader : AccessToken send 성공")
    @Test
    public void sendAccessTokenByHeaderSuccess() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        String token = "Test_Token";

        // when
        jwtService.sendAccessTokenByHeader(response, token);

        // then
        Assertions.assertThat(response.getStatus()).isEqualTo(MockHttpServletResponse.SC_OK);
        Assertions.assertThat(response.getHeader(accessTokenHeader)).isEqualTo(token);
    }

    @DisplayName("sendRefreshTokenByCookie : RefreshToken Header로 전송 성공")
    @Test
    public void sendRefreshTokenByCookieSuccess() throws Exception {
        // given
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String token = "Test_RefreshToken";

        // when
        jwtService.sendRefreshTokenByCookie(request, response, token);

        /*String refreshToken_value = Arrays.stream(response.getCookies())
                .filter(cookie -> cookie.getName().equals(refreshTokenHeader))
                .findFirst()
                .map(Cookie::getValue)
                .map(v -> URLDecoder.decode(v,StandardCharsets.UTF_8).replace(BEARER_PREFIX,""))
                .orElse(null);*/

        Cookie[] cookies = ((MockHttpServletResponse) response).getCookies();
        Cookie refreshTokenCookie = null;

        for (Cookie cookie : cookies) {
            if (cookie.getName().equals(refreshTokenHeader)) {
                refreshTokenCookie = cookie;
                break;
            }
        }

        String refreshToken_value = URLDecoder.decode(refreshTokenCookie.getValue(), StandardCharsets.UTF_8).replace(BEARER_PREFIX,"");

        // then
        Assertions.assertThat(response.getStatus()).isEqualTo(MockHttpServletResponse.SC_OK);
        Assertions.assertThat(refreshToken_value).isEqualTo(token);
    }

    @DisplayName("sendAccessTokenAndRefreshToken : AccessToken, RefreshToken Header로 전송 성공")
    @Test
    public void sendAccessTokenAndRefreshTokenSuccess() throws Exception {
        // given
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String accessToken = "Test_AccessToken";
        String refreshToken = "Test_RefreshToken";

        // when
        jwtService.sendAccessTokenAndRefreshToken(request, response, accessToken, refreshToken);

        String refreshToken_value = Arrays.stream(response.getCookies())
                .filter(cookie -> cookie.getName().equals(refreshTokenHeader))
                .findFirst()
                .map(Cookie::getValue)
                .map(v -> URLDecoder.decode(v,StandardCharsets.UTF_8).replace(BEARER_PREFIX,""))
                .orElse(null);

        // then
        Assertions.assertThat(response.getStatus()).isEqualTo(MockHttpServletResponse.SC_OK);
        Assertions.assertThat(response.getHeader(accessTokenHeader)).isEqualTo(accessToken);
        Assertions.assertThat(refreshToken_value).isEqualTo(refreshToken);
    }

    @DisplayName("getAccessTokenFromHeader : HttpServletRequest에서 token 가져오기 성공")
    @Test
    public void getAccessTokenFromHeaderSuccess() throws Exception {
        // given
        MockHttpServletRequest request = new MockHttpServletRequest();
        String accessTokenHeader = "Authorization";
        String jwt_token = jwtService.createAccessToken("testEmail@email.com");
        String jwt_token_value = jwt_token.replace(BEARER_PREFIX, "");

        request.addHeader(accessTokenHeader, jwt_token);

        // when
        Optional<String> token = jwtService.getAccessTokenFromHeader(request);

        // then
        Assertions.assertThat(token).isNotEmpty();
        Assertions.assertThat(token.get()).isEqualTo(jwt_token_value);
    }

    @DisplayName("getRefreshTokenFromCookie : Header에서 refreshToken 가져오기 성공")
    @Test
    public void getRefreshTokenFromCookieSuccess() throws Exception {
        // given
        MockHttpServletRequest request = new MockHttpServletRequest();
        String full_refreshToken = BEARER_PREFIX + "test_RefreshToken";
        String refreshToken = full_refreshToken.replace(BEARER_PREFIX, "");

        request.setCookies(new Cookie(refreshTokenHeader, full_refreshToken));

        // when
        String getRefreshToken = jwtService.getRefreshTokenFromCookie(request).get();

        // then
        Assertions.assertThat(getRefreshToken).isEqualTo(refreshToken);
    }

    @DisplayName("validateToken : jwt token 검증 성공")
    @Test
    public void validateTokenSuccess() throws Exception {
        // given
        String jwt_token_value = jwtService.createAccessToken("testEmail@email.com").replace(BEARER_PREFIX, "");

        // when
        boolean valid = jwtService.validateToken(jwt_token_value);

        // then
        Assertions.assertThat(valid).isEqualTo(true);
    }

    @DisplayName("validateToken : jwt token 검증 실패 - JwtException 예외 발생")
    @Test
    public void validateTokenFailure() throws Exception, JwtException {
        // given
        String invalid_token = "Invalid Token";

        // when & then
        Assertions.assertThatThrownBy(() -> jwtService.validateToken(invalid_token))
                .isInstanceOf(JwtException.class)
                .hasMessageContaining("Invalid Jwt signature, 유효하지 않는 Jwt 서명입니다.");
    }

    @DisplayName("extractEmailFromToken : token에서 Email 값 추출 성공")
    @Test
    public void extractEmailFromTokenSuccess() throws Exception {
        // given
        String origin_email = "testEmail@email.com";
        String jwt_token_value = jwtService.createAccessToken(origin_email).replace(BEARER_PREFIX, "");

        // when
        Optional<String> email = jwtService.extractEmailFromToken(jwt_token_value);

        // then
        Assertions.assertThat(email.get()).isEqualTo(origin_email);
    }

    @DisplayName("updateRefreshToken : redis RefreshToken 생성 및 업데이트 성공")
    @Test
    public void updateRefreshToken() throws Exception {
        // given
        String email = "testEmail@email.com";
        String refreshToken = "test RefreshToken";

        // when
        jwtService.updateRefreshToken(email, refreshToken);

        String getRefreshToken = redisTemplate.opsForValue().get(email);

        // then
        Assertions.assertThat(refreshToken).isEqualTo(getRefreshToken);
    }

    @DisplayName("getRefreshTokenFromRedisThroughEmail : redis에서 email에 해당하는 refreshToken 가져오기 성공")
    @Test
    public void getRefreshTokenFromRedisThroughEmailSuccess() throws Exception {
        // given
        String email = "testEmail@email.com";
        String refreshToken = "test RefreshToken";

        redisTemplate.opsForValue().set(email, refreshToken);

        // when
        String getRefreshToken = jwtService.getRefreshTokenFromRedisThroughEmail(email).get();

        // then
        Assertions.assertThat(getRefreshToken).isEqualTo(refreshToken);
    }

    @DisplayName("deleteRefreshTokenByEmail : email에 해당하는 데이터 redis에서 삭제 성공")
    @Test
    public void deleteRefreshTokenByEmailSuccess() throws Exception {
        // given
        String email = "testEmail@email.com";
        String refreshToken = "test RefreshToken";

        redisTemplate.opsForValue().set(email, refreshToken);

        // when
        jwtService.deleteRefreshTokenByEmail(email);

        String result = redisTemplate.opsForValue().get(email);

        // then
        Assertions.assertThat(result).isNull();
    }

    @DisplayName("deleteRefreshTokenByRefreshToken : refreshToken에서 email 추출 후 해당하는 데이터 redis에서 삭제 성공")
    @Test
    public void deleteRefreshTokenByRefreshTokenSuccess() throws Exception {
        // given
        String email = "testEmail@email.com";
        String full_refreshToken = jwtService.createRefreshToken(email);
        String refreshToken = full_refreshToken.replace(BEARER_PREFIX, "");

        redisTemplate.opsForValue().set(email, refreshToken);

        // when
        jwtService.deleteRefreshTokenByRefreshToken(refreshToken);

        String result = redisTemplate.opsForValue().get(email);

        // then
        Assertions.assertThat(result).isNull();
    }

    @DisplayName("isEqualsRefreshToken : redis에 저장된 RefreshToken과 인자로 주어진 RefreshToken이 동일한지 비교 성공")
    @Test
    public void isEqualsRefreshTokenSuccess() throws Exception {
        // given
        String email = "testEmail@email.com";
        String refreshToken = jwtService.createRefreshToken(email).replace(BEARER_PREFIX, "");

        redisTemplate.opsForValue().set(email, refreshToken);

        // when
        boolean result = jwtService.isEqualsRefreshToken(refreshToken);

        // then
        Assertions.assertThat(result).isEqualTo(true);
    }

    @DisplayName("isEqualsRefreshToken : redis에 저장된 RefreshToken과 인자로 주어진 RefreToken이 동일한지 비교 실패 - redis에 refreshToken이 존재하지 않음")
    @Test
    public void isEqualsRefreshTokenFailure_notExistRefreshTokenInRedis() throws Exception {
        // given
        String email = "testEmail@email.com";
        String refreshToken = jwtService.createRefreshToken(email).replace(BEARER_PREFIX, "");

        // when
        boolean result = jwtService.isEqualsRefreshToken(refreshToken);

        // then
        Assertions.assertThat(result).isEqualTo(false);
    }

    @DisplayName("isEqualsRefreshToken : redis에 저장된 RefreshToken과 인자로 주어진 RefreToken이 동일한지 비교 실패 - redis에 refreshToken와 동일하지 않음")
    @Test
    public void isEqualsRefreshTokenFailure_notEqualsRefreshToken() throws Exception {
        // given
        String email = "testEmail@email.com";
        String refreshToken = jwtService.createRefreshToken(email).replace(BEARER_PREFIX, "");
        String another_refreshToken = "Not Equals RefreshToken";

        redisTemplate.opsForValue().set(email, refreshToken);
        redisTemplate.opsForValue().set(email, another_refreshToken);

        // when
        boolean result = jwtService.isEqualsRefreshToken(refreshToken);

        // then
        Assertions.assertThat(result).isEqualTo(false);
    }
}
