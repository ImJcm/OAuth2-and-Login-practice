package com.imjcm.oauth2andloginpractice.global.config.jwt.service;

import com.imjcm.oauth2andloginpractice.global.common.CookieUtil;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Date;
import java.util.Optional;

@Slf4j(topic = "JWT 토큰 설정 및 유틸리티")
@RequiredArgsConstructor
@Service
public class JwtService {
    @Value("${jwt.secret.key}")
    private String secretKey;

    @Value("${jwt.access.expiration}")
    private int accessTokenExpirationsPeriod;

    @Value("${jwt.access.header}")
    private String accessTokenHeader;

    @Value("${jwt.refresh.expiration}")
    private int refreshTokenExpirationsPeriod;

    @Value("${jwt.refresh.header}")
    private String refreshTokenHeader;

    private SecretKey key;
    public static final String BEARER_PREFIX = "Bearer ";
    public static final String EMAIL_CLAIMS = "email";

    private final RedisTemplate<String, String> redisTemplate;


    /**
     * @PostContstruct 애너테이션은 JwtService에 최초로 접근 시, 한 번만 실행될 수 있는 메서드를 의미
     * base64로 인코딩된 secretKey를 decode하여 원문을 byte 배열로 만든 후,
     * hmacShaKeyFor() 메서드를 통해 HMAC 알고리즘을 적용한 SecretKey 객체를 만들고 저장한다.
     *
     * 인용 : SignatureAlgorithm is Deprecated. since 0.12.0; use Jwts.SIG instead.
     * 번역 : SignatureAlgorithm은 더 이상 사용되지 않는다. 0.12.0버전부터 Jwts.SIG를 사용
     * https://stackoverflow.com/questions/73576686/what-substitute-can-i-use-for-java-springs-jwts-signwith-deprecated-method
     *
     * byte[] bytes = Base64.getDecoder().decode(secretKey);
     * key = Keys.hmacShaKeyFor(bytes);
     * 에서 io.jsonwebtoken의 Decoders를 사용하여 base64로 암호화된 secretKey를 복호화한 byte[]를 반환한다.
     * https://github.com/jwtk/jjwt#jws-create-key
     */
    @PostConstruct
    public void init() {
        key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));
    }

    /**
     * email을 인자로 AccessToken을 생성한다.
     * AccessToken 양식 : Bearer + accessToken
     * @param email
     * @return
     */
    public String createAccessToken(String email) {
        Date date = new Date();

        return BEARER_PREFIX +
                Jwts.builder()
                        .claim("email",email)
                        .issuedAt(date)
                        .expiration(new Date(date.getTime() + accessTokenExpirationsPeriod))
                        .signWith(key,Jwts.SIG.HS256)
                        .compact();

    }

    /**
     * email을 인자로 RefreshToken을 생성한다.
     * RefreshToken 양식 : Bearer + refreshToken
     * @param email
     * @return
     */
    public String createRefreshToken(String email) {
        Date date = new Date();

        return BEARER_PREFIX +
                Jwts.builder()
                        .claim("email",email)
                        .issuedAt(date)
                        .expiration(new Date(date.getTime() + refreshTokenExpirationsPeriod))
                        .signWith(key,Jwts.SIG.HS256)
                        .compact();
    }

    /**
     * accessToken Header로 보내기 (Key : Authorization, value - accessToken)
     * @param response
     * @param token
     */
    public void sendAccessTokenByHeader(HttpServletResponse response, String token) {
        response.setStatus(HttpServletResponse.SC_OK);
        response.addHeader(accessTokenHeader, token);
    }

    /**
     * refreshToken Cookie로 보내기 (Key : Refresh Authorization, value - refreshToken)
     * 기존에 저장된 refreshToken을 Cookie에서 지우고, 새로운 refreshToken을 저장한다.
     * @param request
     * @param response
     * @param token
     */
    public void sendRefreshTokenByCookie(HttpServletRequest request, HttpServletResponse response, String token) {
        response.setStatus(HttpServletResponse.SC_OK);
        CookieUtil.deleteCookie(request, response, refreshTokenHeader);
        CookieUtil.addCookie(response, refreshTokenHeader, token, refreshTokenExpirationsPeriod);
    }

    /**
     * accessToken, refreshToken을 함께 Header,Cookie로 보내기
     * @param response
     * @param accessToken
     * @param refreshToken
     */
    public void sendAccessTokenAndRefreshToken(HttpServletRequest request, HttpServletResponse response, String accessToken, String refreshToken) {
        response.setStatus(HttpServletResponse.SC_OK);
        sendAccessTokenByHeader(response, accessToken);
        sendRefreshTokenByCookie(request, response, refreshToken);
    }

    /**
     * header에서 AccessToken 가져오기
     * Header에서 Key로 Authorization인 value에서 AccessToken을 Bearer Prefix 부분을 제거하여 반환
     * @param request
     * @return
     */
    public Optional<String> getAccessTokenFromHeader(HttpServletRequest request) {
        /*
        // 아래 코드와 동일한 기능
        String bearerToken = request.getHeader(accessTokenHeader);
        if(StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)) {
            return bearerToken.substring(7);
        }
        return null;
        */
        return Optional.ofNullable(request.getHeader(accessTokenHeader))
                .filter(accessToken -> accessToken.startsWith(BEARER_PREFIX))
                .map(accessToken -> accessToken.replace(BEARER_PREFIX,""));
    }

    /**
     * Cookie에서 RefreshToken 가져오기
     * Cookie에서 Key로 Refresh-Authorization인 value에서 RefreshToken을 UTF-8 decode를 수행 후, Bearer Prefix 부분을 제거하여 반환
     * @param request
     * @return
     */
    public Optional<String> getRefreshTokenFromCookie(HttpServletRequest request) {
        return Optional.ofNullable(request.getCookies()) // 쿠키 배열이 null일 수 있으므로 Optional로 감싸기
                .flatMap(cookies -> Arrays.stream(cookies) // 쿠키 배열을 스트림으로 변환
                        .filter(cookie -> cookie.getName().equals(refreshTokenHeader)) // refreshTokenHeader와 같은 이름의 쿠키 찾기
                        .findFirst() // 첫 번째로 찾은 쿠키 반환
                        .map(Cookie::getValue) // 쿠키의 값을 가져오기
                        .map(value -> URLDecoder.decode(value, StandardCharsets.UTF_8)) // URL 디코딩
                        .map(value -> value.replace(BEARER_PREFIX, ""))); // BEARER_PREFIX 제거
    }

    /**
     * token 검증
     *
     * Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token); 해당 메서드는 jjwt 0.12.0 이후에 사용이 권장되지 않는다.
     *  - setSigningKey, parseClaimsJws 두 메서드가 deprecated
     * 0.12.0버전 부터 Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(jwt)
     * https://stackoverflow.com/questions/73486900/how-to-fix-parser-is-deprecated-and-setsigningkeyjava-security-key-is-deprec
     * @param token
     * @return
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
            return true;
        } catch (SecurityException | MalformedJwtException | SignatureException e) {
            log.error("Invalid Jwt signature, 유효하지 않는 Jwt 서명입니다.");
            throw new JwtException("Invalid Jwt signature, 유효하지 않는 Jwt 서명입니다.");
        } catch (ExpiredJwtException e) {
            log.error("Expired Jwt token, 만료된 Jwt 토큰입니다.");
            throw new JwtException("Expired Jwt token, 만료된 Jwt 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            log.error("Unsupported Jwt token, 지원되지 않는 Jwt 토큰입니다.");
            throw new JwtException("Unsupported Jwt token, 지원되지 않는 Jwt 토큰입니다.");
        } catch (IllegalArgumentException e) {
            log.error("Jwt claims is empty, 잘못된 Jwt 토큰입니다.");
            throw new JwtException("Jwt claims is empty, 잘못된 Jwt 토큰입니다.");
        }
    }

    /**
     * Access / Refresh Token으로부터 사용자 정보를 담은 Claims에서 email 반환
     * @param token
     * @return
     */
    public Optional<String> extractEmailFromToken(String token) {
        return Optional.ofNullable(Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get(EMAIL_CLAIMS)
                .toString());
    }

    /**
     * email, refreshToken을 Key:value 형태로 redis에 저장 및 업데이트
     * @param email
     * @param refreshToken
     */
    public void updateRefreshToken(String email, String refreshToken) {
        redisTemplate.opsForValue().set(email,refreshToken.replace(BEARER_PREFIX,""));
    }

    /**
     * Redis DB에서 email에 해당하는 Key가 존재할 경우, refreshToken인 value를 반환
     * @param email
     * @return
     */
    public Optional<String> getRefreshTokenFromRedisThroughEmail(String email) {
        return Optional.ofNullable(redisTemplate.opsForValue().get(email));
    }

    /**
     * Redis에서 email에 해당하는 Key 데이터를 삭제
     * @param email
     */
    public void deleteRefreshTokenByEmail(String email) {
        redisTemplate.delete(email);
    }

    public void deleteRefreshTokenByRefreshToken(String refreshToken) {
        String email = extractEmailFromToken(refreshToken).get();

        deleteRefreshTokenByEmail(email);
    }

    /** redis에 저장된 refreshToken과 header로 전달된 refreshToken이 같은지 검사와 email에 해당하는 refreshToken이 존재하는지 검증
     * @param refreshToken
     * @return
     */
    public boolean isEqualsRefreshToken(String refreshToken) {
        String email = extractEmailFromToken(refreshToken).get();
        String curRefreshToken = getRefreshTokenFromRedisThroughEmail(email).orElse(null);

        if(curRefreshToken == null) {
            log.info("refreshToken이 존재하지 않음.");
            return false;
        } else {
            if(curRefreshToken.equals(refreshToken)) {
                log.info("refreshToken이 동일.");
                return true;
            } else {
                log.info("refreshToken이 동일하지 않음");
                return false;
            }
        }
    }

    /**
     * 현재 SecurityContextHolder를 비운다.
     */
    public void clearAuthentication() {
        SecurityContextHolder.clearContext();

    }
}
