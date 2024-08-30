package com.imjcm.oauth2andloginpractice.login.UnitTest;

import com.imjcm.oauth2andloginpractice.domain.member.Member;
import com.imjcm.oauth2andloginpractice.global.common.Role;
import com.imjcm.oauth2andloginpractice.global.config.jwt.service.JwtService;
import com.imjcm.oauth2andloginpractice.global.config.login.handler.LoginSuccessHandler;
import jakarta.servlet.http.Cookie;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.util.ReflectionTestUtils;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class LoginSuccessHandlerTest {
    @InjectMocks
    private LoginSuccessHandler loginSuccessHandler;

    @Mock
    private JwtService jwtService;

    @BeforeEach
    void init() {
        ReflectionTestUtils.setField(jwtService, "accessTokenExpirationsPeriod",1800000);
        ReflectionTestUtils.setField(jwtService, "refreshTokenExpirationsPeriod", 3600000);
    }

    @DisplayName("onAuthenticationSuccess : Authentication 성공 시 수행")
    @Test
    public void onAuthenticationSuccessTest() throws Exception {
        // given
        String jwt_Header = "Authorization";
        String rjwt_Header = "Refresh_Authorization";
        String jwt_prefix = "Bearer ";
        String email = "testMember@email.com";
        String password = "testPassword";
        Role role = Role.USER;
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                Member.builder()
                        .email(email)
                        .password(password) // 실제 Base64.encode 필요
                        .nickname("testMember")
                        .role(role)
                        .build(),   // principal
                password,   // credential
                List.of(new SimpleGrantedAuthority(role.getAuthority())) // authorities
        );

        String accessToken = "jwt-token";
        String refreshToken = "rjwt-token";

        given(jwtService.createAccessToken(email))
                .willReturn(accessToken);

        given(jwtService.createRefreshToken(email))
                .willReturn(refreshToken);

        doAnswer(invocationOnMock -> {
            response.addHeader(jwt_Header, jwt_prefix + accessToken);
            response.addCookie(new Cookie(rjwt_Header, jwt_prefix + refreshToken));
            return null;
        }).when(jwtService).sendAccessTokenAndRefreshToken(eq(request),eq(response),eq(accessToken),eq(refreshToken));

        // when
        loginSuccessHandler.onAuthenticationSuccess(request, response, authentication);

        String r_value = Arrays.stream(response.getCookies())
                .filter(cookie -> cookie.getName().equals(rjwt_Header))
                .findFirst()
                .map(Cookie::getValue)
                .map(v -> URLDecoder.decode(v, StandardCharsets.UTF_8).replace(jwt_prefix,""))
                .orElse(null);

        // then
        verify(jwtService).createAccessToken(eq(email));
        verify(jwtService).createRefreshToken(eq(email));
        verify(jwtService).updateRefreshToken(eq(email), eq(refreshToken));
        verify(jwtService).sendAccessTokenAndRefreshToken(eq(request), eq(response), eq(accessToken), eq(refreshToken));

        Assertions.assertThat(response.getHeader(jwt_Header)).isEqualTo(jwt_prefix + accessToken);
        Assertions.assertThat(r_value).isEqualTo(refreshToken);
    }
}
