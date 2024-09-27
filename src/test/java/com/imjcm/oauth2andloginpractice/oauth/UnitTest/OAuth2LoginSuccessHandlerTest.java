package com.imjcm.oauth2andloginpractice.oauth.UnitTest;

import com.imjcm.oauth2andloginpractice.global.config.jwt.service.JwtService;
import com.imjcm.oauth2andloginpractice.global.config.oauth.CustomOAuth2Member;
import com.imjcm.oauth2andloginpractice.global.config.oauth.handler.OAuth2LoginSuccessHandler;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;

import java.io.IOException;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class OAuth2LoginSuccessHandlerTest {
    @InjectMocks
    private OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;

    @Mock
    private JwtService jwtService;

    @DisplayName("onAuthenticationSuccess : oAuth 로그인 성공")
    @Test
    public void onAuthenticationSuccess() throws ServletException, IOException {
        // given
        String email = "email";
        String accessToken = "accessToken";
        String refreshToken = "refreshToken";
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        Authentication authentication = mock(Authentication.class);
        CustomOAuth2Member oAuth2Member = mock(CustomOAuth2Member.class);

        given(authentication.getPrincipal()).willReturn(oAuth2Member);
        given(oAuth2Member.getAttribute(email)).willReturn(email);
        given(jwtService.createAccessToken(email)).willReturn(accessToken);
        given(jwtService.createRefreshToken(email)).willReturn(refreshToken);

        doNothing().when(jwtService).sendRefreshTokenByCookie(any(HttpServletRequest.class), any(HttpServletResponse.class), any(String.class));
        doNothing().when(jwtService).updateRefreshToken(email, refreshToken);
        doNothing().when(jwtService).clearAuthentication();

        // when
        oAuth2LoginSuccessHandler.onAuthenticationSuccess(request, response, authentication);

        // then
        verify(jwtService, times(1)).sendRefreshTokenByCookie(request, response, refreshToken);
        verify(jwtService, times(1)).updateRefreshToken(email, refreshToken);
        verify(jwtService, times(1)).clearAuthentication();
    }
}
