package com.imjcm.oauth2andloginpractice.oauth.UnitTest;

import com.imjcm.oauth2andloginpractice.global.config.oauth.handler.OAuth2LoginFailureHandler;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.AuthenticationException;

import java.io.IOException;
import java.io.PrintWriter;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class OAuth2LoginFailureHandlerTest {
    @InjectMocks
    private OAuth2LoginFailureHandler oAuth2LoginFailureHandler;

    @DisplayName("onAuthenticationFailure : oAuth 로그인 실패")
    @Test
    public void onAuthenticationFailureTest() throws ServletException, IOException {
        // given
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        AuthenticationException authenticationException = mock(AuthenticationException.class);
        PrintWriter printWriter = mock(PrintWriter.class);

        given(response.getWriter()).willReturn(printWriter);

        // when
        oAuth2LoginFailureHandler.onAuthenticationFailure(request, response, authenticationException);

        // then
        verify(response, times(1)).sendRedirect(any(String.class));
    }
}
