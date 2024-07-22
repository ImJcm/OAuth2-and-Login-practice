package com.imjcm.oauth2andloginpractice.login.UnitTest;

import com.imjcm.oauth2andloginpractice.global.config.login.handler.LoginFailureHandler;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;

@ExtendWith(MockitoExtension.class)
public class LoginFailureHandlerTest {
    @InjectMocks
    private LoginFailureHandler loginFailureHandler;

    @DisplayName("onAuthenticationFailure : Authentication 인증 실패 시 수행")
    @Test
    public void onAuthenticationFailureTest() throws Exception {
        // given
        String failure_cause = "로그인 실패! 이메일 또는 비밀번호를 확인해주세요.";
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        AuthenticationException exception = new BadCredentialsException("Authenticaton 실패");

        // when
        loginFailureHandler.onAuthenticationFailure(request, response, exception);

        // then
        Assertions.assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
        Assertions.assertThat(response.getContentAsString()).isEqualTo(failure_cause);
    }
}
