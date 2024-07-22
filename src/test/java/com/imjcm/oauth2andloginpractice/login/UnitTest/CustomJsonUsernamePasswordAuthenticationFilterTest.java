package com.imjcm.oauth2andloginpractice.login.UnitTest;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.imjcm.oauth2andloginpractice.domain.member.dto.request.LoginRequestDto;
import com.imjcm.oauth2andloginpractice.global.config.login.filter.CustomJsonUsernamePasswordAuthenticationFilter;
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
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
public class CustomJsonUsernamePasswordAuthenticationFilterTest {
    @InjectMocks
    private CustomJsonUsernamePasswordAuthenticationFilter customJsonUsernamePasswordAuthenticationFilter;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private ObjectMapper objectMapper;

    private String email;
    private String password;

    @BeforeEach
    void init() {
        email = "testEmail@email.com";
        password = "testPassword";

        // Inject AuthenticationManager into the filter
        customJsonUsernamePasswordAuthenticationFilter.setAuthenticationManager(authenticationManager);
    }

    @DisplayName("attemptAuthentication : Authentication 인증 시도 성공")
    @Test
    public void attemptAuthenticationMethodSuccess() throws Exception {
        // given
        LoginRequestDto requestDto = new LoginRequestDto(email, password);
        String jsonRequest = new ObjectMapper().writeValueAsString(requestDto);

        given(objectMapper.readValue(any(InputStream.class), any(Class.class)))
                .willReturn(requestDto);

        Authentication authentication = new UsernamePasswordAuthenticationToken(
                email,
                password,
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
        given(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .willReturn(authentication);

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        request.setContent(jsonRequest.getBytes(StandardCharsets.UTF_8));

        // when
        Authentication result = customJsonUsernamePasswordAuthenticationFilter.attemptAuthentication(request, response);

        // then
        Assertions.assertThat(result).isNotNull();
        Assertions.assertThat(result.getName()).isEqualTo(email);
        Assertions.assertThat(result.getCredentials()).isEqualTo(password);
        Assertions.assertThat(result.getAuthorities()).isNotEmpty();

        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
    }

    @DisplayName("attemptAuthentication : Authentication 인증 실패 - IOException")
    @Test
    public void attemptAuthenticationMethodFailure_NotExistMember() throws Exception {
        // given
        LoginRequestDto requestDto = null;
        // detailMessage : No content to map due to end-of-input
        Exception ioException = new IOException("역직렬화에 필요한 email, password JSON request가 존재하지 않음");
        // detailMessage : No content to map due to end-of-input
        Exception exception = new RuntimeException("역직렬화에 필요한 email, password JSON request가 존재하지 않음");
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        given(objectMapper.readValue(any(InputStream.class), eq(LoginRequestDto.class)))
                .willThrow(ioException);

        // when, then
        Assertions.assertThatThrownBy(() -> customJsonUsernamePasswordAuthenticationFilter.attemptAuthentication(request,response))
                .isInstanceOf(RuntimeException.class);
    }

}
