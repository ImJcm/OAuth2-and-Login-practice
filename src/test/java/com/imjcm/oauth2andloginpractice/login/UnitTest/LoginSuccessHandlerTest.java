package com.imjcm.oauth2andloginpractice.login.UnitTest;

import com.imjcm.oauth2andloginpractice.domain.member.Member;
import com.imjcm.oauth2andloginpractice.domain.member.MemberRepository;
import com.imjcm.oauth2andloginpractice.global.common.Role;
import com.imjcm.oauth2andloginpractice.global.config.jwt.service.JwtService;
import com.imjcm.oauth2andloginpractice.global.config.login.handler.LoginSuccessHandler;
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

import java.util.List;

import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class LoginSuccessHandlerTest {
    @InjectMocks
    private LoginSuccessHandler loginSuccessHandler;

    @Mock
    private JwtService jwtService;

    @Mock
    private MemberRepository memberRepository;

    @BeforeEach
    void init() {
        ReflectionTestUtils.setField(jwtService, "accessTokenExpirationsPeriod",1800000L);
    }

    @DisplayName("onAuthenticationSuccess : Authentication 성공 시 수행")
    @Test
    public void onAuthenticationSuccessTest() throws Exception {
        // given
        String jwt_Header = "Authorization";
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

        String token = "jwt-token";

        given(jwtService.createAccessToken(email, role))
                .willReturn(token);

        doAnswer(invocationOnMock -> {
            response.addHeader(jwt_Header, jwt_prefix + token);
            return null;
        }).when(jwtService).sendAccessToken(eq(response),eq(token));

        // when
        loginSuccessHandler.onAuthenticationSuccess(request, response, authentication);

        // then
        verify(jwtService).createAccessToken(eq(email),eq(role));
        verify(jwtService).sendAccessToken(eq(response), eq(token));

        Assertions.assertThat(response.getHeader(jwt_Header)).isEqualTo(jwt_prefix + token);
    }
}
