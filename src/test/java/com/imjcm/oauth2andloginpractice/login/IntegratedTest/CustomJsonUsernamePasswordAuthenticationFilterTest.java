package com.imjcm.oauth2andloginpractice.login.IntegratedTest;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.imjcm.oauth2andloginpractice.domain.member.Member;
import com.imjcm.oauth2andloginpractice.domain.member.MemberRepository;
import com.imjcm.oauth2andloginpractice.domain.member.dto.request.LoginRequestDto;
import com.imjcm.oauth2andloginpractice.global.common.Role;
import com.imjcm.oauth2andloginpractice.global.config.login.filter.CustomJsonUsernamePasswordAuthenticationFilter;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.RequestBuilder;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

@SpringBootTest
@AutoConfigureMockMvc
public class CustomJsonUsernamePasswordAuthenticationFilterTest {
    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private CustomJsonUsernamePasswordAuthenticationFilter customJsonUsernamePasswordAuthenticationFilter;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private MemberRepository memberRepository;

    private String email;
    private String password;
    private String nickname;
    private Role role;
    private String url;
    @BeforeEach
    void init() {
        email = "testEmail@email.com";
        password = "testPassword";
        nickname = "testMember";
        role = Role.USER;
        url = "/api/member/login";

        memberRepository.deleteAll();
    }

    public void signup(String email, String password) {
        memberRepository.save(Member.builder()
                .email(email)
                .password(passwordEncoder.encode(password))
                .role(role)
                .nickname(nickname)
                .build());
    }

    @DisplayName("attemptAuthentication - LoginSuccessHandler : Authentication 인증 시도 / LoginSuccessHandler 수행")
    @Test
    public void attemptAuthenticationMethodSuccess() throws Exception {
        // given
        signup(email, password);
        LoginRequestDto requestDto = new LoginRequestDto(email, password);
        String jsonRequest = new ObjectMapper().writeValueAsString(requestDto);

        // when
        MvcResult result = mockMvc.perform(post(url)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(jsonRequest))
                .andReturn();

        // then
        Assertions.assertThat(result.getResponse().getStatus()).isEqualTo(HttpStatus.OK.value());
    }

    @DisplayName("attempAuthentication - LoginFailureHandler : Authentication 인증 시도 / LoginFailureHandler 수행")
    @Test
    public void attemptAuthenticationMethodFailure() throws Exception {
        // given
        LoginRequestDto requestDto = new LoginRequestDto("notExistEmail@email.com", password);
        String jsonRequest = new ObjectMapper().writeValueAsString(requestDto);

        // when
        MvcResult result = mockMvc.perform(post(url)
                .contentType(MediaType.APPLICATION_JSON)
                .content(jsonRequest))
            .andReturn();

        // then
        Assertions.assertThat(result.getResponse().getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
    }

    @DisplayName("attemptAuthentication - IOException : LoginRequestDto Error로 RuntimeException 발생")
    @Test
    public void attemptAuthentication_objectMapper_readValue_IOException() throws Exception {
        // given
        String invalidJsonRequest = "{email: \"testEmail@email.com\", password: "; // 잘못된 JSON 형식

        // when & then
        Assertions.assertThatThrownBy(() -> {
            RequestBuilder requestBuilder = post(url) // 필터가 적용된 엔드포인트
                    .content(invalidJsonRequest)
                    .contentType(MediaType.APPLICATION_JSON);

            MvcResult mvcResult = mockMvc.perform(requestBuilder)
                    .andReturn();
        }).hasCauseInstanceOf(IOException.class)        // IOException 발생 여부
                .isInstanceOf(RuntimeException.class);  // api 호출 시, 결과 RuntimeException 발생 여부
    }
}
