package com.imjcm.oauth2andloginpractice.member.UnitTest;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.imjcm.oauth2andloginpractice.domain.member.MemberController;
import com.imjcm.oauth2andloginpractice.domain.member.MemberService;
import com.imjcm.oauth2andloginpractice.domain.member.dto.request.SignupRequestDto;
import com.imjcm.oauth2andloginpractice.global.common.ApiResponseDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(value = MemberController.class)
public class MemberControllerTest {
    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private MemberService memberService;

    @BeforeEach
    void setup() {
    }

    @DisplayName("controller signup : 회원가입 성공")
    @Test
    @WithMockUser
    public void signupSuccessTest() throws Exception {
        // given
        final String url = "/api/member/signup";
        SignupRequestDto signupRequestDto = new SignupRequestDto("testMember@email.com", "testMember", "testPassword");
        String content = objectMapper.writeValueAsString(signupRequestDto);

        given(memberService.signup(any(SignupRequestDto.class))).willReturn(ApiResponseDto.of("회원가입 성공", HttpStatus.OK.value()));

        // when
        ResultActions resultActions = mockMvc.perform(post(url)
                .with(csrf())
                .accept(MediaType.APPLICATION_JSON).contentType(MediaType.APPLICATION_JSON).content(content));

        // then
        resultActions.andExpect(status().isOk()).andExpect(jsonPath("$.message").value("회원가입 성공")).andExpect(jsonPath("$.statusCode").value(HttpStatus.OK.value())).andDo(print());
    }
}
