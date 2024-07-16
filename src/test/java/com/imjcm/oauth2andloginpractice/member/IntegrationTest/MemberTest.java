package com.imjcm.oauth2andloginpractice.member.IntegrationTest;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.imjcm.oauth2andloginpractice.domain.member.Member;
import com.imjcm.oauth2andloginpractice.domain.member.MemberRepository;
import com.imjcm.oauth2andloginpractice.domain.member.MemberService;
import com.imjcm.oauth2andloginpractice.domain.member.dto.request.SignupRequestDto;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
public class MemberTest {
    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private MemberService memberService;

    @Autowired
    private MemberRepository memberRepository;

    @Autowired
    private ObjectMapper objectMapper;

    @BeforeEach
    void init() {
        memberRepository.deleteAll();   // 데이터 초기화
    }

    @DisplayName("signup Test : 회원가입 성공")
    @Test
    public void signupSuccessTest() throws Exception {
        // given
        SignupRequestDto signupRequestDto = new SignupRequestDto("testEmail@email.com","tester","testPassword");
        final String requestDto_json = objectMapper.writeValueAsString(signupRequestDto);

        // when
        ResultActions result = mockMvc.perform(post("/api/member/signup")
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .content(requestDto_json));

        // then
        result.andExpect(status().isOk());

        List<Member> members = memberRepository.findAll();

        Assertions.assertThat(members.size()).isEqualTo(1);
        Assertions.assertThat(members.get(0).getEmail()).isEqualTo(signupRequestDto.getEmail());
        Assertions.assertThat(members.get(0).getNickname()).isEqualTo(signupRequestDto.getNickname());
    }

}
