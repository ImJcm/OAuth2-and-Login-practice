package com.imjcm.oauth2andloginpractice.member.UnitTest;

import com.imjcm.oauth2andloginpractice.domain.member.Member;
import com.imjcm.oauth2andloginpractice.domain.member.MemberRepository;
import com.imjcm.oauth2andloginpractice.domain.member.MemberService;
import com.imjcm.oauth2andloginpractice.domain.member.dto.request.SignupRequestDto;
import com.imjcm.oauth2andloginpractice.global.common.ApiResponseDto;
import com.imjcm.oauth2andloginpractice.global.common.Role;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

@ExtendWith(MockitoExtension.class)
public class MemberServiceTest {
    @InjectMocks
    private MemberService memberService;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private MemberRepository memberRepository;

    @DisplayName("service signup test : 회원가입 성공")
    @Test
    public void signupSuccessTest() throws Exception {
        // given
        SignupRequestDto signupRequestDto = new SignupRequestDto("testMember@email.com", "testMember", "testPassword");
        Member member = Member.builder()
                .email(signupRequestDto.getEmail())
                .nickname(signupRequestDto.getNickname())
                .password(passwordEncoder.encode(signupRequestDto.getPassword()))
                .role(Role.USER)
                .build();

        given(memberRepository.save(ArgumentMatchers.any(Member.class)))
                .willReturn(member);

        // when
        ApiResponseDto result = memberService.signup(signupRequestDto);

        // then
        Assertions.assertThat(result.message).isEqualTo("회원가입 성공");
        Assertions.assertThat(result.statusCode).isEqualTo(HttpStatus.OK.value());
    }

    @DisplayName("service existByEmail : 이메일 중복 검사 성공")
    @Test
    public void existByEmailSuccessTest() throws Exception {
        // given
        String email = "testEmail@email.com";

        given(memberRepository.existsByEmail(any(String.class)))
                .willReturn(true);

        // when
        boolean result = memberService.existByEmail(email);

        // then
        Assertions.assertThat(result).isEqualTo(true);
    }

    @DisplayName("service existByEmail : 이메일 중복 검사 실패 - 중복 예외 발생")
    @Test
    public void existByEmailFailureTest() throws Exception {
        // given
        String email = "testEmail@email.com";

        given(memberRepository.existsByEmail(ArgumentMatchers.anyString()))
                .willReturn(false);

        // when
        boolean result = memberService.existByEmail(email);

        // then
        Assertions.assertThat(result).isEqualTo(false);
    }
}
