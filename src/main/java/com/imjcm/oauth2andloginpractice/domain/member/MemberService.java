package com.imjcm.oauth2andloginpractice.domain.member;

import com.imjcm.oauth2andloginpractice.domain.member.dto.request.LoginRequestDto;
import com.imjcm.oauth2andloginpractice.domain.member.dto.request.PasswordRequestDto;
import com.imjcm.oauth2andloginpractice.domain.member.dto.request.ProfileRequestDto;
import com.imjcm.oauth2andloginpractice.domain.member.dto.request.SignupRequestDto;
import com.imjcm.oauth2andloginpractice.domain.member.dto.response.ProfileResponseDto;
import com.imjcm.oauth2andloginpractice.global.common.ApiResponseDto;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class MemberService {
    private final MemberRepository memberRepository;

    public ApiResponseDto login(LoginRequestDto loginRequestDto, HttpServletResponse response) {
        Member member = findByEmail(loginRequestDto.getEmail());

        if(!member.getPassword().equals(loginRequestDto.getPassword())) {
            throw new IllegalArgumentException("비밀번호가 일치하지 않습니다.");
        }

        return ApiResponseDto.of("로그인 성공", HttpStatus.OK.value());
    }

    public ApiResponseDto signup(SignupRequestDto signupRequestDto) {
        if(existByEmail(signupRequestDto.getEmail())) {
            throw new IllegalArgumentException("중복된 이메일입니다.");
        }

        memberRepository.save(Member.builder()
                .email(signupRequestDto.getEmail())
                .nickname(signupRequestDto.getNickname())
                .password(signupRequestDto.getPassword())
                .build()
        );

        return ApiResponseDto.of("회원가입 성공", HttpStatus.OK.value());
    }

    @Transactional
    public ApiResponseDto updateProfile(ProfileRequestDto profileRequestDto) {
        Member member = getMemberByAuthentication();

        member.updateProfile(profileRequestDto.getNickname());

        return ApiResponseDto.of("프로필 수정 성공", HttpStatus.OK.value());
    }

    @Transactional
    public ApiResponseDto updatePassword(PasswordRequestDto passwordRequestDto) {
        Member member = getMemberByAuthentication();

        passwordEqualCheck(member.getPassword(), passwordRequestDto.getPassword());

        member.updatePassword(passwordRequestDto.getChangedPassword());

        return ApiResponseDto.of("비밀번호 변경 성공", HttpStatus.OK.value());
    }

    public ApiResponseDto deleteProfile(PasswordRequestDto passwordRequestDto) {
        Member member = getMemberByAuthentication();

        passwordEqualCheck(member.getPassword(), passwordRequestDto.getPassword());

        memberRepository.delete(member);

        return ApiResponseDto.of("회원탈퇴 성공", HttpStatus.OK.value());
    }


    public ProfileResponseDto getProfile() {
        Member member = getMemberByAuthentication();

        return ProfileResponseDto.of(member);
    }

    public boolean passwordEqualCheck(String pPw, String Pw) {
        if(!pPw.equals(Pw)) {
            throw new IllegalArgumentException("현재 비밀번호가 일치하지 않습니다.");
        }

        return true;
    }

    public Member getMemberByAuthentication() {
        String email = SecurityContextHolder.getContext().getAuthentication().getName();

        return findByEmail(email);
    }

    public Member findByEmail(String email) {
        return memberRepository.findByEmail(email).orElseThrow(() -> new IllegalArgumentException("존재하지 않는 이메일입니다."));
    }

    public boolean existByEmail(String email) {
        return memberRepository.existsByEmail(email);
    }
}
