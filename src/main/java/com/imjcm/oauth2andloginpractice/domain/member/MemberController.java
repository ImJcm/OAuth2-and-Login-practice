package com.imjcm.oauth2andloginpractice.domain.member;

import com.imjcm.oauth2andloginpractice.domain.member.dto.request.LoginRequestDto;
import com.imjcm.oauth2andloginpractice.domain.member.dto.request.PasswordRequestDto;
import com.imjcm.oauth2andloginpractice.domain.member.dto.request.ProfileRequestDto;
import com.imjcm.oauth2andloginpractice.domain.member.dto.request.SignupRequestDto;
import com.imjcm.oauth2andloginpractice.domain.member.dto.response.ProfileResponseDto;
import com.imjcm.oauth2andloginpractice.global.common.ApiResponseDto;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
@RequiredArgsConstructor
@RequestMapping("/api/member")
public class MemberController {
    private final MemberService memberService;

    @PostMapping("/login")
    public ResponseEntity<ApiResponseDto> login(@RequestBody LoginRequestDto loginRequestDto, HttpServletResponse response) {
        ApiResponseDto apiResponseDto = memberService.login(loginRequestDto, response);
        return ResponseEntity.ok().body(apiResponseDto);
    }

    @PostMapping("/signup")
    public ResponseEntity<ApiResponseDto> signup(@RequestBody SignupRequestDto signupRequestDto) {
        ApiResponseDto apiResponseDto = memberService.signup(signupRequestDto);
        return ResponseEntity.ok().body(apiResponseDto);
    }

    @GetMapping("/profile")
    public ResponseEntity<ProfileResponseDto> getProfile() {
        ProfileResponseDto profileResponseDto = memberService.getProfile();
        return ResponseEntity.ok().body(profileResponseDto);
    }

    @PutMapping("/profile")
    public ResponseEntity<ApiResponseDto> updateProfile(@RequestBody ProfileRequestDto profileRequestDto) {
        ApiResponseDto apiResponseDto = memberService.updateProfile(profileRequestDto);
        return ResponseEntity.ok().body(apiResponseDto);
    }

    @PutMapping("/password")
    public ResponseEntity<ApiResponseDto> updatePassword(@RequestBody PasswordRequestDto passwordRequestDto) {
        ApiResponseDto apiResponseDto = memberService.updatePassword(passwordRequestDto);
        return ResponseEntity.ok().body(apiResponseDto);
    }

    @DeleteMapping("/profile")
    public ResponseEntity<ApiResponseDto> delete(@RequestBody PasswordRequestDto passwordRequestDto) {
        ApiResponseDto apiResponseDto = memberService.deleteProfile(passwordRequestDto);
        return ResponseEntity.ok().body(apiResponseDto);
    }


}
