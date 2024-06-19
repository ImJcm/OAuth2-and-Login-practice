package com.imjcm.oauth2andloginpractice.domain.member.dto.response;

import com.imjcm.oauth2andloginpractice.domain.member.Member;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class ProfileResponseDto {
    private String email;
    private String nickname;

    public static ProfileResponseDto of(Member member) {
        return ProfileResponseDto.builder()
                .email(member.getEmail())
                .nickname(member.getNickname())
                .build();
    }
}
