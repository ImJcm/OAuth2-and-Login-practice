package com.imjcm.oauth2andloginpractice.global.config.oauth;

import com.imjcm.oauth2andloginpractice.domain.member.Member;
import com.imjcm.oauth2andloginpractice.global.common.PasswordUtil;
import com.imjcm.oauth2andloginpractice.global.common.Role;
import com.imjcm.oauth2andloginpractice.global.common.SocialType;
import com.imjcm.oauth2andloginpractice.global.config.oauth.info.GoogleOAuth2MemberInfo;
import com.imjcm.oauth2andloginpractice.global.config.oauth.info.OAuth2MemberInfo;
import lombok.Builder;
import lombok.Getter;

import java.util.Map;

@Getter
public class OAuth2Attribute {
    private String nameAttributeKey;
    private OAuth2MemberInfo oAuth2MemberInfo;

    @Builder
    public OAuth2Attribute(String nameAttributeKey, OAuth2MemberInfo oAuth2MemberInfo) {
        this.nameAttributeKey = nameAttributeKey;
        this.oAuth2MemberInfo = oAuth2MemberInfo;
    }

    public static OAuth2Attribute of(SocialType socialType, String nameAttributeKey, Map<String, Object> attribute) {
        return switch (socialType) {
            case KAKAO -> null; //ofKakao(nameAttributeKey, attribute);
            case NAVER -> null; //ofNaver(nameAttributeKey, attribute);
            case GOOGLE -> ofGoogle(nameAttributeKey, attribute);
        };
    }

    private static OAuth2Attribute ofGoogle(String nameAttributeKey, Map<String, Object> attribute) {
        return OAuth2Attribute.builder()
                .nameAttributeKey(nameAttributeKey)
                .oAuth2MemberInfo(new GoogleOAuth2MemberInfo(attribute))
                .build();
    }

    public Member toEntity(OAuth2MemberInfo oAuth2MemberInfo, SocialType socialType) {
        return Member.builder()
                .socialType(socialType)
                .oauthId(oAuth2MemberInfo.getId())
                .role(Role.USER)
                .email(oAuth2MemberInfo.getEmail())
                .password(PasswordUtil.generateRandomPassword())
                .nickname(oAuth2MemberInfo.getNickname())
                .build();
    }

}
