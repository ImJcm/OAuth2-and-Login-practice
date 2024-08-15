package com.imjcm.oauth2andloginpractice.global.config.oauth.service;

import com.imjcm.oauth2andloginpractice.domain.member.Member;
import com.imjcm.oauth2andloginpractice.domain.member.MemberRepository;
import com.imjcm.oauth2andloginpractice.global.common.PasswordUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

@RequiredArgsConstructor
@Service
public class OAuth2MemberService extends DefaultOAuth2UserService {
    private final MemberRepository memberRepository;

    private PasswordUtil passwordUtil;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User member = super.loadUser(userRequest);
        saveOrUpdate(member);
        return member;
    }

    private void saveOrUpdate(OAuth2User oAuth2Member) {
        Map<String, Object> attributes = oAuth2Member.getAttributes();
        String email = (String) attributes.get("email");
        String name = (String) attributes.get("name");
        Member member = memberRepository.findByEmail(email)
                .map(entity -> entity.updateProfile(name))
                .orElse(
                        Member.builder()
                                .email(email)
                                .nickname(name)
                                .password(passwordUtil.generateRandomPassword())
                                .build()
                );
        memberRepository.save(member);
    }
}
