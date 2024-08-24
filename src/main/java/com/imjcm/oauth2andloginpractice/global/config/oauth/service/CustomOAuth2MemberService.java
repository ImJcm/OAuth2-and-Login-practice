package com.imjcm.oauth2andloginpractice.global.config.oauth.service;

import com.imjcm.oauth2andloginpractice.domain.member.Member;
import com.imjcm.oauth2andloginpractice.domain.member.MemberRepository;
import com.imjcm.oauth2andloginpractice.global.common.SocialType;
import com.imjcm.oauth2andloginpractice.global.config.oauth.CustomOAuth2Member;
import com.imjcm.oauth2andloginpractice.global.config.oauth.OAuth2Attribute;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Map;

@RequiredArgsConstructor
@Service
public class CustomOAuth2MemberService extends DefaultOAuth2UserService {
    private final MemberRepository memberRepository;

    /**
     * code, client_id, client_secrets를 통해 AccessToken을 발급받고, AccessToken으로 사용자 정보를 받은 정보를 가공하기 위한 메서드
     *
     * @param userRequest
     * @return
     * @throws OAuth2AuthenticationException
     */
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2Member = super.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        SocialType socialType = getSocialType(registrationId);
        String userNameAttributeName = userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();
        Map<String, Object> attribute = oAuth2Member.getAttributes();

        OAuth2Attribute oAuth2attribute = OAuth2Attribute.of(socialType, userNameAttributeName, attribute);

        Member createdMember = getMember(oAuth2attribute, socialType);

        return new CustomOAuth2Member(
                Collections.singleton(new SimpleGrantedAuthority(createdMember.getRole().getAuthority())),
                attribute,
                oAuth2attribute.getNameAttributeKey()
        );
    }


    /**
     * socialType과 OAuthId에 해당하는 계정이 이미 로그인한 전적이 있는지 확인하고 해당 계정이 존재하면 해당 계정을 반환하거나
     * 새로운 계정인 경우, saveMember를 통해 새로운 계정으로 생성한 후 반환한다.
     *
     * 자체 회원가입을 통한 계정과 oAuth 로그인을 통한 계정 생성에서 충돌이 일어날 수 있기 때문에 어떤 방식으로 계정 처리를 할 것인지 결정해야함.
     * 해결방법으로
     * 1. 계정을 통합하는 방식
     *  - 방법 : 동일한 이메일을 사용하는 계정이 이미 존재하는 경우, 통합 옵션을 제공하고 두 계정을 통합하여 사용한다.
     *  - 장점 : 사용자는 자체 로그인과 OAuth 로그인 방식을 자유롭게 선택할 수 있고 계정 관리가 단순화된다.
     *  - 단점 : 사용자 동의 절차가 필요하며, 통합 과정에서 신중한 검증이 필요하다.
     *
     * 2. OAuth 로그인 실패 처리
     *  - 방법 : 회원가입 또는 OAuth 로그인 시, 이미 존재하는 이메일이 있다면 로그인 또는 회원가입 실패 처리
     *  - 장점 : 보안이 강화되고, 사용자에게 명확한 로그인 방법을 제공한다.
     *  - 단점 : 사용자는 로그인 방법에 유연성이 없어질 수 있다.
     *
     * 3. 자체 로그인 계정과 OAuth 로그인 계정으로 사용하는 방식
     *  - 방법 : 자체 회원가입 계정과 OAuth 계정은 동일한 이메일을 가지고 두 계정을 별도로 관리
     *  - 장점 : 계정 간의 혼동이 적고, 명확하게 구분된 계정 관리가 가능하다.
     *  - 단점 : 사용자가 두 개의 계정을 갖게 되어 관리함에 있어서 복잡할 수 있다.
     * 3가지 방법 중 고려할 수 있다.
     *
     * 현재 구현된 로직은 3번이다.
     * @param oAuth2attribute
     * @param socialType
     * @return
     */
    private Member getMember(OAuth2Attribute oAuth2attribute, SocialType socialType) {
        Member findMember = memberRepository.findBySocialTypeAndOauthId(socialType, oAuth2attribute.getOAuth2MemberInfo().getId())
                .orElse(null);

        if(findMember == null) {
            return saveMember(oAuth2attribute, socialType);
        }
        return findMember;
    }

    private Member saveMember(OAuth2Attribute oAuth2Attribute, SocialType socialType) {
        Member createdMember = oAuth2Attribute.toEntity(oAuth2Attribute.getOAuth2MemberInfo(), socialType);
        return memberRepository.save(createdMember);
    }

    private SocialType getSocialType(String registrationId) {
        SocialType socialType = null;

        switch (registrationId) {
            case "kakao":
                socialType = SocialType.KAKAO;
                break;
            case "google":
                socialType = SocialType.GOOGLE;
                break;
            case "naver":
                socialType = SocialType.NAVER;
                break;
        }
        return socialType;
    }
}
