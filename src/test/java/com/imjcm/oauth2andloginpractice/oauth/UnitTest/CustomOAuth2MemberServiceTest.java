package com.imjcm.oauth2andloginpractice.oauth.UnitTest;

import com.imjcm.oauth2andloginpractice.domain.member.Member;
import com.imjcm.oauth2andloginpractice.domain.member.MemberRepository;
import com.imjcm.oauth2andloginpractice.global.common.Role;
import com.imjcm.oauth2andloginpractice.global.common.SocialType;
import com.imjcm.oauth2andloginpractice.global.config.oauth.CustomOAuth2Member;
import com.imjcm.oauth2andloginpractice.global.config.oauth.OAuth2Attribute;
import com.imjcm.oauth2andloginpractice.global.config.oauth.info.OAuth2MemberInfo;
import com.imjcm.oauth2andloginpractice.global.config.oauth.service.CustomOAuth2MemberService;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class CustomOAuth2MemberServiceTest {
    @InjectMocks
    private CustomOAuth2MemberService customOAuth2MemberService;
    @Mock
    private MemberRepository memberRepository;
    @Mock
    private DefaultOAuth2UserService defaultOAuth2UserService;


    @DisplayName("CustomOAuth2MemberService.loadUser: 성공적으로 CustomOAuth2Member 반환 - 존재하는 계정인 경우")
    @Test
    public void loadUserSuccess_ExistMember() throws Exception {
        // given
        String registrationId = "google";   // kakao, naver
        String attributeName = "sub";       // id
        OAuth2UserRequest request = mock(OAuth2UserRequest.class);
        OAuth2User user = mock(OAuth2User.class);
        Member member = mock(Member.class);
        Optional<Member> optionalMember = Optional.of(member);
        Role role = mock(Role.class);
        Map<String, Object> attribute = new HashMap<>();
        attribute.put(attributeName, "1234");
        ClientRegistration clientRegistration = mock(ClientRegistration.class);
        ClientRegistration.ProviderDetails providerDetails = mock(ClientRegistration.ProviderDetails.class);
        ClientRegistration.ProviderDetails.UserInfoEndpoint userInfoEndpoint = mock(ClientRegistration.ProviderDetails.UserInfoEndpoint.class);

        given(user.getAttributes()).willReturn(attribute);
        given(request.getClientRegistration()).willReturn(clientRegistration);
        given(clientRegistration.getRegistrationId()).willReturn(registrationId);
        given(clientRegistration.getProviderDetails()).willReturn(providerDetails);
        given(providerDetails.getUserInfoEndpoint()).willReturn(userInfoEndpoint);
        given(userInfoEndpoint.getUserNameAttributeName()).willReturn(attributeName);
        given(member.getRole()).willReturn(role);
        given(role.getAuthority()).willReturn(Role.USER.getAuthority());
        given(defaultOAuth2UserService.loadUser(any(OAuth2UserRequest.class))).willReturn(user);
        given(memberRepository.findBySocialTypeAndOauthId(any(), any()))
                .willReturn(optionalMember);

        // when
        customOAuth2MemberService.loadUser(request);

        // then
        verify(memberRepository, times(1)).findBySocialTypeAndOauthId(any(), any());
    }

    @DisplayName("CustomOAuth2MemberService.loadUser: 성공적으로 CustomOAuth2Member 반환 - 존재하지 않은 계정인 경우")
    @Test
    public void loadUserSuccess_NotExistMember() {
        // given
        String registrationId = "google";   // kakao, naver
        String attributeName = "sub";       // id
        OAuth2UserRequest request = mock(OAuth2UserRequest.class);
        OAuth2User user = mock(OAuth2User.class);
        Member member = mock(Member.class);
        Role role = mock(Role.class);
        Map<String, Object> attribute = new HashMap<>();
        attribute.put(attributeName, "1234");
        ClientRegistration clientRegistration = mock(ClientRegistration.class);
        ClientRegistration.ProviderDetails providerDetails = mock(ClientRegistration.ProviderDetails.class);
        ClientRegistration.ProviderDetails.UserInfoEndpoint userInfoEndpoint = mock(ClientRegistration.ProviderDetails.UserInfoEndpoint.class);

        given(user.getAttributes()).willReturn(attribute);
        given(request.getClientRegistration()).willReturn(clientRegistration);
        given(clientRegistration.getRegistrationId()).willReturn(registrationId);
        given(clientRegistration.getProviderDetails()).willReturn(providerDetails);
        given(providerDetails.getUserInfoEndpoint()).willReturn(userInfoEndpoint);
        given(userInfoEndpoint.getUserNameAttributeName()).willReturn(attributeName);
        given(member.getRole()).willReturn(role);
        given(role.getAuthority()).willReturn(Role.USER.getAuthority());
        given(defaultOAuth2UserService.loadUser(any(OAuth2UserRequest.class))).willReturn(user);
        given(memberRepository.findBySocialTypeAndOauthId(any(), any()))
                .willReturn(Optional.empty());
        given(memberRepository.save(any(Member.class))).willReturn(member);

        // when
        customOAuth2MemberService.loadUser(request);

        // then
        verify(memberRepository, times(1)).findBySocialTypeAndOauthId(any(), any());
        verify(memberRepository, times(1)).save(any());
    }
}
