package com.imjcm.oauth2andloginpractice.oauth.IntegratedTest;

import com.imjcm.oauth2andloginpractice.domain.member.Member;
import com.imjcm.oauth2andloginpractice.domain.member.MemberRepository;
import com.imjcm.oauth2andloginpractice.global.common.Role;
import com.imjcm.oauth2andloginpractice.global.common.SocialType;
import com.imjcm.oauth2andloginpractice.global.config.oauth.service.CustomOAuth2MemberService;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

@SpringBootTest
public class CustomOAuth2MemberServiceTest {
    @Autowired
    private CustomOAuth2MemberService customOAuth2MemberService;

    @Autowired
    private MemberRepository memberRepository;

    @MockBean
    private DefaultOAuth2UserService defaultOAuth2UserService;

    private Member testMember;

    private void testMemberInsert() {
        testMember = Member.builder()
                        .email("testOAuthEmail@email.com")
                        .nickname("testOAuthMember")
                        .password("123")
                        .role(Role.USER)
                        .socialType(SocialType.GOOGLE)
                        .oauthId("1234")
                        .build();
        memberRepository.save(testMember);
    }

    @AfterEach
    public void init() {
        testMember = memberRepository.findByEmail("testOAuthEmail@email.com").orElse(null);
        if(testMember != null) memberRepository.delete(testMember);
    }

    @DisplayName("CustomOAuth2MemberService.loadUser: 성공적으로 CustomOAuth2Member 반환 - 존재하는 계정인 경우")
    @Test
    public void loadUserSuccess_ExistMember() {
        // given
        testMemberInsert();

        String registrationId = "google";   // kakao, naver
        String attributeName = "sub";       // id
        String emailName = "email";
        String nickName = "name";
        String passwordName = "password";
        String roleName = "role";
        String socialTypeName = "socialType";
        OAuth2UserRequest request = mock(OAuth2UserRequest.class);
        OAuth2User user = mock(OAuth2User.class);
        Member member = mock(Member.class);
        Optional<Member> optionalMember = Optional.of(member);
        Role role = mock(Role.class);
        Map<String, Object> attribute = new HashMap<>();
        attribute.put(emailName, "testOAuthEmail@email.com");
        attribute.put(nickName, "testOAuthMember");
        attribute.put(passwordName, "123");
        attribute.put(roleName, Role.USER);
        attribute.put(socialTypeName, SocialType.GOOGLE);
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

        // when
        OAuth2User result = customOAuth2MemberService.loadUser(request);

        // then
        Assertions.assertThat(result.getAttributes().get(attributeName)).isEqualTo("1234");
        Assertions.assertThat(result.getAttributes().get(emailName)).isEqualTo("testOAuthEmail@email.com");
        Assertions.assertThat(result.getAttributes().get(nickName)).isEqualTo("testOAuthMember");
        Assertions.assertThat(result.getAttributes().get(passwordName)).isEqualTo("123");
        Assertions.assertThat(result.getAttributes().get(roleName)).isEqualTo(Role.USER);
        Assertions.assertThat(result.getAttributes().get(socialTypeName)).isEqualTo(SocialType.GOOGLE);
    }

    /*
        비관리 의존성 DefaultOAuth2UserService를 Bean 객체로 Mocking하여 통합테스트 진행
     */
    @DisplayName("CustomOAuth2MemberService.loadUser: 성공적으로 CustomOAuth2Member 반환 - 존재하지 않은 계정인 경우")
    @Test
    public void loadUserSuccess_NotExistMember() {
        // given
        String registrationId = "google";   // kakao, naver
        String attributeName = "sub";       // id
        String emailName = "email";
        String nickName = "name";
        String passwordName = "password";
        String roleName = "role";
        String socialTypeName = "socialType";
        OAuth2UserRequest request = mock(OAuth2UserRequest.class);
        OAuth2User user = mock(OAuth2User.class);
        Member member = mock(Member.class);
        Optional<Member> optionalMember = Optional.of(member);
        Role role = mock(Role.class);
        Map<String, Object> attribute = new HashMap<>();
        attribute.put(emailName, "testOAuthEmail@email.com");
        attribute.put(nickName, "testOAuthMember");
        attribute.put(passwordName, "123");
        attribute.put(roleName, Role.USER);
        attribute.put(socialTypeName, SocialType.GOOGLE);
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

        // when
        OAuth2User result = customOAuth2MemberService.loadUser(request);

        // then
        Assertions.assertThat(result.getAttributes().get(attributeName)).isEqualTo("1234");
        Assertions.assertThat(result.getAttributes().get(emailName)).isEqualTo("testOAuthEmail@email.com");
        Assertions.assertThat(result.getAttributes().get(nickName)).isEqualTo("testOAuthMember");
        Assertions.assertThat(result.getAttributes().get(passwordName)).isEqualTo("123");
        Assertions.assertThat(result.getAttributes().get(roleName)).isEqualTo(Role.USER);
        Assertions.assertThat(result.getAttributes().get(socialTypeName)).isEqualTo(SocialType.GOOGLE);
    }
}
