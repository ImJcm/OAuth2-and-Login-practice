package com.imjcm.oauth2andloginpractice.global.config.oauth;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

import java.util.Collection;
import java.util.Map;

@Getter
public class CustomOAuth2Member extends DefaultOAuth2User {
    public CustomOAuth2Member(Collection<? extends GrantedAuthority> authorities,
                              Map<String, Object> attributes,
                              String nameAttributeKey) {
        super(authorities, attributes, nameAttributeKey);
    }
}
