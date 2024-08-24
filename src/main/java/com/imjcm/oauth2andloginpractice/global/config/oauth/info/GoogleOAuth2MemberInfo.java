package com.imjcm.oauth2andloginpractice.global.config.oauth.info;

import java.util.Map;

public class GoogleOAuth2MemberInfo extends OAuth2MemberInfo {
    public GoogleOAuth2MemberInfo(Map<String, Object> attribute) {
        super(attribute);
    }

    @Override
    public String getId() {
        return (String) attribute.get("sub");
    }

    @Override
    public String getEmail() {
        return (String) attribute.get("email");
    }

    @Override
    public String getNickname() {
        return (String) attribute.get("name");
    }

    /*@Override
    public String getImageUrl() {
        return (String) attribute.get("picture");
    }*/
}
