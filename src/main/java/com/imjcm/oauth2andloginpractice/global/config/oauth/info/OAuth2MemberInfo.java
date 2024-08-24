package com.imjcm.oauth2andloginpractice.global.config.oauth.info;

import lombok.AllArgsConstructor;

import java.util.Map;

@AllArgsConstructor
public abstract class OAuth2MemberInfo {
    protected Map<String, Object> attribute;

    public abstract String getId();
    public abstract String getEmail();
    public abstract String getNickname();
    //public abstract String getImageUrl();
}
