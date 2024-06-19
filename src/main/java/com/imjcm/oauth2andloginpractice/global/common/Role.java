package com.imjcm.oauth2andloginpractice.global.common;

public enum Role {
    USER("일반 사용자"),
    ADMIN("관리자");

    private final String description;

    Role(String description) {
        this.description = description;
    }

    public String getDescription() {
        return this.description;
    }
}
