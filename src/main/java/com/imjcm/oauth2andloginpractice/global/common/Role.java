package com.imjcm.oauth2andloginpractice.global.common;

public enum Role {
    USER(Authority.USER),
    ADMIN(Authority.ADMIN);

    private final String authority;

    Role(String authority) {
        this.authority = authority;
    }

    public String getAuthority() {
        return this.authority;
    }

    public static Role getRoleType(String authority) {
        Role role = null;
        switch (authority) {
            case "ROLE_USER":
                role = Role.USER;
                break;
            case "ROLE_ADMIN":
                role = Role.ADMIN;
                break;
        }
        return role;
    }

    public static class Authority {
        public static final String USER = "ROLE_USER";
        public static final String ADMIN = "ROLE_ADMIN";
    }
}
