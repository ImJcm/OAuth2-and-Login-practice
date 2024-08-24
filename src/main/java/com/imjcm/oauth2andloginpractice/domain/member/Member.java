package com.imjcm.oauth2andloginpractice.domain.member;

import com.imjcm.oauth2andloginpractice.global.common.Role;
import com.imjcm.oauth2andloginpractice.global.common.SocialType;
import com.imjcm.oauth2andloginpractice.global.common.TimeStamped;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Entity
@Table(name = "members")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Getter
public class Member extends TimeStamped implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false, unique = true)
    private String nickname;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    @Enumerated(value = EnumType.STRING)
    private Role role;

    @Column
    private String oauthId;     // 로그인한 OAuth 식별자 값

    @Column
    @Enumerated(value = EnumType.STRING)
    private SocialType socialType;  // KAKAO, NAVER, GOOGLE

    @Builder
    public Member(String email, String nickname, String password, Role role, SocialType socialType, String oauthId) {
        this.email = email;
        this.nickname = nickname;
        this.password = password;
        this.role = role;
        this.socialType = socialType;
        this.oauthId = oauthId;
    }

    // 닉네임 업데이트
    public Member updateProfile(String nickname) {
        this.nickname = nickname;
        return this;
    }

    // 비밀번호 업데이트
    public Member updatePassword(String password) {
        this.password = password;
        return this;
    }

    public Member updateSocialType(SocialType socialType) {
        this.socialType = socialType;
        return this;
    }

    // 권한 반환
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(this.role.getAuthority()));
    }

    // 사용자의 email 반환
    @Override
    public String getUsername() {
        return this.email;
    }

    // 계정 만료 여부 반환
    @Override
    public boolean isAccountNonExpired() {
        return true; // 만료되지 않음
    }

    // 계정 잠금 여부 반환
    @Override
    public boolean isAccountNonLocked() {
        return true; // 잠금되지 않음
    }

    // 패스워드 만료 여부 반환
    @Override
    public boolean isCredentialsNonExpired() {
        return true; // 만료되지 않음
    }

    // 계정 사용 가능 여부 반환
    @Override
    public boolean isEnabled() {
        return true; // 사용 가능
    }
}
