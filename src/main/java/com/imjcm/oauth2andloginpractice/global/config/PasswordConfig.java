package com.imjcm.oauth2andloginpractice.global.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class PasswordConfig {
    /**
     * Spring Security에서 제공하는 BCrypt Hashing 함수로 패스워드를 암호화하는 함수
     * 해싱 함수 -> 암호화는 가능하지만 암호화된 문자열을 복화화하여 원본 문자열을 알아내는 것이 불가능
     * 따라서, 단방향 암호화이다.
     * 비밀번호를 비교할 때는 secret Key로 암호화된 문자열을 DB에 회원 객체와 비교
     * @return  PasswordEncoder 객체 반환
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
