package com.imjcm.oauth2andloginpractice.global.config.login.service;

import com.imjcm.oauth2andloginpractice.domain.member.Member;
import com.imjcm.oauth2andloginpractice.domain.member.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 *  UserDetailsService를 구현
 *  username,password 인증방식을 사용할 때 사용자를 조회하고 검증한 후, UserDetails 객체를 반환
 *  UsernamePasswordAuthenticatonFilter
 *  -> UserDetailsService
 *  -> loadByUsername()
 *  -> Member 조회 및 객체 반환
 *  -> UserDetails 객체 생성
 *  -> Authentication 객체 생성
 */
@Service
@RequiredArgsConstructor
public class LoginService implements UserDetailsService {
    private final MemberRepository memberRepository;

   /**
    *   email로 부터 Member가 존재하는지 확인
    *   존재하지 않는 email인 경우, Exception 발생
    *   Member Entity를 UserDetails를 구현체로 지정했기 때문에 Member를 반환
    */
    @Override
    public Member loadUserByUsername(String email) throws UsernameNotFoundException {
        return memberRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Not Found " + email));
    }
}
