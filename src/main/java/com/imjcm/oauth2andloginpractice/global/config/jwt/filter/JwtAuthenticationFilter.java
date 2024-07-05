package com.imjcm.oauth2andloginpractice.global.config.jwt.filter;

import com.imjcm.oauth2andloginpractice.domain.member.Member;
import com.imjcm.oauth2andloginpractice.domain.member.MemberRepository;
import com.imjcm.oauth2andloginpractice.global.config.jwt.service.JwtService;
import com.imjcm.oauth2andloginpractice.global.config.login.service.LoginService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 *  JWT Authorization(인가) 필터
 *  JWT 토큰을 검증하여
 */
@Slf4j(topic = "JWT 검증 및 인가")
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private static final String CHECK_URL = "/api/member/login";

    private final JwtService jwtService;
    private final LoginService loginService;
    private final MemberRepository memberRepository;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if(request.getRequestURI().equals(CHECK_URL)) {
            filterChain.doFilter(request,response);
            return;
        }

        String token = jwtService.getAccessTokenFromHeader(request)
                .filter(jwtService::validateToken)
                .orElse(null);

        if(token != null) {
            try {
                jwtService.extractEmailFromToken(token)
                        .ifPresent(this::saveAuthentication);
            } catch (Exception e) {
                log.error(e.getMessage());
                return;
            }
        } else {
            log.error("Token Error");
            return;
        }

        filterChain.doFilter(request,response);
    }

    /**
     * email로부터 실제 DB에서 사용자를 조회한 후, UsernamePasswordAuthneitcationToken로 인증 객체인 Authentication 객체 생성
     * UsernamePasswordAuthenticationToken의 인자
     * 1. UserDetails : email로부터 실제 DB에 저장된 유저 객체
     * 2. credential(보통 비밀번호를 의미, 인증 시에는 null로 제거)
     * 3. Authorities로 Collection < ? extends GrantedAuthority>의 타입으로 유저의 권한을 저장하고 있다.
     *
     * SecurityContextHolder에 저장 만들어진 Authentication = UsernamePasswordAuthenticationToken을 저장한다.
     * 이후, Controller에서 @AuthneitcationPrincipal을 통해 전역적으로 인증된 Authentication 객체로서 사용된다.
     *
     * @param email
     */
    public void saveAuthentication(String email) {
        UserDetails userDetails = loginService.loadUserByUsername(email);

        Authentication authentication = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities()
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

}
