package com.imjcm.oauth2andloginpractice.global.config.jwt.filter;

import com.imjcm.oauth2andloginpractice.global.config.jwt.service.JwtService;
import com.imjcm.oauth2andloginpractice.global.config.login.service.LoginService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if(request.getRequestURI().equals(CHECK_URL)) {
            filterChain.doFilter(request,response);
            return;
        }

        //String tokenValue = jwtService.getTokenFromRequest(request);

        // Token 문자열 검사 : notnull, bigger size than empty String, Not Blank String;
        /*if(StringUtils.hasText(tokenValue)) {
            tokenValue = jwtService.subStringToken(tokenValue);
        }*/
    }
}
