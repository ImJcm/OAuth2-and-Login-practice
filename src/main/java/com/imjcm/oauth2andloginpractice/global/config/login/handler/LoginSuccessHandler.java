package com.imjcm.oauth2andloginpractice.global.config.login.handler;

import com.imjcm.oauth2andloginpractice.domain.member.Member;
import com.imjcm.oauth2andloginpractice.domain.member.MemberRepository;
import com.imjcm.oauth2andloginpractice.global.common.Role;
import com.imjcm.oauth2andloginpractice.global.config.jwt.service.JwtService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import java.io.IOException;

@Slf4j(topic = "로그인 인증 성공")
@RequiredArgsConstructor
public class LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final JwtService jwtService;
    private final MemberRepository memberRepository;

    @Value("${jwt.access.expiration}")
    private String accessTokenExpiration;

    /**
     * UsernamePasswordAuthenticationFilter로 부터 인증을 마친 후, 인증이 성공할 경우 로직을 처리하는 onAuthenticationSuccess 메서드 수행한다.
     * AccessToken을 생성한 후, Header를 통해 token을 전달한다.
     * @param request
     * @param response
     * @param authentication
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        String email = extractEmail(authentication);
        Role role = extractRole(authentication);

        String token = jwtService.createAccessToken(email, role);

        jwtService.sendAccessToken(response, token);

        log.info("로그인 성공 - email : {}",email);
        log.info("로그인 성공 - AccessToken : {}",token);
        log.info("로그인 성공 - AccessToken Expiration : {}",accessTokenExpiration);
    }

    /**
     * Authentication 객체의 Principal에 저장된 UserDetails 객체에서 email을 추출
     * Member는 UserDetails를 상속하기 때문에 Member타입으로 캐스팅하여 getPrincipal을 통해 받는다.
     * @param authentication
     * @return
     */
    private String extractEmail(Authentication authentication) {
        Member userDetails = (Member) authentication.getPrincipal();
        return userDetails.getEmail();
    }

    /**
     * Authentication 객체의 Principal에 저장된 UserDetails 객체에서 role을 추출
     * Member는 UserDetails를 상속하기 때문에 Member타입으로 캐스팅하여 getPrincipal을 통해 받는다.
     * @param authentication
     * @return
     */
    private Role extractRole(Authentication authentication) {
        Member userDetails = (Member) authentication.getAuthorities();
        return userDetails.getRole();
    }
}
