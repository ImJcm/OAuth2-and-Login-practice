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
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 *  JWT Authorization(인가) 필터
 *  JWT 토큰을 검증하여
 */
@Slf4j(topic = "JWT 검증 및 인가")
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private static final String NO_CHECK_URL = "/api/member/login";

    private final JwtService jwtService;
    private final LoginService loginService;
    private final MemberRepository memberRepository;

    /**
     * "/api/member/login"에 해당하는 요청인 경우, 해당 필터를 거치지 않고 다음 필터로 이동
     * - RefreshToken 검사
     * RefreshToken이 null이 아니라면, refreshToken에서 email을 추출한 후, 추출한 이메일이 정상적인 사용자의 이메일인지 확인한 후
     * 해당 이메일로 AccessToken, RefreshToken을 재생성 및 발급 수행한다.
     *
     * null이라면, checkAcessTokenAndAuthentication()을 수행한다.
     *
     * - checkAccessTokenAndAuthentication()
     * 그외 요창인 경우, request로부터 AccessToken을 추출한다.
     * 추출한 AccessToken에서 validateToken을 거쳐 토큰 유효성 검사를 수행한다.
     * AccessToken이 없거나, 유효성 검사에 실패한 경우 null을 반환하고 다음 필터로 이동한다.
     *
     * 토큰이 null이 아닌 경우, token으로부터 Claim을 추출하고, claims에서 email을 추출하고 이메일이 존재할 경우,
     * saveAuthentication(email)을 수행한다.
     *
     * 토큰이 null인 경우, 다음 필터로 넘어가더라도, Authentication을 요구하는 API인 경우, 해당 메서드에서
     * 에러가 발생할 것이다.
     *
     * 위 과정을 모두 마친 후, 해당 필터에서 다음 필터로 이동시킨다.(filterChain.doFilter(req,res))
     *
     * @param request
     * @param response
     * @param filterChain
     * @throws ServletException
     * @throws IOException
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if(request.getRequestURI().equals(NO_CHECK_URL)) {
            filterChain.doFilter(request,response);
            return;
        }

        String refreshToken = jwtService.getRefreshTokenFromHeader(request)
                .filter(jwtService::validateToken)
                .orElse(null);

        if(refreshToken != null) {
            if(jwtService.isEqualsRefreshToken(refreshToken)) {
                checkRefreshTokenAndReIssueAccessToken(response, refreshToken);
            } else {
                jwtService.deleteRefreshTokenByRefreshToken(refreshToken);
                deleteAuthentication();
            }
            return;
        }

        checkAccessTokenAndAuthentication(request,response,filterChain);
    }

    /**
     * Filter에서 RefreshToken이 null인 경우, AccessToken으로 인증을 수행하는 것으로 AccessToken의 유효성 검사 후,
     * AccessToken에서 email을 추출하고 해당 이메일이 존재하는 이메일인지 검사하고 이메일에 해당하는 RefreshToken이 존재하는지 여부를 확인 후,
     * 이메일을 사용하는 사용자의 이메일을 SecurityContextHolder에 Authentication을 등록하여 인증을 수행한다.
     *
     * email에 해당하는 RefreshToken이 존재하지 않거나, email에 해당하는 사용자가 없거나, AccessToken에서 email을 추출했을 때 없거나,
     * AccessToken이 유효하지 않은 경우, Authentication을 등록하지 않는다.
     *
     * @param request
     * @param response
     * @param filterChain
     * @throws ServletException
     * @throws IOException
     */
    public void checkAccessTokenAndAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        jwtService.getAccessTokenFromHeader(request)
                .filter(jwtService::validateToken)
                .flatMap(accessToken -> jwtService.extractEmailFromToken(accessToken)
                .flatMap(memberRepository::findByEmail))
                .flatMap(member -> jwtService.getRefreshTokenFromRedisThroughEmail(member.getEmail()))
                .ifPresent(refreshToken -> saveAuthentication(jwtService.extractEmailFromToken(refreshToken).get()));

        filterChain.doFilter(request,response);

        /*
        String accessToken = jwtService.getAccessTokenFromHeader(request)
                .filter(jwtService::validateToken)
                .orElse(null);

        if(accessToken != null) {
            try {
                jwtService.extractEmailFromToken(accessToken)
                        .ifPresent(this::saveAuthentication);
            } catch (Exception e) {
                log.error(e.getMessage());
                return;
            }
        } else {
            log.info("Token is Null");
        }
         */
    }

    /**
     * email로부터 실제 DB에서 사용자를 조회한 후, UsernamePasswordAuthneitcationToken로 인증 객체인 Authentication 객체 생성
     * UsernamePasswordAuthenticationToken의 인자
     * 1. UserDetails : email로부터 실제 DB에 저장된 유저 객체 - UserDetailsService를 상속한 loginService의 loadUserByUsername() 이용
     * 2. credential(보통 비밀번호를 의미, 인증 시에는 null로 제거)
     * 3. Authorities로 Collection < ? extends GrantedAuthority>의 타입으로 유저의 권한을 저장하고 있다.
     *
     * SecurityContextHolder에 저장 만들어진 Authentication = UsernamePasswordAuthenticationToken을 저장한다.
     * 이후, Controller에서 @AuthneitcationPrincipal을 통해 전역적으로 인증된 Authentication 객체로서 사용된다.
     *
     * @param email
     */
    public void saveAuthentication(String email) {
        Member userDetails = loginService.loadUserByUsername(email);

        Authentication authentication = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities()
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    /**
     * Header에 RefreshToken이 존재하면 수행하는 메서드로, RefreshToken에서 email을 추출하여 이메일에 해당하는 사용자가 존재하는지
     * 확인 후, AccessToken, RefreshToken을 재생성한 후, Redis DB에 업데이트하고 클라이언트에게 재발급한다.
     *
     * @param response
     * @param refreshToken
     */
    public void checkRefreshTokenAndReIssueAccessToken(HttpServletResponse response, String refreshToken) {
        String email = jwtService.extractEmailFromToken(refreshToken).get();

        memberRepository.findByEmail(email)
                .ifPresent(member -> {
                    String reIssuedRefreshToken = jwtService.reIssuedRefreshToken(email);
                    String reIssuedAccessToken = jwtService.createAccessToken(email,member.getRole());
                    jwtService.sendAccessTokenAndRefreshToken(response, reIssuedAccessToken, reIssuedRefreshToken);
                });
    }

    /**
     * 현재 SecurityContextHolder를 비운다.
     */
    public void deleteAuthentication() {
        SecurityContextHolder.clearContext();
    }
}
