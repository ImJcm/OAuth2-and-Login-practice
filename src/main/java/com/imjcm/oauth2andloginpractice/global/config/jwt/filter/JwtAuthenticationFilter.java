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
import java.util.Optional;

/**
 *  JWT Authorization(인가) 필터
 *  JWT 토큰을 검증하여
 */
@Slf4j(topic = "JWT 검증 및 인가")
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private static final String[] NO_CHECK_URL = {"/login", "/api/jwt/reissue-token"};

    private final JwtService jwtService;
    private final LoginService loginService;
    private final MemberRepository memberRepository;

    /**
     * "/login","/api/jwt/reissue-token"에 해당하는 요청인 경우, 해당 필터를 거치지 않고 다음 필터로 이동
     * (예외 API가 많아질 경우, 클라이언트 API 호출에서 Authorization Header를 제거하거나, 정규식으로 필터처리 과정이 필요해보임)
     *
     * - checkAccessTokenAndAuthentication()
     * 그외 요청인 경우, request의 header로부터 AccessToken을 추출한다.
     *
     * AccessToken이 존재하면, Cookie에서 RefreshToken을 추출하고 RefreshToken이 존재하면
     * Redis에서 RefreshToken이 존재하는지 확인한다.
     *
     * 추출한 AccessToken에서 validateToken을 거쳐 토큰 유효성 검사를 수행한다.
     * AccessToken이 없거나, 유효성 검사에 실패한 경우, 해당 필터를 종료한다.
     *
     * 토큰이 null이 아닌 경우, token으로부터 Claim을 추출하고, claims에서 email을 추출하고 이메일이 존재할 경우,
     * saveAuthentication(email)을 수행한다.
     *
     * 토큰이 null인 경우, 다음 필터로 넘어가더라도, Authentication을 요구하는 API인 경우, AuthenticaitonEntryPoint에서
     * 핸들링되어 401 response를 전달한다.
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
        for(String url : NO_CHECK_URL) {
            if(request.getRequestURI().equals(url)) {
                filterChain.doFilter(request,response);
                return;
            }
        }

        checkAccessTokenRefreshTokenAndAuthentication(request,response,filterChain);
    }

    /**
     * Filter에서 RefreshToken이 null인 경우, AccessToken으로 인증을 수행하는 것으로 AccessToken의 유효성 검사 후,
     * AccessToken에서 email을 추출하고 해당 이메일이 존재하는 이메일인지 검사하고 이메일에 해당하는 RefreshToken이 존재하는지 여부를 확인 후,
     * 이메일을 사용하는 사용자의 이메일을 SecurityContextHolder에 Authentication을 등록하여 인증을 수행한다.
     *
     * email에 해당하는 RefreshToken이 존재하지 않거나, email에 해당하는 사용자가 없거나, AccessToken에서 email을 추출했을 때 없거나,
     * AccessToken이 유효하지 않은 경우, Authentication을 등록하지 않는다.
     *
     * JWT AccessToken의 유효성 검사하여 유효하지 않은 경우, 401 에러를 클라이언트에게 반환하여 refreshToken과 함께 /api/jwt/reissue-token을 요청하여
     * RefreshToken이 유효하면 새로운 AccessToken과 RefreshToken을 클라이언트에게 전달하는 로직이다.
     *
     * 이때, 유효하지 않은 JWT AccessToken이거나 refreshToken이 없는 경우, AuthenticationEntryPoint에서 인증되지 않은 사용자로 판단하여 401 에러 반환
     *
     * AuthenticationEntryPoint에 진입 조건
     * -> 인증이 필요한 API 요청에 미인증 사용자가 요청하는 경우 = Spring ContextHolder의 Authentication == null
     *
     * 만약, AccessToken이 유효하지 않아서 클라이언트 측에서 API호출로 JWT를 갱신하는 방법이 아닌 백엔드 서버에서 AccessToken의 유효성을 검사하고 유효하지 않다면
     * cookie값을 직접 가져와 유효성 및 DB에 존재하는 RefreshToken인지 확인 후, AccessToken과 RefreshToken을 Header, Cookie에 각각 response로 전달하고,
     * request에서 요청으로 들어온 uri를 redirect시키는 방법도 존재한다.
     *
     * 하지만, 새로 발급한 AccessToken의 경우 header로 보낸 후, 클라이언트 측에서 localStorage에 저장하고 추가 API 요청마다 Header에 담아서 보내야 하는데
     * redirect를 수행하게 되면 새로 발급한 AccessToken을 저장할 방법이 없다.
     *
     * 따라서, 아래 방법은 잘못된 방법이라고 생각한다.
     * (이러한 방식으로 백엔드에서 처리하는 방법이 있지만 아직 내가 모르는 것일 수 있다.)
     *
     * Optional<String> optionalRefreshToken = jwtService.getRefreshTokenFromCookie(request);
     *
     * if(optionalRefreshToken.isPresent()) {
     *     String refreshToken = optionalRefreshToken.get();
     *
     *     if(!jwtService.validateToken(refreshToken)) {
     *         jwtService.extractEmailFromToken(refreshToken)
     *                 .ifPresent(email -> {
     *                     jwtService.sendAccessTokenByHeader(response, jwtService.createAccessToken(email));
     *                     jwtService.sendRefreshTokenByCookie(request, response, jwtService.createRefreshToken(email));
     *                 });
     *         response.sendRedirect(request.getRequestUri()); // AccessToken Header를 받을 수 없기 때문에
     *     }
     * }
     *
     * 결론
     * 1. response의 status Code를 401로 설정하고 클라이언트 응답 수행
     * 2. AuthenticationEntryPoint를 이용하여 예외를 발생시켜 토큰 재발급을 수행
     * 3. JwtAuthenticationFilter 이전에 JwtExceptionFiller를 추가하여 예외처리를 수행하고 예외를 발생시켜 토큰 재발급 API를 호출하도록 요청
     * 4. 백엔드 서버에서 accessToken의 유효하지 않음을 검사하고 refreshToken을 쿠키에서 추출하여 유효성에 따라 재발급을 수행해서 재발급한 refreshToken은
     *     Cookie에 저장하고, accessToken은 Header로 넘기는 것이 아닌 redirect uri의 param으로 api-uri?token="accessToken-value"로 보내고
     *     각 페이지마다 uri에 token param 존재 여부에 따라 localStorage에 저장하는 token.js를 추가하는 방법
     *     token.js
     *     const token = searchParam('token');
     *
     *     if(token) {
     *         localStorage.setItem("Authorization", token);
     *     }
     *
     *     function searchParam(key) {
     *         return new URLSearchParams(location.search).get(key);
     *     }
     *
     * 백엔드 서버에서 JWT 인증 예외가 발생한 API인 경우,JWT 재발급 과정만 수행하고 이전에 요청한 API는 클라이언트에서
     * 재요청하는 형식으로 로직을 구성하는 것이 좋다고 생각하기 때문에 3번 과정으로 구현하였다.
     * @param request
     * @param response
     * @param filterChain
     * @throws ServletException
     * @throws IOException
     */
    public void checkAccessTokenRefreshTokenAndAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        Optional<String> optionalAccessToken = jwtService.getAccessTokenFromHeader(request);

        if(optionalAccessToken.isPresent()) {
            String accessToken = optionalAccessToken.get();
            String refreshToken = jwtService.getRefreshTokenFromCookie(request).orElse(null);

            if(refreshToken != null) {
                if(!jwtService.isEqualsRefreshToken(refreshToken)) {
                    /*
                        AccessToken은 유효하지만, RefreshToken이 Redis Value와 다르거나 null
                        즉, 이전에 사용된 refreshToken을 사용
                     */
                    jwtService.extractEmailFromToken(refreshToken)
                            .ifPresent(jwtService::deleteRefreshTokenByEmail);

                    return;
                }

                if(!jwtService.validateToken(accessToken)) {
                    log.error("유효한 JWT 토큰이 아닙니다.");
                    return;
                }

                jwtService.extractEmailFromToken(accessToken)
                        .flatMap(memberRepository::findByEmail)
                        .ifPresent(member -> saveAuthentication(member.getEmail()));
            }
        }
        filterChain.doFilter(request, response);
    }

    /**
     * email로부터 실제 DB에서 사용자를 조회한 후, UsernamePasswordAuthneitcationToken로 인증 객체인 Authentication 객체 생성
     * UsernamePasswordAuthenticationToken의 인자
     * 1. UserDetails : email로부터 실제 DB에 저장된 유저 객체 - UserDetailsService를 상속한 loginService의 loadUserByUsername() 이용
     * 2. credential(보통 비밀번호를 의미, 인증 시에는 null로 제거)
     * 3. Authorities로 Collection < ? extends GrantedAuthority>의 타입으로 유저의 권한을 저장하고 있다.
     *
     * 현재 SecurityContextHolder를 비우고 만들어진 Authentication = UsernamePasswordAuthenticationToken을 저장한다.
     * 이후, Controller에서 @AuthneitcationPrincipal을 통해 전역적으로 인증된 Authentication 객체로서 사용된다.
     * @param email
     */
    public void saveAuthentication(String email) {
        Member userDetails = loginService.loadUserByUsername(email);

        Authentication authentication = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities()
        );

        jwtService.clearAuthentication();

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
