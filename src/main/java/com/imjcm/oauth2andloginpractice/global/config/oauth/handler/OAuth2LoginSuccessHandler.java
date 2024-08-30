package com.imjcm.oauth2andloginpractice.global.config.oauth.handler;

import com.imjcm.oauth2andloginpractice.global.config.jwt.service.JwtService;
import com.imjcm.oauth2andloginpractice.global.config.oauth.CustomOAuth2Member;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.Iterator;

@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final JwtService jwtService;
    private static final String REDIRECT_URL = "/home";

    /**
     * oAuth2 로그인 성공 시, 수행하는 메서드
     * DefaultOAuth2User를 상속한 CustomOAuth2Member를 authentication.getPrincipal()을 통해 받는다.
     * email을 추출하고, AccessToken, RefreshToken을 생성한다.
     *
     * redirect 시, header를 통해 전달은 불가능하므로 parameter를 통해 accessToken을 전달하고, Cookie를 통해 RefreshToken을 저장한다.
     *
     * 클라이언트에서 param으로 전달된 AccessToken을 저장한다.
     * @param request
     * @param response
     * @param authentication
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        try {
            CustomOAuth2Member oAuth2Member = (CustomOAuth2Member) authentication.getPrincipal();

            Iterator<? extends GrantedAuthority> it = oAuth2Member.getAuthorities().iterator();

            String email = oAuth2Member.getAttribute("email");

            String accessToken = jwtService.createAccessToken(email);
            String refreshToken = jwtService.createRefreshToken(email);

            //jwtService.sendAccessTokenAndRefreshToken(request, response, accessToken, refreshToken);
            jwtService.sendRefreshTokenByCookie(request, response, refreshToken);
            jwtService.updateRefreshToken(email, refreshToken);

            jwtService.clearAuthentication();
            //super.clearAuthenticationAttributes(request);

            DefaultRedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

            redirectStrategy.sendRedirect(request, response, getTargetUrl(accessToken));
        } catch (Exception e) {
            throw e;
        }
    }

    /**
     * redirect_uri + token Parameter uri를 생성하는 메서드
     * @param token
     * @return
     */

    private String getTargetUrl(String token) {
        return UriComponentsBuilder.fromUriString(REDIRECT_URL)
                .queryParam("token", token)
                .build()
                .toUriString();
    }
}
