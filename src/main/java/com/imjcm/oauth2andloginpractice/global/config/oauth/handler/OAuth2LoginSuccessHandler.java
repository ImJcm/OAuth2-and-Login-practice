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
     *
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
            super.clearAuthenticationAttributes(request);

            DefaultRedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

            redirectStrategy.sendRedirect(request, response, getTargetUrl(accessToken));
        } catch (Exception e) {
            throw e;
        }
    }

    private String getTargetUrl(String token) {
        return UriComponentsBuilder.fromUriString(REDIRECT_URL)
                .queryParam("token", token)
                .build()
                .toUriString();
    }
}
