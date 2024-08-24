package com.imjcm.oauth2andloginpractice.global.config.jwt.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Slf4j(topic = "Spring Security Filter Authentication Exception Handler")
@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    /**
     * Spring Security의 authorizeRequest에 적용한 API에서 인증이 필요한 경우, Authentication 객체 여부에 따라 예외 핸들링 메서드'
     * Authentication 객체가 null + API authenticated인 경우 실행
     * @param request
     * @param response
     * @param authException
     * @throws IOException
     */
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
        if(request.getRequestURI().startsWith("/api/")) {
            log.info(authException.getMessage());
            //response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "인증되지 않은 사용자입니다.");
            Map<String, Object> body = new HashMap<>();

            body.put("status", HttpServletResponse.SC_UNAUTHORIZED);
            body.put("message", authException.getMessage());

            ObjectMapper objectMapper = new ObjectMapper();

            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            objectMapper.writeValue(response.getOutputStream(), body);
        }
    }
}