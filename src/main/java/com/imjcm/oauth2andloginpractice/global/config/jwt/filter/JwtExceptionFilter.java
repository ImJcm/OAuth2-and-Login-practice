package com.imjcm.oauth2andloginpractice.global.config.jwt.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class JwtExceptionFilter extends OncePerRequestFilter {
    /**
     * JwtAuthenticationFilter에서 발생하는 예외를 try-catch
     * @param request
     * @param response
     * @param filterChain
     * @throws ServletException
     * @throws IOException
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            filterChain.doFilter(request, response);
        } catch (JwtException e) {
            setErrorResponse(request, response, e);
        }
    }

    /**
     * JwtException 핸들링 메서드 - 401 Error Code를 response에 담아 전달하는 메서드
     * @param request
     * @param response
     * @param e
     * @throws IOException
     */
    private void setErrorResponse(HttpServletRequest request, HttpServletResponse response, JwtException e) throws IOException {
        Map<String, Object> body = new HashMap<>();

        body.put("status", HttpServletResponse.SC_UNAUTHORIZED);
        body.put("message", e.getMessage());

        ObjectMapper mapper = new ObjectMapper();
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        mapper.writeValue(response.getOutputStream(), body);
    }
}
