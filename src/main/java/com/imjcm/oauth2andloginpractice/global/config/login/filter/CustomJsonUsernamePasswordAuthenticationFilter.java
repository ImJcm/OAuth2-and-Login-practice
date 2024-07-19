package com.imjcm.oauth2andloginpractice.global.config.login.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.imjcm.oauth2andloginpractice.domain.member.dto.request.LoginRequestDto;
import com.imjcm.oauth2andloginpractice.global.config.jwt.service.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

@Slf4j(topic = "로그인 및 JWT 생성")
@RequiredArgsConstructor
public class CustomJsonUsernamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final ObjectMapper objectMapper;

    /**
     * 클라이언트로부터 입력으로 넘어오는 JSON 형태의 email(username), password 형태의 데이터를 LoginRequestDto 형태로 받고,
     * UsernamePasswordAuthenticationToken을 만들어 AuthenticationManager를 통해 사용자인지 여부를 검증 및 인증을 수행한다.
     *  - UsernamePasswordAuthenticationToken(Principal, Credential, Authorities) - Principal = email, Credential = password
     *  - getAuthenticationManager().authenticate()를 수행 후, Authentication인 UsernamePasswordAuthenticationToken의 구성이 변경된다.
     *      - Principal = username에 해당하는 UserDetails가 저장, Credential : 인자로 넘어온 Password, Authority : pricipal에 담긴 UserDetails의 getAuthorities가 담긴다.
     *      -> 확인한 부분 : AbstractUserDetailsAuthenticationProvider.class - authenticate()에서 위 과정이 수행됨
     * 인증 성공 시, 실제 DB에 존재하는 회원의 정보가 담긴 UserDetails를 상속한 클래스를 포함하는 Authentication을 반환한다.
     *  - LoginSuccessHandler
     * 인증 실패 시, 인증 실패 핸들러 수행 또는 (파라미터 인자 매핑, etc) 예외 발생
     *  - LoginFailureHandler
     * @param request
     * @param response
     * @return
     * @throws AuthenticationException
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        try {
            LoginRequestDto requestDto = objectMapper.readValue(request.getInputStream(), LoginRequestDto.class);

            return getAuthenticationManager().authenticate(
                    new UsernamePasswordAuthenticationToken(
                            requestDto.getEmail(),
                            requestDto.getPassword(),
                            null
                    )
            );

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
