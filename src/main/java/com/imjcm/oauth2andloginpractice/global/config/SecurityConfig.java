package com.imjcm.oauth2andloginpractice.global.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.imjcm.oauth2andloginpractice.domain.member.MemberRepository;
import com.imjcm.oauth2andloginpractice.global.config.jwt.filter.JwtAuthenticationFilter;
import com.imjcm.oauth2andloginpractice.global.config.jwt.service.JwtService;
import com.imjcm.oauth2andloginpractice.global.config.login.filter.CustomJsonUsernamePasswordAuthenticationFilter;
import com.imjcm.oauth2andloginpractice.global.config.login.handler.LoginFailureHandler;
import com.imjcm.oauth2andloginpractice.global.config.login.handler.LoginSuccessHandler;
import com.imjcm.oauth2andloginpractice.global.config.login.service.LoginService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 *  CustomJsonUsernamePasswordAuthenticationFilter : username, password로 UsernamePasswordAuthenticationToken() 생성 후, AuthenticationManager.authentication()으로 인증 수행 - Authentication(인증)
 *  JwtAuthenticationFilter : HttpRequest로 부터 JWT 토큰을 검증하는 필터 - 인가(Authorization)
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {
    private final ObjectMapper objectMapper;
    private final JwtService jwtService;
    private final LoginService loginService;
    private final MemberRepository memberRepository;
    private final AuthenticationConfiguration authenticationConfiguration;

    /**
     *  FormLogin : FormLogin 양식 사용 x
     *  csrf : csrf 보안 사용 x - Cross site Request Forgery가 불가능하도록 설정
     *  sessionManagement : Session 사용하지 않으므로 STATELESS 설정 - Session 방식은 사용하지 않고 JWT 방식을 사용하기 위한 설정
     *  authorizeHttpRequests : 어떠한 API 요청을 인증 과정을 거칠 것인지 설정
     *      - /api/member/signup은 인증 과정 없이 허용
     *      - anyRequest().anthenticated() : 그외 나머지 요청은 인증 과정 적용
     *  addFilterBefore(customJsonUsernamePasswordAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
     *      - UsernamePasswordAuthenticationFilter 전에 customJsonUsernamePasswordAuthenticationFilter를 설정
     *  addFilterBefore(jwtAuthenticationFilter(), CustomJsonUsernamePasswordAuthenticationFilter.class)
     *      - CustomJsonUsernamePasswordAuthenticationFilter전에 jwtAuthenticationFilter를 적용
     *      - jwt 토큰 여부 검사 및 검증 -> jwt 유효 시, Authentication 생성하여 인증 / jwt 미유효 시, 예외 발생 또는 login 유도
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .formLogin((formLogin) ->
                        formLogin.disable())
                .csrf((csrfConfig) ->
                        csrfConfig.disable())
                .sessionManagement((sessionManagement)
                        -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests((authorizeRequests) ->
                        authorizeRequests
                                .requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
                                .requestMatchers("/api/member/signup").permitAll()
                                .anyRequest().authenticated())
                .addFilterBefore(customJsonUsernamePasswordAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtAuthenticationFilter(), CustomJsonUsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    /**
     *   JWT Authorization(인가)를 위한 Filter 지정
     *   jwtService - jwt 토큰을 이용하기 위한 기능을 모아놓은 클래스
     *   loginService - UserDetailsService를 상속받아 UserDetails 객체를 이용하는 클래스
     */
    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter(jwtService, loginService);
    }

    /**
     *   JWT Authentication(인증)을 위한 Filter 설정
     *   로그인 시, 인증을 하기위해서는 AuthenticationManager를 필요로 한다.
     *   spring 6.x 부터 제공되는 AuthenticationConfiguration 사용하여 AuthenticationManager를 받아올 수 있도록 한다.
     *   authenticationConfiguration은 인증을 위한 설정을 담고 있으며 AuthenticationManager로 사용될 수 있다.
     *   jwtService, ObjectMapper를 인자로 받는다
     *      - jwtService : jwt 토큰을 이용하기 위한 Service
     *      - ObjectMapper : username(email), password를 전달하여 JSON 형태로 매핑하기 위함
     *   AuthenticationFilter를 적용할 url을 설정한다. (url = "/api/member/login")
     *      - UsernamePasswordAuthenticationFilter의 default Url = (/login, POST)
     *      - setFilterProcessesUrl()로 지정할 경우, url만 지정, Method = null로 설정됨.
     *          - login의 경우, POST만 넘어오는 경우가 암묵적으로 정해진 룰이라고 생각한다.
     *   로그인 성공 시, Bean으로 등록한 LoginSuccessHandler를 지정
     *   로그인 실패 시, Bean으로 등록한 LoginFailureHandler를 지정
     */
    @Bean
    public CustomJsonUsernamePasswordAuthenticationFilter customJsonUsernamePasswordAuthenticationFilter() throws Exception {
        CustomJsonUsernamePasswordAuthenticationFilter customJsonUsernamePasswordAuthenticationFilter
                = new CustomJsonUsernamePasswordAuthenticationFilter(jwtService, objectMapper);
        customJsonUsernamePasswordAuthenticationFilter.setFilterProcessesUrl("/api/member/login");
        customJsonUsernamePasswordAuthenticationFilter.setAuthenticationManager(authenticationManager(authenticationConfiguration));
        customJsonUsernamePasswordAuthenticationFilter.setAuthenticationSuccessHandler(loginSuccessHandler());
        customJsonUsernamePasswordAuthenticationFilter.setAuthenticationFailureHandler(loginFailureHandler());
        return customJsonUsernamePasswordAuthenticationFilter;
    }

    /**
     *  AuthenticationManager Bean 등록
     *  AuthenticationManager로 사용할 Manager를 AuthenticationConfiguration에서 AuthenticationManager를 반환하여 사용
     *  AuthenticationConfiguration 내부에서 PasswordEncoder Bean이 존재하는지 확인 후, PasswordEncoder로 설정
     *  AuthenticationManagerBuilder를 생성한 후, publisher + config를 통해 AuthenticationProvider의 역할을 설정한다고 생각한다. <- 정확하지 않음
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    /**
     *  로그인 성공 시, 호출되는 LoginSuccessHandler Bean 등록
     */
    @Bean
    public LoginSuccessHandler loginSuccessHandler() {
        return new LoginSuccessHandler(jwtService, memberRepository);
    }

    /**
     *  로그인 실패 시, 호출되는 LoginFailureHandler Bean 등록
     */
    @Bean
    public LoginFailureHandler loginFailureHandler() {
        return new LoginFailureHandler();
    }
}
