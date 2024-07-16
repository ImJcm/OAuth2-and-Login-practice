package com.imjcm.oauth2andloginpractice.jwt.UnitTest;

import com.imjcm.oauth2andloginpractice.global.common.Role;
import com.imjcm.oauth2andloginpractice.global.config.jwt.service.JwtService;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

@ExtendWith(MockitoExtension.class)
public class JwtServiceTest {
    @Mock
    private JwtService jwtService;

    @BeforeEach
    void init() {
        ReflectionTestUtils.setField(jwtService, "secretKey","amNtLW9hdXRoMi9jdXN0b21Mb2dpbkZpbHRlciBQcm9qZWN0");
        ReflectionTestUtils.setField(jwtService, "accessTokenHeader","Authorization");
        ReflectionTestUtils.setField(jwtService, "accessTokenExpirationsPeriod",1800000L);
        ReflectionTestUtils.setField(jwtService, "key",Keys.hmacShaKeyFor(Decoders.BASE64.decode("amNtLW9hdXRoMi9jdXN0b21Mb2dpbkZpbHRlciBQcm9qZWN0")));
    }

    @DisplayName("createAccessToken : accessToken 생성 성공")
    @Test
    public void createAccessTokenSuccess() throws Exception {
        // given
        String email = "testEmail";
        Role role = Role.USER;

        /*
            createAccessToken의 반환값은 Bearer + Jwt 값이지만, 예상 반환 값으로 email을 반환하도록 설정한다.
         */
        given(jwtService.createAccessToken(any(String.class),any(Role.class)))
                .willReturn(email);

        // when
        String token = jwtService.createAccessToken(email, role);

        // then
        Assertions.assertThat(email).isEqualTo(token);
    }

}
