package com.imjcm.oauth2andloginpractice.global.common;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.util.SerializationUtils;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;

public class CookieUtil {
    /**
     * 쿠키를 저장하는 메서드
     * 공백문자를 %20으로 변경한 후, maxAge를 적용하여 현재 브라우저에 쿠키를 저장한다.
     * @param response
     * @param name
     * @param value
     * @param maxAge
     */
    public static void addCookie(HttpServletResponse response, String name, String value, int maxAge) {
        value = URLEncoder.encode(value, StandardCharsets.UTF_8).replaceAll("\\+", "%20");
        Cookie cookie = new Cookie(name, value);
        cookie.setPath("/");
        cookie.setMaxAge(maxAge);

        response.addCookie(cookie);
    }

    /**
     * name에 해당하는 Cookie를 제거하는 메서드
     * @param request
     * @param response
     * @param name
     */
    public static void deleteCookie(HttpServletRequest request, HttpServletResponse response, String name) {
        Cookie[] cookies = request.getCookies();

        if(cookies != null) {
            Arrays.stream(cookies)
                .filter(cookie -> cookie.getName().equals(name))
                .forEach(c -> {
                    c.setValue("");
                    c.setPath("/");
                    c.setMaxAge(0);
                    response.addCookie(c);
                });
        }
    }

    /**
     * name에 해당하는 Cookie 값을 가져오는 메서드
     * @param request
     * @param name
     * @return
     */
    public static Optional<Cookie> getCookie(HttpServletRequest request, String name) {
        return Arrays.stream(request.getCookies())
                .filter(cookie -> cookie.getName().equals(name))
                .findFirst();
    }

    /**
     * URLEncode를 통해 Searialize를 적용한 값 반환하는 메서드
     * @param obj
     * @return
     */
    public static String serialize(Object obj) {
        return Base64.getUrlEncoder()
                .encodeToString(SerializationUtils.serialize(obj));
    }

    /**
     * Cookie 값을 T URLDecode를 이용하여 T타입으로 deserialize를 적용한 값 반환하는 메서드
     * @param cookie
     * @param cls
     * @return
     * @param <T>
     */
    public static <T> T deserialize(Cookie cookie, Class<T> cls) {
        return cls.cast(
                SerializationUtils.deserialize(
                        Base64.getUrlDecoder().decode(cookie.getValue())
                )
        );
    }
}
