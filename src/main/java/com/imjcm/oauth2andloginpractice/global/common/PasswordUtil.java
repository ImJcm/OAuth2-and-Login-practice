package com.imjcm.oauth2andloginpractice.global.common;

import java.util.Random;

public class PasswordUtil {
    private final int leftLimit = 48;     // numeral '0'
    private final int rightLimit = 122;   // letter 'z'
    private final int targetStringLength = 10;

    private final Random random = new Random();

    public String generateRandomPassword() {
        return random.ints(leftLimit, rightLimit + 1)
                .filter(i -> (i <= 57 || (65 <= i && i <= 90) || i >= 97))
                .limit(targetStringLength)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();
    }

}
