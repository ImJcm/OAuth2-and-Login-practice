package com.imjcm.oauth2andloginpractice.global.common;

import java.util.Random;

public class PasswordUtil {
    private static final int leftLimit = 48;     // numeral '0'
    private static final int rightLimit = 122;   // letter 'z'
    private static final int targetStringLength = 10;

    public static String generateRandomPassword() {
        Random random = new Random();

        return random.ints(leftLimit, rightLimit + 1)
                .filter(i -> (i <= 57 || (65 <= i && i <= 90) || i >= 97))
                .limit(targetStringLength)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();
    }

}
