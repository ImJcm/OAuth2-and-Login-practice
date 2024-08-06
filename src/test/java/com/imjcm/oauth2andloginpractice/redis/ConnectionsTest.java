package com.imjcm.oauth2andloginpractice.redis;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.util.Set;

@SpringBootTest
public class ConnectionsTest {
    @Autowired
    private RedisTemplate<String, String> redisTemplate;

    @AfterEach
    public void clearRedis() {
        Set<String> keys = redisTemplate.keys("*");

        if(keys != null) {
            redisTemplate.delete(keys);
        }

        System.out.println("Redis 모든 Key 삭제");
    }

    @Test
    public void valueStringTest() {
        // given
        ValueOperations<String, String> valueOperations = redisTemplate.opsForValue();
        String key = "testKey";
        String value = "testValue";

        // when
        valueOperations.set(key, value);

        // then
        String output = valueOperations.get(key);
        Assertions.assertThat(output).isEqualTo(value);
    }
}
