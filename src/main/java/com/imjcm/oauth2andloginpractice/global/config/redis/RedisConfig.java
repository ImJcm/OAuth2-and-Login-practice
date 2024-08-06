package com.imjcm.oauth2andloginpractice.global.config.redis;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;

@Configuration
public class RedisConfig {
    // redis DB의 host name
    @Value("${spring.data.redis.host}")
    private String host;

    // redis DB의 port 번호
    @Value("${spring.data.redis.port}")
    private String port;

    // redis DB password
    @Value("${spring.data.redis.password}")
    private String password;

    /**
     *  Redis Client는 "Jedis", "Lettuce"로 두 가지가 있다.
     *  이전에는 Jedis를 많이 사용하였으나 여러 단점(멀티 쓰레드 불안정, Pool 한계 등)과 Lettuce의 장점(Netty 기반이라 비동기 지원 가능)
     *  으로 인해 Lettuce를 많이 쓰는 추세이다.
     *  spring Boot 2.0 부터 Jedis가 기본 클라이언트에서 deprecated 되고 Lettuce가 탑재되었다.
     */
    @Bean
    public RedisConnectionFactory redisConnectionFactory() {
        RedisStandaloneConfiguration redisStandaloneConfiguration = new RedisStandaloneConfiguration();
        redisStandaloneConfiguration.setHostName(host);
        redisStandaloneConfiguration.setPort(Integer.parseInt(port));
        redisStandaloneConfiguration.setPassword(password);
        return new LettuceConnectionFactory(redisStandaloneConfiguration);
    }

    /**
     *  <?,?>으로 지정한 이유는 개발자가 원하는 타입으로 데이터를 저장할 수 있기 때문이다.
     *  Redis는 RedisRepository, RedisTemplate를 통해 엔티티를 저장할 수 있다.
     *
     *  RedisRepository는 트랜잭션을 지원하지 않기 때문에 데이터의 원자성을 보장할 수 없다.
     *
     *  원자성(Atomicity)란? 데이터베이스 시스템에서 ACID 트랜잭션 특성 중 하나로 하나의 원자 트랜잭션은 모두 성공하거나 또는 실패하는
     *  데이터베이스 운용의 집합이다.
     *
     *  따라서, 트랜잭션을 지원하는 RedisTemplate를 사용하여 RefreshToken을 저장하고 수정하려고 한다.
     *
     *  RefreshToken의 저장 형태는 Key:value = email:refreshToken로 정하기로 결정하였다.
     *  (AccessToken의 탈취 문제를 해결하기 위해 RefreshToken을 도입하였지만 RefreshToken도 탈취당하여 발생하는 문제를 방지하기 위해
     *  RefreshToken rotation을 설정을 위해 위의 저장 형태를 고려하였다.
     *
     *  RefreshToken으로 AccessToken의 갱신하는 경우, RefreshToken을 Redis에 저장하는데 이때 갱신한 RefreshToken만 저장하는 경우,
     *  공격자에 의한 RefreshToken으로 갱신되었을 때, 사용자가 보유하는 RefreshToken은 Redis에서 찾아볼 수 없게 되므로 정상적인 사용자가 요청하고 있다고 불 수 없다.
     *  그래서, RefreshToken으로 요청이 들어오는 경우, RefreshToken에서 email을 추출하여 어떤 사용자에 대한 요청인지 식별하기 위해 사용된다.
     *  식별된 email을 통해 RefreshToken을 확인하고 동일하지 않은 RefreshToken으로 요청인 경우는 공격자라고 판단할 수 있기 때문에
     *  Redis에 Key:value의 형태로 email:refreshToken으로 저장하기로 결정하였다.)
     *
     *  RefreshToken rotation 도입 이유
     *  RefreshToken이 탈취당하면 긴 유효기간을 갖는 RefreshToken으로 AccessToken을 요청하여 악의적인 행위를 할 수 있기 때문이다.
     *
     *  RefreshToken 탈취 방지 해결방법
     *  RefreshToken Rotation
     *
     *  RefreshToken Rotation 적용 후, 시나리오
     *  로그인 후, AccessToken, RefreshToken이 클라이언트에게 전달되고, RefreshToken은 Redis에 email:refreshToken으로 저장된다.
     *
     *  이후, 클라이언트가 AccessToken이 만료가 되어 RefreshToken을 보내왔다면, 해당 RefreshToken이 Redis에 있는지 체크해야한다.
     *  이때, RefreshToken에서 Email을 추출하여 Redis에 해당 email이 Key로 존재하고, refreshToken이 동일하면,
     *  AccessToken과 RefreshToken을 새로 갱신하여 전달한다.
     *
     *  이 과정에서 공격자가 RefreshToken을 탈취하여 새로운 AccessToken을 전달받으려고 시도하는 경우,
     *  공격자의 RefreshToken이 redis에 저장된 RefreshToken과 다른 경우, 이전 RefreshToken으로 시도하는 경우는 공격자에 의한 요청으로 판단할 수 있다.
     *
     *  공격자의 RefreshToken이 redis에 저장된 RefreshToken과 같은 경우, 공격자가 사용자보다 AccessToken을 우선적으로 요청한 경우이므로 공격자인지 사용자인지 구별할 수는 없지만,
     *  AccessToken, RefreshToken의 짧은 유효기간 내에서 이루어진 탈취이므로 실제 사용자가 이전 RefreshToken으로 요청을 시도할 경우가 크다.
     *  이때, Redis의 RefreshToken과 비교하여 다르기 때문에 사용자를 공격자로 판단하고, RefreshToken의 email에 해당하는 redis 값을 삭제한다.
     *
     *  이를 통해, 공격자의 접근을 차단할 수 있고, 사용자는 인증을 재요구받고 인증을 수행하여 정상적으로 이용할 수 있다.
     */
    @Bean
    public RedisTemplate<?,?> redisTemplate() {
        RedisTemplate<?,?> redisTemplate = new RedisTemplate<>();
        redisTemplate.setConnectionFactory(redisConnectionFactory());
        return redisTemplate;
    }
}
