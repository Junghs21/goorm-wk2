package com.goorm.goormweek2.security.token;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class TokenBlacklistService {

    private final RedisTemplate<String, String> redisTemplate;
    private final String TOKEN_PREFIX = "token:";

    //블랙리스트에 토큰 추가
    public void addToBlacklist(String token, long expirationInMillis) {
        redisTemplate.opsForValue().set(token, "blacklisted", expirationInMillis, TimeUnit.MILLISECONDS);
    }

    public boolean isBlacklisted(String token) {
        return redisTemplate.hasKey(token);
    }

    public void saveToken(String token) {
        redisTemplate.opsForValue().set(TOKEN_PREFIX + token, token, 14, TimeUnit.DAYS); //14일 동안 저장
    }

    public void removeToken(String token) {
        redisTemplate.delete(TOKEN_PREFIX + token);
    }
}
