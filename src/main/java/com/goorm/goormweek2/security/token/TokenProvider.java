package com.goorm.goormweek2.security.token;

import static java.lang.System.getenv;

import com.goorm.goormweek2.member.MemberRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Slf4j
@Component
@RequiredArgsConstructor
public class TokenProvider {

//    Map<String, String> env = getenv();
//    private String secretKey = Base64.getEncoder().encodeToString(
//        Objects.requireNonNull(env.get("JWT_SECRET")).getBytes());

    @Value("${jwt.secret}")
    private String secretKey;

    private final MemberRepository memberRepository;
    private static final String AUTHORITIES_KEY = "ROLE_USER";
    private final TokenBlacklistService tokenBlacklistService;

    public TokenDTO generateToken(Authentication authentication) {

        //구현
        String accessToken = "accessToken";
        String refreshToken = "refreshToken";

        tokenBlacklistService.saveToken(refreshToken);

        return TokenDTO.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    public Authentication getAuthentication(String accessToken) {
        Claims claims = Jwts.parserBuilder()
            .setSigningKey(secretKey)
            .build()
            .parseClaimsJws(accessToken)
            .getBody();

        Collection<? extends GrantedAuthority> authorities =
            Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        User principal = new User(claims.getSubject(), "", authorities);

        return new UsernamePasswordAuthenticationToken(principal, accessToken, authorities);
    }

    //액세스 토큰과 리프레시 토큰 함께 재발행
    public TokenDTO reissueToken(String refreshToken) {

        //구현
        //Redis에서 리프레시 토큰이 유효한지 확인
        if (!tokenBlacklistService.isBlacklisted(refreshToken)) {
            //리프레시 토큰이 유효하다면 새 토큰 발급
            Authentication authentication = getAuthentication(refreshToken); //기존 리프레시 토큰에서 인증 정보 가져오기
            String newAccessToken = "newAccessToken"; //새로 발행된 액세스 토큰
            String newRefreshToken = "newRefreshToken"; //새로 발행된 리프레시 토큰

            //새 리프레시 토큰을 Redis에 저장 (기존 리프레시 토큰 삭제)
            tokenBlacklistService.saveToken(newRefreshToken); //Redis에 새 리프레시 토큰 저장
            tokenBlacklistService.removeToken(refreshToken); //기존 리프레시 토큰 삭제

            return TokenDTO.builder()
                    .accessToken(newAccessToken)
                    .refreshToken(newRefreshToken)
                    .build();
        } else {
            throw new IllegalStateException("유효하지 않은 리프레시 토큰입니다.");
        }
    }

    public TokenDTO resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            // 구현
            //실제 토큰 값만 추출
            String token = bearerToken.substring(7);

            //accessToken과 refreshToken을 TokenDTO에 담아서 반환
            TokenDTO tokenDTO = TokenDTO.builder()
                    .accessToken(token)
                    .build();

            return tokenDTO;
        }
        return null;
    }

    public boolean validateToken(String token) {
        try {
            if(tokenBlacklistService.isBlacklisted(token)){
                log.info("블랙리스트에 등록된 토큰입니다.");

                return false;
            }

            Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {

            log.info("잘못된 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {

            log.info("만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e) {

            log.info("지원되지 않는 JWT 토큰입니다.");
        } catch (IllegalArgumentException e) {

            log.info("JWT 토큰이 잘못되었습니다.");
        }
        return false;
    }

    public Claims getClaims(String token) {
        return Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token).getBody();
    }

    public long getExpiration(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();

        long expirationTimeInMillis = claims.getExpiration().getTime();
        long currentTimeInMillis = System.currentTimeMillis();

        return expirationTimeInMillis - currentTimeInMillis;
    }
}
