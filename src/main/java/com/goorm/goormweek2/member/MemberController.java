package com.goorm.goormweek2.member;

import com.goorm.goormweek2.member.MemberDTO.GeneralDto;
import com.goorm.goormweek2.security.token.TokenDTO;
import com.goorm.goormweek2.security.token.TokenProvider;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;

@RequiredArgsConstructor
@RestController
public class MemberController {

    private final MemberService memberService;
    private final TokenProvider tokenProvider;

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody GeneralDto memberDto) {
        memberService.register(memberDto.getEmail(), memberDto.getPassword());
        return ResponseEntity.ok("회원가입 성공");
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody GeneralDto generalDto) {
        TokenDTO token = memberService.login(generalDto.getEmail(), generalDto.getPassword());
        //쿠키로 변환해서 응답

        //액세스 토큰 쿠키 생성
        Cookie accessTokenCookie = new Cookie("accessToken", token.getAccessToken());
        accessTokenCookie.setHttpOnly(true);  //자바스크립트에서 접근 불가 - 보안 강화
        accessTokenCookie.setPath("/");       //애플리케이션 전체에 적용
        accessTokenCookie.setMaxAge(7 * 24 * 60 * 60); //쿠키의 만료 시간 설정 - 7일

        //리프레시 토큰 쿠키 생성
        Cookie refreshTokenCookie = new Cookie("refreshToken", token.getRefreshToken());
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge(14 * 24 * 60 * 60); //리프레시 토큰 만료 시간 설정 - 14일

        //쿠키를 응답 헤더에 추가
        return ResponseEntity.ok()
                .header("Set-Cookie", accessTokenCookie.toString())
                .header("Set-Cookie", refreshTokenCookie.toString())
                .body("로그인 성공");
    }

    @DeleteMapping("/logout")
    public ResponseEntity<String> logout(HttpServletRequest request) {
        //구현
        //기존 쿠키 삭제 (0으로 만료 시간 설정)
        Cookie accessTokenCookie = new Cookie("accessToken", null);
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setPath("/");
        accessTokenCookie.setMaxAge(0);  //쿠키 만료

        Cookie refreshTokenCookie = new Cookie("refreshToken", null);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge(0);  //쿠키 만료

        return ResponseEntity.ok()
                .header("Set-Cookie", accessTokenCookie.toString())
                .header("Set-Cookie", refreshTokenCookie.toString())
                .body("로그아웃 성공");
    }

    @GetMapping("/reissue")
    public ResponseEntity<String> reissue(HttpServletRequest request) {
        //구현
        Cookie[] cookies = request.getCookies();
        String refreshToken = Arrays.stream(cookies)
                .filter(cookie -> "refreshToken".equals(cookie.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("리프레시 토큰이 존재하지 않습니다."));

        //리프레시 토큰을 사용하여 새로운 토큰 발급
        TokenDTO newToken = tokenProvider.reissueToken(refreshToken);

        //액세스 토큰 쿠키 생성
        Cookie newAccessTokenCookie = new Cookie("accessToken", newToken.getAccessToken());
        newAccessTokenCookie.setHttpOnly(true);
        newAccessTokenCookie.setPath("/");
        newAccessTokenCookie.setMaxAge(7 * 24 * 60 * 60);

        //리프레시 토큰 쿠키 생성
        Cookie newRefreshTokenCookie = new Cookie("refreshToken", newToken.getRefreshToken());
        newRefreshTokenCookie.setHttpOnly(true);
        newRefreshTokenCookie.setPath("/");
        newRefreshTokenCookie.setMaxAge(14 * 24 * 60 * 60);

        //쿠키와 함께 응답
        return ResponseEntity.ok()
                .header("Set-Cookie", newAccessTokenCookie.toString())
                .header("Set-Cookie", newRefreshTokenCookie.toString())
                .body("토큰 재발급 성공");
    }

}