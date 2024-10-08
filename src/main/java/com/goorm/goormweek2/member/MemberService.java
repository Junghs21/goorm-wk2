package com.goorm.goormweek2.member;

import com.goorm.goormweek2.security.token.TokenBlacklistService;
import com.goorm.goormweek2.security.token.TokenDTO;
import com.goorm.goormweek2.security.token.TokenProvider;
import jakarta.transaction.Transactional;
import java.util.NoSuchElementException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
@Transactional
public class MemberService {
    private final BCryptPasswordEncoder encoder;
    private final MemberRepository memberRepository;
    private final AuthenticationManager authenticationManager;
    private final TokenProvider tokenProvider;
    private final TokenBlacklistService tokenBlacklistService;

    //회원가입
    public void register(String email, String password) {
        String encryptedPassword = encoder.encode(password);
        Member member = Member.builder()
            .email(email)
            .password(encryptedPassword)
            .build();
        memberRepository.save(member);
    }

    //로그인
    @Transactional
    public TokenDTO login(String email, String password) {
        Member member = memberRepository.findByEmail(email)
                .orElseThrow(() -> new NoSuchElementException("Member with email " + email + " not found"));

        if (!encoder.matches(password, member.getPassword())) {
            throw new IllegalArgumentException("Invalid password");
        } else {
            //UsernamePasswordAuthenticationToken 변수를 authToken으로 변경
            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(email, password);
            Authentication authentication = authenticationManager.authenticate(authToken);

            //TokenDTO는 여전히 token으로 유지
            TokenDTO token = tokenProvider.generateToken(authentication);

            return token;
        }
    }

    //로그아웃
    public void logout(String token) {
//        로그아웃 구현
        long expiration = tokenProvider.getExpiration(token);
        tokenBlacklistService.addToBlacklist(token, expiration);
    }
}
