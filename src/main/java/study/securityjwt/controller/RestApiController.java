package study.securityjwt.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.thymeleaf.util.StringUtils;
import study.securityjwt.config.auth.MemberDetails;
import study.securityjwt.model.Member;
import study.securityjwt.model.Role;
import study.securityjwt.model.dto.MemberDto;
import study.securityjwt.repository.MemberRepository;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.util.Optional;

@RestController
@RequiredArgsConstructor
public class RestApiController {

    private final MemberRepository memberRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("/")
    public String home(@CookieValue(value = "accessToken", required = false) String accessToken) {
        if (!StringUtils.isEmpty(accessToken)) {
            String username = JWT.require(Algorithm.HMAC512("secretKey"))
                    .build()
                    .verify(accessToken)
                    .getClaim("username")
                    .asString();
            return "<h1>" + username + "</h1>" +
                    "<a href=\"/logout\">로그아웃</a> <hr>" +
                    "<a href=\"/user\">/user</a> <br>" +
                    "<a href=\"/admin\">/admin</a> <br>";
        }
        return "<h1>HOME</h1>";
    }

    @PostMapping("/join")
    public String join(@RequestBody MemberDto dto) {
        Member member = Member.builder()
                .username(dto.getUsername())
                .password(bCryptPasswordEncoder.encode(dto.getPassword()))
                .role(Role.ROLE_USER)
                .build();
        memberRepository.save(member);
        return "회원가입완료";
    }

    @GetMapping("/user")
    public String user() {
        return "user";
    }

    @GetMapping("/admin")
    public String admin() {
        return "admin";
    }

}
