package study.securityjwt.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import study.securityjwt.model.Member;
import study.securityjwt.model.Role;
import study.securityjwt.model.dto.MemberDto;
import study.securityjwt.repository.MemberRepository;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

@RestController
@RequiredArgsConstructor
public class RestApiController {

    private final MemberRepository memberRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("/")
    public String home() {
        return "<h1>HOME</h1>";
    }


    @PostMapping("/join")
    public String join(@RequestBody MemberDto dto) {
        Member user = Member.builder()
                .username(dto.getUsername())
                .password(bCryptPasswordEncoder.encode(dto.getPassword()))
                .role(Role.ROLE_USER)
                .build();
        memberRepository.save(user);
        return "회원가입완료";
    }

    @GetMapping("/logout")
    public String logout(HttpServletResponse res) {
        Cookie cookie = new Cookie("accessToken", "");
        cookie.setMaxAge(0);
        res.addCookie(cookie);
        return "로그아웃 완료됨";
    }

}
