package study.securityjwt;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;
import study.securityjwt.model.Member;
import study.securityjwt.model.Role;
import study.securityjwt.repository.MemberRepository;

import javax.annotation.PostConstruct;

@Component
@RequiredArgsConstructor
public class InitDB {

    private final MemberRepository memberRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @PostConstruct
    public void init() {
        Member member = Member.builder()
                .username("dhpark")
                .password(bCryptPasswordEncoder.encode("1234"))
                .role(Role.ROLE_USER)
                .build();
        memberRepository.save(member);

        Member admin = Member.builder()
                .username("admin")
                .password(bCryptPasswordEncoder.encode("1234"))
                .role(Role.ROLE_ADMIN)
                .build();
        memberRepository.save(admin);



    }

}
