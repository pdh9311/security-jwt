package study.securityjwt.config.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import study.securityjwt.repository.MemberRepository;

@Service
@RequiredArgsConstructor
public class MemberDetailsService implements UserDetailsService {

    private final MemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("loadUserByUsername => " + username);
        return memberRepository.findByUsername(username)
                .map(MemberDetails::new)
                .orElseThrow(() -> new UsernameNotFoundException("회원가입되지 않은 사용자입니다."));
    }
}
