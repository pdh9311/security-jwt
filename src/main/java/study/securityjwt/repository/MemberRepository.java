package study.securityjwt.repository;


import org.springframework.data.jpa.repository.JpaRepository;
import study.securityjwt.model.Member;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Long> {
    Optional<Member> findByUsername(String username);
}
