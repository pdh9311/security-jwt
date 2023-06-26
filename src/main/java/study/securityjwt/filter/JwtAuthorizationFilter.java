package study.securityjwt.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;
import org.thymeleaf.util.StringUtils;
import study.securityjwt.config.auth.MemberDetails;
import study.securityjwt.model.Member;
import study.securityjwt.repository.MemberRepository;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *  BasicAuthenticationFilter는 권한이나 인증이 필요한 특정 주소를 요청받았을때 동작하는 필터입니다.
 */
//@RequiredArgsConstructor
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private MemberRepository memberRepository;
    private String SECRET_KEY;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, MemberRepository memberRepository, String secretKey) {
        super(authenticationManager);
        this.memberRepository = memberRepository;
        this.SECRET_KEY = secretKey;
    }

    /**
     *  인증이나 권한이 필요한 주소 요청이 있을 때 해당 필터를 타게 됨.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("JwtAuthorization");
        String accessToken = "";

        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("accessToken")) {
                    accessToken = cookie.getValue();
                    break;
                }
            }
        }

        if (StringUtils.isEmpty(accessToken)) {
            chain.doFilter(request, response);
            return;
        }

        String username = JWT.require(Algorithm.HMAC512(SECRET_KEY))
                .build()
                .verify(accessToken)
                .getClaim("username")
                .asString();

        if (username != null) {
            Member member = memberRepository.findByUsername(username)
                    .orElseThrow(() -> new UsernameNotFoundException("회원이 아닙니다."));
            MemberDetails memberDetails = new MemberDetails(member);

            // JWT 토큰 서명을 통해서 서명이 정상이면 Authentication 객체를 만들어준다. (권한을 처리하기 위해서)
            Authentication authentication
                    = new UsernamePasswordAuthenticationToken(memberDetails, null, memberDetails.getAuthorities());
            // 강제로 시큐리티 세션에 접근하여 Authentication 객체를 저장.
            SecurityContextHolder.getContext().setAuthentication(authentication);

            chain.doFilter(request, response);
        }

    }
}
