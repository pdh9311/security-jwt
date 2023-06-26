package study.securityjwt.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import study.securityjwt.config.auth.MemberDetails;
import study.securityjwt.model.dto.MemberDto;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

/**
 * 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 있는데,
 * 이 필터는 POST /login 요청으로 username과 password를 전송하면 동작합니다
 */
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private static final ObjectMapper objectMapper = new ObjectMapper();

    private final AuthenticationManager authenticationManager;
    private final String SECRET_KEY;

    /**
     * POST /login 요청하면 로그인 시도를 위해서 실행되는 함수
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthentication");
        try {
            // 1. username. password 받아서  Token 생성
            MemberDto Member = objectMapper.readValue(request.getReader(), MemberDto.class);
            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(Member.getUsername(), Member.getPassword());

            // 2. 정상인지  authenticationManager로 로그인 시도를 해본다. 이때 MemberDetailsService의 loadUserByUsername()이 실행된다.
            Authentication authentication = authenticationManager.authenticate(token);

            // 3. MemberDetails를 SecurityContext에 담고(SecurityContext에 담는 이유는 권한관리를 해주기 위해서 입니다.)
            return authentication;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    // 4. JWT 토큰을 만들어서 응답해주면 됨.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        MemberDetails MemberDetails = (MemberDetails) authResult.getPrincipal();

        /**
         * claim은 JWT를 통해서 전달할 데이터를 담는 곳이라고 생각하면 됩니다.
         */
        String jwtToken = JWT.create()
                .withSubject("Member Token")
                .withExpiresAt(new Date(System.currentTimeMillis() + (1000 * 60 * 10))) // 10분
                .withClaim("id", MemberDetails.getMember().getId())
                .withClaim("username", MemberDetails.getMember().getUsername())
                .sign(Algorithm.HMAC512(SECRET_KEY));

        Cookie cookie = new Cookie("accessToken", jwtToken);
        cookie.setMaxAge(60 * 10);  // 10분
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        response.addCookie(cookie);
    }
}
