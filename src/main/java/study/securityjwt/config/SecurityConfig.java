package study.securityjwt.config;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.session.ForceEagerSessionCreationFilter;
import org.springframework.web.filter.DelegatingFilterProxy;
import study.securityjwt.filter.JwtAuthenticationFilter;
import study.securityjwt.filter.JwtAuthorizationFilter;
import study.securityjwt.repository.MemberRepository;

@Configuration
@EnableWebSecurity  // 스프링 시큐리티 필터 체인으로 등록해줍니다.
@RequiredArgsConstructor
public class SecurityConfig {

    @Value("${jwt.secret}")
    private String SECRET_KEY;

    private final CorsConfig corsConfig;
    private final MemberRepository memberRepository;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(authorize -> authorize
                        .mvcMatchers("/user/**").hasAnyAuthority("ROLE_USER", "ROLE_ADMIN")
                        .mvcMatchers("/admin/**").hasRole("ADMIN")
                        .anyRequest().permitAll()
                )
                .httpBasic(basic -> basic.disable())
                .formLogin(form -> form.disable())
                .sessionManagement(sessionManagement -> sessionManagement
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login")
                        .invalidateHttpSession(true)
                        .deleteCookies("accessToken"))
                .apply(new MyCustomDsl())
        ;
        return http.build();
    }

    public class MyCustomDsl extends AbstractHttpConfigurer<MyCustomDsl, HttpSecurity> {
        @Override
        public void configure(HttpSecurity http) throws Exception {
            AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
            http
                    .addFilter(corsConfig.corsFilter())
                    .addFilter(new JwtAuthenticationFilter(authenticationManager, SECRET_KEY))
                    .addFilterBefore(new JwtAuthorizationFilter(authenticationManager, memberRepository, SECRET_KEY), JwtAuthenticationFilter.class)
            ;
        }
    }

}
