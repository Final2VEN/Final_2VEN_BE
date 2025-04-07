package com.sysmatic2.finalbe.config;

import com.sysmatic2.finalbe.exception.CustomAccessDeniedHandler;
import com.sysmatic2.finalbe.exception.CustomAuthenticationEntryPoint;
import com.sysmatic2.finalbe.jwt.JWTFilter;
import com.sysmatic2.finalbe.jwt.JWTUtil;
import com.sysmatic2.finalbe.jwt.LoginFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final JWTUtil jwtUtil;
    private final AuthenticationConfiguration authenticationConfiguration;
    private final CustomAuthenticationEntryPoint authenticationEntryPoint;
    private final CustomAccessDeniedHandler accessDeniedHandler;

    /**
     * CORS 설정 공통 메서드
     * @param allowAllOrigins 모든 출처 허용 여부 (로컬 환경에서만 true 가능)
     * @return UrlBasedCorsConfigurationSource 객체
     */
    private UrlBasedCorsConfigurationSource createCorsConfiguration(boolean allowAllOrigins) {
        CorsConfiguration configuration = new CorsConfiguration();

        if (allowAllOrigins) {
            configuration.addAllowedOriginPattern("*"); // 로컬 환경에서만 모든 출처 허용
            configuration.setAllowCredentials(false); // JWT와 같은 인증 정보 포함 허용
        } else {
            configuration.addAllowedOriginPattern("https://*"); // HTTPS 출처만 허용
            configuration.addAllowedOriginPattern("http://*");
            configuration.setAllowCredentials(true); // JWT와 같은 인증 정보 포함 허용
        }

        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        configuration.addAllowedHeader("*");
        configuration.addExposedHeader("Authorization");

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    /**
     * 로컬 환경 (local)에서 HTTPS 강제 설정 없이 동작하는 SecurityFilterChain 설정
     * @param http HttpSecurity 객체
     * @return SecurityFilterChain 객체
     * @throws Exception Spring Security 설정 중 예외 발생 시
     */
    @Bean
    @Profile("local") // 로컬 환경에서 활성화
    public SecurityFilterChain securityFilterChainLocal(HttpSecurity http) throws Exception {
        http
                .cors(cors -> cors.configurationSource(createCorsConfiguration(true))) // 로컬 환경에서 모든 출처 허용
                .csrf(csrf -> csrf.disable()) // CSRF 비활성화
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/members/details", "/api/members/change-password", "/api/members/withdrawal").authenticated()
                        .requestMatchers("/api/auth/admin/**", "/api/admin/**").hasRole("ADMIN") //관리자 관련
                        .requestMatchers("/api/strategies/{id}/update-form","/api/strategies/{id}/approval-request",
                                "/api/strategies/{id}/rejection-info", "/api/strategies/{id}/termination", "/api/strategies/{id}/daily-data",
                                "/api/strategies/{strategyId}/daily-data/{dailyDataId}", "/api/strategies/{strategyId}/daily-analyses/delete"
                                ).hasAnyRole("ADMIN", "TRADER") //전략 관련
                        .requestMatchers(HttpMethod.POST, "/api/strategies").hasAnyRole("ADMIN", "TRADER") //전략 등록
                        .requestMatchers(HttpMethod.DELETE, "/api/strategies").hasAnyRole("ADMIN", "TRADER") //전략 삭제
                        .requestMatchers(HttpMethod.PUT, "/api/strategies/{id}").hasAnyRole("ADMIN", "TRADER") //전략 수정
                        .requestMatchers(HttpMethod.POST, "/api/live-account-data/{strategyId}").hasAnyRole("ADMIN", "TRADER") //실계좌 등록
                        .requestMatchers(HttpMethod.DELETE, "/api/live-account-data/{strategyId}").hasAnyRole("ADMIN", "TRADER") //실계좌 삭제
                        .requestMatchers("/**").permitAll()
                )
                .formLogin(formLogin -> formLogin.disable()) // 폼 로그인 비활성화
                .httpBasic(httpBasic -> httpBasic.disable()) // HTTP Basic 비활성화
                .addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class)
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil), UsernamePasswordAuthenticationFilter.class)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(e -> e
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler)
                );

        return http.build();
    }

    /**
     * 운영 환경 (prod)에서 HTTPS를 강제하는 SecurityFilterChain 설정
     * @param http HttpSecurity 객체
     * @return SecurityFilterChain 객체
     * @throws Exception Spring Security 설정 중 예외 발생 시
     */
    @Bean
    @Profile("prod") // 프로덕션 환경에서 활성화
    public SecurityFilterChain securityFilterChainProd(HttpSecurity http) throws Exception {
        http
                .cors(cors -> cors.configurationSource(createCorsConfiguration(false))) // HTTPS 출처만 허용
                .csrf(csrf -> csrf.disable()) // CSRF 비활성화
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/members/details", "/api/members/change-password", "/api/members/withdrawal").authenticated()
                        .requestMatchers("/api/members/details", "/api/members/change-password", "/api/members/withdrawal").authenticated()
                        .requestMatchers("/api/auth/admin/**", "/api/admin/**").hasRole("ADMIN") //관리자 관련
                        .requestMatchers("/api/strategies/{id}/update-form","/api/strategies/{id}/approval-request",
                                "/api/strategies/{id}/rejection-info", "/api/strategies/{id}/termination", "/api/strategies/{id}/daily-data",
                                "/api/strategies/{strategyId}/daily-data/{dailyDataId}", "/api/strategies/{strategyId}/daily-analyses/delete",
                                "/api/strategies/{strategyId}/upload"
                        ).hasAnyRole("ADMIN", "TRADER") //전략 관련
                        .requestMatchers(HttpMethod.POST, "/api/strategies").hasAnyRole("ADMIN", "TRADER") //전략 등록
                        .requestMatchers(HttpMethod.DELETE, "/api/strategies").hasAnyRole("ADMIN", "TRADER") //전략 삭제
                        .requestMatchers(HttpMethod.PUT, "/api/strategies/{id}").hasAnyRole("ADMIN", "TRADER") //전략 수정
                        .requestMatchers(HttpMethod.POST, "/api/live-account-data/{strategyId}").hasAnyRole("ADMIN", "TRADER") //실계좌 등록
                        .requestMatchers(HttpMethod.DELETE, "/api/live-account-data/{strategyId}").hasAnyRole("ADMIN", "TRADER") //실계좌 삭제
                        .requestMatchers("/swagger-ui/**", "/api/**").permitAll()
                        .requestMatchers("/**").permitAll()

                )
//                .requiresChannel(channel -> channel.anyRequest().requiresSecure()) // HTTPS 강제
                .formLogin(formLogin -> formLogin.disable()) // 폼 로그인 비활성화
                .httpBasic(httpBasic -> httpBasic.disable()) // HTTP Basic 비활성화
                .addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class)
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil), UsernamePasswordAuthenticationFilter.class)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(e -> e
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler)
                );

        return http.build();
    }

    /**
     * AuthenticationManager Bean 등록
     * @return AuthenticationManager 객체
     * @throws Exception Spring Security 설정 중 예외 발생 시
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    /**
     * 패스워드 암호화를 위한 BCryptPasswordEncoder Bean 등록
     * @return PasswordEncoder 객체
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}