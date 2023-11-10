package com.example.jwttest.jwt.config;

import com.example.jwttest.jwt.dao.SampleRepository;
import com.example.jwttest.jwt.filter.JwtAuthenticationFilter;
import com.example.jwttest.jwt.filter.MyTestFilter1;
import com.example.jwttest.jwt.filter.TokenCheckFilter;
import com.example.jwttest.jwt.security.MyAuthProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;
import org.springframework.web.filter.FormContentFilter;

@Slf4j
@EnableWebSecurity(debug = true)
@RequiredArgsConstructor
// spring security에 cross domain issue를 해결하기 위한 filter가 있어서 그걸 넣는 작업을 할 거임 ㅇㅇ
// 그게 뭐냐면
public class TokenSecurityConfig {

    private final CorsFilter corsFilter;
    private final UserDetailsService userDetailsService;


    private final SampleRepository sampleRepository;



    @Bean
    public AuthenticationManager authenticationManager(){
        AuthenticationManager manager = new ProviderManager(authenticationProvider());
        return manager;
    }

    @Bean
    public AuthenticationProvider authenticationProvider(){
        // Db 들어갈 때 쓰는 거, Spring Security에서 제공하는 DB 연동을 위한 provider
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        return provider;
        // 원하면 직접 생성해서 사용 가능
//        return new MyAuthProvider(userDetailsService,passwordEncoder());
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
//                .authorizeHttpRequests(authorizationManagerRequestMatcherRegistry -> authorizationManagerRequestMatcherRegistry
//                        .antMatchers("/test").permitAll()
//                        .anyRequest().permitAll())
                .sessionManagement(httpSecuritySessionManagementConfigurer -> httpSecuritySessionManagementConfigurer
                        // session을 사용하지 않겠다는 정의
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilter(corsFilter)
//                .addFilterBefore(new MyFilter2(), CorsFilter.class)
//                .addFilterBefore(new MyFilter3(), MyFilter2.class)
//                .addFilterBefore(new MyFilter1(), MyFilter3.class)
                .addFilterAfter(new MyTestFilter1(), UsernamePasswordAuthenticationFilter.class)
                .addFilter(new JwtAuthenticationFilter(authenticationManager()))
                .addFilter(new TokenCheckFilter(authenticationManager(),sampleRepository))
                .csrf(csrfConfigurer -> csrfConfigurer
                        .disable())
                .formLogin(httpSecurityFormLoginConfigurer -> httpSecurityFormLoginConfigurer
                        .disable())
                .httpBasic(httpSecurityHttpBasicConfigurer -> httpSecurityHttpBasicConfigurer
                        .disable())
                .authorizeRequests(expressionInterceptUrlRegistry -> {
                            try {
                                expressionInterceptUrlRegistry
                                        .antMatchers(HttpMethod.OPTIONS,"/my/api/**")
                                        .access("hasRole('USER') or hasRole('ADMIN')")
                                        .antMatchers("/admin/api/**")
                                        .access("hasRole('ADMIN')")
                                        .anyRequest().permitAll()
                                        .and()
                                        .cors();
                            } catch (Exception e) {
                                throw new RuntimeException(e);
                            }
                        }
                )

        ;

        // 얘는 매니저를 자동으로 만들어줬기 때문에 쓴 거임, 위에 있는 authenticationManager()가 customize한 부분
//        AuthenticationManagerBuilder authenticationManagerBuilder = httpSecurity.getSharedObject(AuthenticationManagerBuilder.class);
//        authenticationManagerBuilder.authenticationProvider(authenticationProvider());

        return httpSecurity.build();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web ->
                web.ignoring().requestMatchers(
                        PathRequest.toStaticResources().atCommonLocations()
                );
    }

}
