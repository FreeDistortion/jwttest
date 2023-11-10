package com.example.jwttest.jwt.config;

import com.example.jwttest.jwt.filter.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import javax.servlet.FilterChain;

@Slf4j
@Configuration
public class FilterConfig {

//        @Bean
//        public FilterRegistrationBean<MyTestFilter1> makefilter1 () {
//        FilterRegistrationBean<MyTestFilter1> filter1 = new FilterRegistrationBean<>(new MyTestFilter1());
//        // 특정 url 요청에 필터 1을 실행(now: /*)
//        filter1.addUrlPatterns("/*");
//        // 숫자가 작은 순서대로 실행
//        filter1.setOrder(0);
//        log.info("MY-TEST-FILTER-1 CONFIG !!!!!!!!!!!!!!!!!!!!!!!");
//        return filter1;
//    }
//
//        @Bean
//        public FilterRegistrationBean<MyFilter1> myfilter1 () {
//        FilterRegistrationBean<MyFilter1> myfilter = new FilterRegistrationBean<>(new MyFilter1());
//        myfilter.addUrlPatterns("/*");
//        myfilter.setOrder(0);
//        return myfilter;
//    }
//
//        @Bean
//        public FilterRegistrationBean<MyFilter2> myfilter2 () {
//        FilterRegistrationBean<MyFilter2> myfilter = new FilterRegistrationBean<>(new MyFilter2());
//        myfilter.addUrlPatterns("/*");
//        myfilter.setOrder(2);
//        return myfilter;
//    }
//
//        @Bean
//        public FilterRegistrationBean<MyFilter3> myfilter3 () {
//        FilterRegistrationBean<MyFilter3> myfilter = new FilterRegistrationBean<>(new MyFilter3());
//        myfilter.addUrlPatterns("/*");
//        myfilter.setOrder(1);
//        return myfilter;
//    }
//        @Bean
//        public FilterRegistrationBean<RequestTestFilter> myfilter4 () {
//        FilterRegistrationBean<RequestTestFilter> myfilter = new FilterRegistrationBean<>(new RequestTestFilter());
//        myfilter.addUrlPatterns("/*");
//        myfilter.setOrder(3);
//        return myfilter;
//    }
    @Bean
    public CorsFilter corsFilter() {
        // 허용 가능한 부분을 정의
        // 정의한 자원의 허용 범위 값을 config에 세팅.
        // config를 어떤 요청 url에 적용할 것인지 UrlBasedCorsConfigurationSource에 설정.
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();

        log.info("FOR REAL?!");

        // JSON server response를 Javascript에서 처리할 수 있도록 허용
        // cross domain에서 요청을 주고받을 때 cookie에 대한 처리, Authorization이 있는 요청 모두 허용.
        // client에서도 처리
        config.setAllowCredentials(true);

        // 모든 ip에 대해 응답 허용
//        config.addAllowedOrigin("*");
        // version up되면서 사용해야 하는 method가 바뀜
        config.addAllowedOriginPattern("*");

        // 모든 http method를 허용
        config.addAllowedMethod("*");

        // 모든 http header를 허용
        config.addAllowedHeader("*");

        // 외부에서 header값을 읽기 위한 설정
        config.addExposedHeader("Authorization");
        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }
}
