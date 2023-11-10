package com.example.jwttest.jwt.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.jwttest.jwt.model.SampleDTO1;
import com.example.jwttest.jwt.model.SampleDTO2;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import ognl.Token;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // 로그인(인증 요청)을 요청받았을 때 실행
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        // username, password 추출
/*

        try {
            BufferedReader br = request.getReader();
            String str = null;
            while ((str=br.readLine())!=null){
                log.info(str);
            }

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
*/
        // json to dto
/*

        ObjectMapper om = new ObjectMapper();
        SampleDTO1 reqDTO= null;
        try {
            reqDTO=om.readValue(request.getInputStream(), SampleDTO1.class);
            log.info("변환된 dto: {}",reqDTO);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
*/


        log.info(":::::::::::::::::::::::::JWT권한필터-attemptAuthentication():::::::::::::::::::::::::");

        // 1. 인증하면서 전달된 username과 password를 이용해서 UsernamePasswordAuthenticationToken 만들기.
        ObjectMapper om = new ObjectMapper();

        try {
            SampleDTO1 reqDTO = om.readValue(request.getInputStream(), SampleDTO1.class);
            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                    reqDTO.getUsername(), reqDTO.getPassword()
            );

            log.info("{}", reqDTO);
            log.info("{}", token);

            // 2. AuthenticationManager.authenticate()를 호출하면서 Authentication Objec 전달.
            Authentication authenticate = authenticationManager.authenticate(token);

            // 3. 호출 후 전달되는 object를 출력
            log.info("인증객체: {}", authenticate);

            // 4. 검증 결과로 받은 token return.
            return authenticate;
        } catch (IOException e) {
            log.info("IOException");
            throw new RuntimeException(e);
        }
    }

    // 인증 성공시 실행
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        log.info(":::::::::::::::::::::::::JWT권한필터-successfulAuthentication():::::::::::::::::::::::::");
        // 인증이 성공된 상태이므로 token 발급 후 response에 세팅.
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(authResult.getPrincipal(), null, authResult.getAuthorities());

        byte[] secretKey = DatatypeConverter.parseBase64Binary("secretKey");
        Algorithm algorithm = Algorithm.HMAC256(secretKey);
        String sign = JWT.create()
                .withClaim("username", token.getName())
                .withSubject("topic")
                .withExpiresAt(new Date(System.currentTimeMillis()+(1000*60*10)))
                .sign(algorithm);
        response.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + sign);

    }
}