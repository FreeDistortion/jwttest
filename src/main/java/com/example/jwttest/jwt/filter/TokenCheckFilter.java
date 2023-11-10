package com.example.jwttest.jwt.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.jwttest.jwt.dao.SampleRepository;
import com.example.jwttest.jwt.model.SampleDTO2;
import com.example.jwttest.jwt.model.SampleEntity;
import com.example.jwttest.jwt.security.SampleUserDetails;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.stereotype.Repository;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Slf4j

public class TokenCheckFilter extends BasicAuthenticationFilter {


    private final SampleRepository sampleRepository;


    public TokenCheckFilter(AuthenticationManager authenticationManager, SampleRepository sampleRepository) {
        super(authenticationManager);
        this.sampleRepository = sampleRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        log.info("!!!!!!!!!!!!!!!!!!!!!!!!! 요청할 떄 실행되는 Filter !!!!!!!!!!!!!!!!!!!!!!!!!");
        // 1. token을 꺼내서 사용자 및 서명 확인 (secretKey parsing 필요)
        // -> 확인 완료 후 사용자가 맞으면, token에서 꺼낸 PK로 필요한 데이터 조회하는 작업 실행.
        String jwtHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        log.info("jwtHeader: {}", jwtHeader);

        //  조회 후 사용자 정보를 SecurityContext에 공유
        if (jwtHeader == null || !jwtHeader.startsWith("Bearer ")) {
            chain.doFilter(request, response);
            return;
        }

        // jwt token을 검증 후 정상 사용자인지 확인
        String token = jwtHeader
                .replace("Bearer ", "");
        String username = JWT.require(Algorithm.HMAC256(
                        DatatypeConverter.parseBase64Binary("secretKey")
                )).build()
                .verify(token).getClaim("username").asString();
        log.info("username from token: {}", username);

        // need to fix: 빠르게 테스트하기 위해 작업
        // 인증된 사용자면 사용자 정보를 가져오거나, 필요한 작업 실행.
        if (username != null) {

            SampleEntity sampleEntity = sampleRepository.findByUsername(username);
            List<GrantedAuthority> roles = new ArrayList<>();

            // user 권한 설정
            roles.add(new SimpleGrantedAuthority("ROLE_USER"));

            ModelMapper mapper = new ModelMapper();
            SampleDTO2 responseData = mapper.map(sampleEntity, SampleDTO2.class);
            SampleUserDetails sampleUserDetails = new SampleUserDetails(responseData, roles);

            // security 내부에서 사용할 인증토큰(UsernamePasswordAuthenticationToken)에 유저 정보를 저장.
            Authentication securityToken = new UsernamePasswordAuthenticationToken(sampleUserDetails, null, roles);

            // security 내부에서 사용되는 public 저장소
            SecurityContextHolder.getContext().setAuthentication(securityToken);

            log.info("securityToken: {}", securityToken);
        }
        chain.doFilter(request, response);
                                                          // 2. 해당 사용자가 아니면 접근할 수 없도록 처리
    }
}
