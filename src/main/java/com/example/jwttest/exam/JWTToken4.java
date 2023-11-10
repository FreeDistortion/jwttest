package com.example.jwttest.exam;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.aspectj.EnableSpringConfigured;

import java.util.Date;
// token expiration time test
public class JWTToken4 {
    public static void main(String[] args) throws InterruptedException {
        Algorithm algorithm = Algorithm.HMAC256("secretKey");
        // make JWT
        String token = JWT.create()
                .withSubject("TOPIC")
                // token 발급 시작 유효 시간
                .withNotBefore(new Date(System.currentTimeMillis() + 1000))
                // token expiration time
                .withExpiresAt(new Date(System.currentTimeMillis() + 7000))
                .sign(algorithm);

        // time delay - pass expiration time
        Thread.sleep(5000);

        try {
            DecodedJWT verify = JWT.require(algorithm).build().verify(token);
            System.out.println(verify.getClaims());
        } catch (Exception e) {
            System.out.println("This token is not valid.");
            // 유효하지 않은 token이더라도 경우에 따라 어떤 사용자가 요청한 것인지 정보를 봐야 하는 경우도 있음.
            DecodedJWT decodedJWT = JWT.decode(token);
            System.out.println(decodedJWT.getClaims());
        }
    }
}
