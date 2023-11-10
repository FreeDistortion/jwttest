package com.example.jwttest.exam;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;

import java.util.List;

public class JWTTest2 {
    public static void main(String[] args) {
        // JWT - create()
        // JWT spec에서 정의한 claim을 추가할 수 있다.
        /*
        * iss: token 발행 단체 또는 사이트
        * sub(Subject): token의 주제
        * lat: 발행 시간
        * jti: 일련번호
        * exp: 만료시간
        */
        String oauthToken= JWT.create()
                .withClaim("name","name1")
                .withClaim("id", "id1")
                .sign(Algorithm.HMAC256("secretKey"));
        System.out.println(oauthToken);
        JWTTest1.printToken(oauthToken);

        // parsing
        JWTVerifier jwtVerified = JWT.require(Algorithm.HMAC256("secretKey")).build();
        System.out.println(":::::::::::\n"+jwtVerified);

        DecodedJWT decodedJWT = jwtVerified.verify(oauthToken);

        System.out.println("!!!!!!!\n"+decodedJWT);
        System.out.println("header: "+decodedJWT.getHeader());
        System.out.println("payload: "+decodedJWT.getPayload());
        System.out.println("signature: "+decodedJWT.getSignature());
        System.out.println(decodedJWT.getClaims());

        // Jwts library로, oauth library로 만들어진 token을 파싱.

        Jws<Claims> secretKey = Jwts.parser()
                .setSigningKey("secretKey")
                .parseClaimsJws(oauthToken);
        System.out.println(secretKey);

    }
}
