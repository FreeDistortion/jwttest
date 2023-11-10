package com.example.jwttest.exam;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.Base64;
import java.util.Map;

// okta에서 제공하는 token 만들기
public class JWTTest1 {
    public static void printToken(String token) {
        String[] splitdata = token.split("\\.");
        System.out.println("header: "+new String(Base64.getDecoder().decode(splitdata[0])));
        System.out.println("payload: "+new String(Base64.getDecoder().decode(splitdata[1])));
//        System.out.println("verify signature: "+new String(Base64.getDecoder().decode(splitdata[2])));
    }
    public static void main(String[] args) {
        // jjwt를 이용한 token 사용
        // Jwts: builder pattern이 적용된 object - token을 만들 떄 사용하는 builer
        String okta_jwt_token = Jwts.builder()
                .addClaims(Map.of("name","name1","id","id1"))
                // jwt에 서명 추가
                .signWith(SignatureAlgorithm.HS256,"secretKey")
                // 위의 정보를 이용해서 token 생성
                .compact();
        System.out.println(okta_jwt_token);
        printToken(okta_jwt_token);
        
        // parsing token
        Jws<Claims> jwstoken = Jwts.parser()
                .setSigningKey("secretKey")
                .parseClaimsJws(okta_jwt_token);

        System.out.println(jwstoken);

    }
}