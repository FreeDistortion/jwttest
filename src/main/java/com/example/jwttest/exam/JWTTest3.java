package com.example.jwttest.exam;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;

import javax.xml.bind.DatatypeConverter;

public class JWTTest3 {
    public static void main(String[] args) {
        // secret key를 특정 함수를 작용해서 값 변경(hashing)
        byte[] SEC_KEY= DatatypeConverter.parseBase64Binary("secretKey");

        String oauth_token = JWT.create()
                .withClaim("name","name1")
                .withClaim("id","id1")
                .sign(Algorithm.HMAC256(SEC_KEY));

        // parse by oauth library
        JWTVerifier jwtVerified = JWT.require(Algorithm.HMAC256(SEC_KEY)).build();
        DecodedJWT decodedJWT = jwtVerified.verify(oauth_token);
        System.out.println(decodedJWT.getClaims());

        // parse by okta library - secret key를 한 번 더 hashing해서 작업
        Jws<Claims> jwstoken = Jwts.parser()
                .setSigningKey("secretKey")
                .parseClaimsJws(oauth_token);

        System.out.println(jwstoken);

    }
}
