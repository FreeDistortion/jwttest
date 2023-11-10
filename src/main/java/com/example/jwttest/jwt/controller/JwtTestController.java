package com.example.jwttest.jwt.controller;

import com.example.jwttest.jwt.model.SampleDTO2;
import com.example.jwttest.jwt.security.SampleUserDetails;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JwtTestController {
    @GetMapping("/test")
    public String test() {
        return "Configuration Test";
    }

    @PostMapping("/filtertest")
    public String filtertest() {
        return "Test done.";
    }

    @GetMapping("/my/api/test")
    public String usertest() {
        return "Config Test(/my/api/test)";
    }

    @GetMapping("/my/api/mypage")
    public SampleDTO2 mypage(Authentication mydata) {
        // 내 정보 조회 - SecurityContextHolder 안의 SecurityContext에 있는 Authentication(UsernamePasswordAuthenticationToken)에 저장되어 있다.
        // 따라서 Spring이 자동으로 object를 controller에 넘겨준다  .
        SampleUserDetails sampleUserDetails = (SampleUserDetails) mydata.getPrincipal();
        return sampleUserDetails.getSampleDTO2();
    }

    @GetMapping("/admin/api/test")
    public String admintest() {
        return "Config Tests(/admin/api/test)";
    }

}
