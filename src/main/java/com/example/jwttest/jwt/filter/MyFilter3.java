package com.example.jwttest.jwt.filter;

import lombok.extern.slf4j.Slf4j;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

@Slf4j
public class MyFilter3 implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        log.info("!!!!!!!!!!!!!!!!! PRE - MyFilter3 !!!!!!!!!!!!!!!!!");
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        if (httpServletRequest.getMethod().equals("POST")&&httpServletRequest.getHeader("Authorization").equals("mytoken")) {
            chain.doFilter(request, response);
        } else {
            log.info("Token is not valid.");
        }
    }
}
