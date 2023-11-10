package com.example.jwttest.jwt.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

@Slf4j
@RequiredArgsConstructor
public class MyAuthProvider implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String name = authentication.getName();
        String password = (String) authentication.getCredentials();
        SampleUserDetails customerUserDetails = (SampleUserDetails) userDetailsService.loadUserByUsername(name);
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = null;

        if (customerUserDetails != null) {
            if (passwordEncoder.matches(password, customerUserDetails.getPassword())) {
                usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                        customerUserDetails.getSampleDTO2(), null, customerUserDetails.getAuthorities());
            }

        }

        return usernamePasswordAuthenticationToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
