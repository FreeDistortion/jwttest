package com.example.jwttest.jwt.security;

import com.example.jwttest.jwt.model.SampleDTO2;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

// extend User that implementation of UserDetails
// Spring security 인증 처리과정에서 요구되는 object.
// DB에서 조회한 object를 User type으로 변환하기 위해 customize.
// UserDetailService에서 return할 타입으로 AuthenticationProvider로 return.
public class SampleUserDetails extends User {
    private final SampleDTO2 customerResponseDTO;

    public SampleUserDetails(SampleDTO2 customerResponseDTO, Collection<? extends GrantedAuthority> authorities) {
        super(customerResponseDTO.getUsername(), customerResponseDTO.getPassword(), authorities);
        this.customerResponseDTO = customerResponseDTO;
    }

    public SampleDTO2 getSampleDTO2() {
        return customerResponseDTO;
    }
}
