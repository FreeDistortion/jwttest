package com.example.jwttest.jwt.service;

import com.example.jwttest.jwt.dao.SampleDAOImpl;
import com.example.jwttest.jwt.model.SampleDTO2;
import com.example.jwttest.jwt.model.SampleEntity;
import com.example.jwttest.jwt.security.SampleUserDetails;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class SampleSecurityDetailService implements UserDetailsService {

        private final SampleDAOImpl sampleDAO;
        @Override
        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                SampleEntity entity = sampleDAO.login(username);

                if(entity==null){
                        throw new UsernameNotFoundException("No sample.");
                }
                List<GrantedAuthority> roles = new ArrayList<>();

                roles.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
                ModelMapper mapper = new ModelMapper();
                SampleDTO2 responseDTO = mapper.map(entity,SampleDTO2.class);

                SampleUserDetails userDetails = new SampleUserDetails(responseDTO,roles);

                return userDetails;
        }
}
