package com.cigama.auth0.service.security;

import com.cigama.auth0.entity.User;
import com.cigama.auth0.mapper.UserMapper;
import com.cigama.auth0.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    // --- Variables ---

    private final UserRepository userRepository;
    private final UserMapper userMapper;

    // --- Core Methods ---

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));

        return userMapper.toCustomUserDetails(user, null);
    }
}
