package top.ingxx.security.service;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component
public class Myservice implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return User.builder().username("user").password("$2a$10$pBkZ18ezHvTc2cNBaN8k/e36JUauv/s5KIwqj/PRMS0hIHSIsvnIq").roles("USER").build();
    }
}
