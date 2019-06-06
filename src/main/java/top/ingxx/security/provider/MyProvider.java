package top.ingxx.security.provider;

import lombok.extern.java.Log;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import top.ingxx.security.token.MyToken;

import java.util.ArrayList;
import java.util.List;

@Log
@Component
public class MyProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        log.info("经过了authenticate");
        List<SimpleGrantedAuthority> list=new ArrayList<>();
        list.add(new SimpleGrantedAuthority("ROLE_USER"));
        return new MyToken(list);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        log.info("经过了supports");
        return authentication.isAssignableFrom(MyToken.class);
    }
}
