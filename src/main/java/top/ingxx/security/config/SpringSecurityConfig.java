package top.ingxx.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import top.ingxx.security.filter.MyRequestFilter;
import top.ingxx.security.provider.MyProvider;
import top.ingxx.security.service.Myservice;

@EnableWebSecurity
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private Myservice myservice;

    @Autowired
    private MyProvider myProvider;

    //配置认证类
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(myProvider).authenticationProvider(daoAuthenticationProvider());
    }

    //配置基本参数
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/static/**","/templates/**").permitAll()
                .antMatchers("/test").hasAnyRole("USER")
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .and()
                .addFilterBefore(myRequestFilter(authenticationManager()), LogoutFilter.class)
        ;
    }

    //配置dao认证器 设置认证服务类和密码加密方式
    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(myservice);
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }


    //自定义拦截器
    private MyRequestFilter myRequestFilter(AuthenticationManager authenticationManager) {
        MyRequestFilter myRequestFilter = new MyRequestFilter();
        //为过滤器添加认证器
        myRequestFilter.setAuthenticationManager(authenticationManager);
        return myRequestFilter;
    }

}
