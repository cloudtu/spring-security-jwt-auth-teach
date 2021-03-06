package cloudtu.config;

import cloudtu.security.JwtAuthFilter;
import cloudtu.security.UnauthEntryPoint;
import cloudtu.security.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Autowired
    private JwtAuthFilter jwtAuthFilter;

    @Override
    public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        authenticationManagerBuilder.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // ?????????????????? sessionCreationPolicy(SessionCreationPolicy.STATELESS)?????????
        // ?????? http session ????????????????????? SecurityContextHolder ????????????????????????????????? Authentication ??????
        // http session??????????????????????????????????????? Authentication ???????????????????????????????????? http request ???????????????
        // ???????????????????????????????????? SecurityContextHolder.getContext().getAuthentication() ???????????????????????????
        // ??? Authentication instance ????????? null???

        http.cors().and()
            .csrf().disable()
            .exceptionHandling().authenticationEntryPoint(new UnauthEntryPoint()).and() // set unauthorized requests exception handler
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and() // set session management to stateless
            .authorizeRequests().antMatchers("/auth/**").permitAll()
            .anyRequest().authenticated();

        http.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
