package com.furkan.userregistration.configuration;

import com.furkan.userregistration.repository.AccountRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import static org.springframework.http.HttpMethod.*;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final JwtTokenProvider jwtTokenProvider;
    private final AccountRepository accountRepository;

    @Bean
    public WebMvcConfigurer cors() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                        .allowedMethods("*")
                        .allowedHeaders("*")
                        .allowedOrigins("*");
            }
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .userDetailsService(userDetailsBean(accountRepository))
                .passwordEncoder(passwordEncoder());
    }

    private UserDetailsService userDetailsBean(AccountRepository repository) {
        return username -> repository.findByUsername(username)
                                     .map(account -> User
                                             .withUsername(account.getUsername())
                                             .password(account.getPassword())
                                             .authorities(account.getRoles().toArray(new String[0]))
                                             .accountExpired(false)
                                             .credentialsExpired(false)
                                             .disabled(account.isDisabled())
                                             .accountLocked(false)
                                             .build())
                                     .orElseThrow(() -> new UsernameNotFoundException("Username not found"));
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .httpBasic().disable()
                .authorizeRequests()

                // ====================================================================================================

                .antMatchers(POST, "/sign-up").permitAll()
                .antMatchers(POST, "/sign-in").permitAll()
                .antMatchers(GET, "/accounts").hasAnyAuthority("ROLE_ADMIN")
                .antMatchers(POST, "/account/save").hasAnyAuthority("ROLE_ADMIN")
                .antMatchers(DELETE, "/account/delete").hasAnyAuthority("ROLE_ADMIN")
                // ====================================================================================================

                .anyRequest().authenticated()
                .and()

                .addFilterAt(new JwtTokenAuthenticationFilter(jwtTokenProvider),
                             UsernamePasswordAuthenticationFilter.class)
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()

                .cors();
    }
}
