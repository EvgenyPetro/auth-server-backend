package ru.petrov.authserverback.configuration;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import ru.petrov.authserverback.filters.JwtAuthenticationFilter;
import ru.petrov.authserverback.filters.JwtAuthorizationFilter;
import ru.petrov.authserverback.security.AccessDeniedHandlerImpl;
import ru.petrov.authserverback.utils.JwtTokenProvider;

import static org.springframework.http.HttpMethod.POST;

@Configuration
@EnableGlobalMethodSecurity(
        prePostEnabled = true,
        securedEnabled = true,
        jsr250Enabled = true)
@RequiredArgsConstructor
public class SecurityConfiguration {

    @Autowired
    @Lazy
    private JwtAuthenticationFilter authenticationFilter;

    @Autowired
    @Lazy
    private JwtAuthorizationFilter authorizationFilter;

    private final JwtTokenProvider jwtTokenProvider;

    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setPasswordEncoder(passwordEncoder);
        authenticationProvider.setUserDetailsService(userDetailsService);
        return new ProviderManager(authenticationProvider);
    }

    @Bean
    public SecurityFilterChain appSecurityFilterChain(HttpSecurity http) throws Exception {

        // @formatter:off

            http
                .csrf(csrf -> csrf.disable())
                .authorizeRequests(auth -> {
                    auth.mvcMatchers(POST, "/api/v1/create-user").permitAll();
//                    auth.antMatchers("/auth/**", "/oauth2/**").permitAll();
                    auth.anyRequest().authenticated();
                })
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
                .addFilterBefore(authenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(authorizationFilter, JwtAuthenticationFilter.class)
                .cors(Customizer.withDefaults())
                .exceptionHandling()
                    .accessDeniedHandler(new AccessDeniedHandlerImpl())
                    .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
            .and()
                .httpBasic().disable()
                .formLogin().disable()
                .oauth2Login()
                    .authorizationEndpoint()
                    .baseUri("/oauth2/authorize")
            .and()
                  .redirectionEndpoint().baseUri("/oauth2/callback/*")
            .and()
                 .successHandler(new Oauth2SuccessHandler(jwtTokenProvider));

        return http.build();

        // @formatter: on
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}


