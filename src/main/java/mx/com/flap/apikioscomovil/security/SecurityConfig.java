package mx.com.flap.apikioscomovil.security;

import mx.com.flap.apikioscomovil.service.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@EnableMethodSecurity
@Configuration
public class SecurityConfig {

    private static final String[] WHITE_LIST = new String[] {"/api/user/register"};

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private JwtService jwtService;

    @Autowired
    protected void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(this.userDetailsService).passwordEncoder(passwordEncoder());
    }

    /**
     * Configures a security filter chain to handle requests matching a predefined whitelist.
     * The filter chain disables CORS, CSRF, headers, and HTTP basic authentication. It allows
     * public access to the URLs specified in the whitelist and enforces stateless session management.
     *
     * @param http the HttpSecurity configuration object used to build the filter chain
     * @return a configured SecurityFilterChain instance
     * @throws Exception if an error occurs during the filter chain configuration
     */
    @Bean
    @Order(0)
    public SecurityFilterChain whitelistFilterChain(HttpSecurity http) throws Exception {


        return http.cors(Customizer.withDefaults())
                .httpBasic(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .headers(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .securityMatcher(WHITE_LIST)
                .authorizeHttpRequests(auth -> auth.requestMatchers(WHITE_LIST).permitAll())
                .authenticationManager(authenticationManager(http))
                .build();
    }

    /**
     * Configures the main security filter chain to manage authentication and authorization rules.
     * This method sets up the following:
     * - Disables CORS, HTTP basic authentication, CSRF protection, and security headers.
     * - Requires all requests to be authenticated.
     * - Configures the session management to use stateless sessions.
     * - Adds JWT-based authentication and authorization filters.
     * - Configures a custom authentication manager.
     *
     * @param http the HttpSecurity configuration object used to build the security filter chain
     * @return a configured SecurityFilterChain instance
     * @throws Exception if an error occurs during the filter chain configuration
     */
    @Bean
    @Order(1)
    protected SecurityFilterChain configure(HttpSecurity http) throws Exception {

        return http.cors(Customizer.withDefaults())
                .httpBasic(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .headers(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .anyRequest()
                        .authenticated())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(new JwtAuthenticationFilter(authenticationManager(http), jwtService), UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(new JwtAuthorizationFilter(authenticationManager(http), jwtService), BasicAuthenticationFilter.class)
                .authenticationManager(authenticationManager(http))
                .build();

    }

    /**
     * Configures and provides a custom AuthenticationManager bean to manage authentication mechanisms
     * in the Spring Security context. This method sets up the AuthenticationManager by utilizing the
     * shared object from HttpSecurity and configuring it with a UserDetailsService and a password
     * encoder.
     *
     * @param http the HttpSecurity configuration object used to create and configure the AuthenticationManager
     * @return a fully initialized AuthenticationManager instance
     * @throws Exception if an error occurs during the AuthenticationManager configuration
     */
    @Bean("authenticationManager")
    protected AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder builder = http.getSharedObject(AuthenticationManagerBuilder.class);
        builder.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
        return builder.build();
    }

    /**
     * Creates and configures a CorsConfigurationSource bean to define CORS policies for the application.
     * The configuration allows requests from any origin, permits a wide range of HTTP methods and headers,
     * and disables credential sharing in CORS requests.
     *
     * @return an instance of CorsConfigurationSource with the defined CORS settings
     */
    @Bean("corsConfigurationSource")
    public CorsConfigurationSource corsConfigurationSource() {
        final CorsConfiguration configuration = new CorsConfiguration();
        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

        configuration.setAllowedOrigins(List.of("*"));
        configuration.setAllowedMethods(List.of("HEAD", "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(false);

        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    /**
     * Creates a bean of type BCryptPasswordEncoder for encrypting passwords.
     * This password encoder uses BCrypt hashing with a strength of 10 by default.
     * It is typically used in the context of Spring Security to securely store and validate passwords.
     *
     * @return an instance of BCryptPasswordEncoder
     */
    @Bean
    public static BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
