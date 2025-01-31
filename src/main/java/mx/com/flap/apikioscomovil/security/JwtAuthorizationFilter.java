package mx.com.flap.apikioscomovil.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import mx.com.flap.apikioscomovil.service.JwtService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {
    private static final String[] WHITE_LIST = new String[] {"/api/user/register", "/h2-console/*"};

    private JwtService jwtService;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, JwtService jwtService) {
        super(authenticationManager);
        this.jwtService = jwtService;
    }

    /**
     * Filters incoming HTTP requests to enforce JWT authentication and authorization.
     * This method checks for the presence and validity of a JWT token in the "Authorization" header.
     * If the token is absent or invalid, it responds with a 401 Unauthorized error.
     * If the token is valid, it extracts the user's roles and sets the authentication context.
     *
     * @param request  the HttpServletRequest object containing the client's request
     * @param response the HttpServletResponse object to send the response
     * @param chain    the FilterChain object to pass request and response to the next filter in the chain
     * @throws IOException      in case of I/O errors during response writing
     * @throws ServletException in case of general servlet-related exceptions
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

        String header = request.getHeader("Authorization");
        log.info("HEADER: {}", header);
        log.info("url: {}", request.getRequestURI());
        if (header == null || !header.startsWith("Bearer ")) {

            Map<String, Object> body = new HashMap<>();
            body.put("message", "Intento de acceso IP: " + request.getRemoteAddr());
            body.put("Error", "Acceso denegado");

            response.setStatus(401);
            response.getWriter().write(new ObjectMapper().writeValueAsString(body));
            response.setContentType("application/json");
            return;
        }

        UsernamePasswordAuthenticationToken authToken = null;
        if (Boolean.TRUE.equals(jwtService.validate(header))) {
            log.info("roles: {}", this.jwtService.getRoles(header).toString());
            authToken = new UsernamePasswordAuthenticationToken(jwtService.getUsername(header), null, jwtService.getRoles(header));
        }
        SecurityContextHolder.getContext().setAuthentication(authToken);
        chain.doFilter(request, response);
    }

    protected Boolean requiresAuthentication(String header) {

        return header != null && !header.startsWith("Bearer ");
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return Arrays.stream(WHITE_LIST).anyMatch(url -> new AntPathRequestMatcher(url).matches(request));
    }
}
