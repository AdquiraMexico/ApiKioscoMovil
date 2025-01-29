package mx.com.flap.apikioscomovil.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import mx.com.flap.apikioscomovil.entities.User;
import mx.com.flap.apikioscomovil.handlers.CustomeException;
import mx.com.flap.apikioscomovil.repositories.UserRepository;
import mx.com.flap.apikioscomovil.resources.AuthenticationResource;
import mx.com.flap.apikioscomovil.security.SimpleGrantedAuthorityMixin;
import mx.com.flap.apikioscomovil.service.JwtService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;

import static mx.com.flap.apikioscomovil.constants.ConstantsJwt.HMAC;
import static mx.com.flap.apikioscomovil.constants.ConstantsJwt.SECRET;


@Component
@Slf4j
@RequiredArgsConstructor
public class JwtServiceImpl implements JwtService {

    private static final Long EXPIRATION = 3600 * 1000L;
    private static final String TOKENPREFIX = "Bearer ";
    private static final String INTERNALERROR = "Error interno : ";

    @Value("${encrypt.isDev}")
    private Boolean isDev;

    private final UserRepository userRepository;

    public static final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS512);

    /**
     * Creates an AuthenticationResource instance with a JWT token and user details, based on the provided authentication.
     *
     * @param auth the authentication object containing user credentials and authorities.
     * @return an instance of AuthenticationResource containing a JWT token and user details.
     * @throws CustomeException if an internal error occurs or if the user does not exist.
     */
    @Override
    public AuthenticationResource create(Authentication auth) {
        try {
            AuthenticationResource resource = new AuthenticationResource();
            String username = ((org.springframework.security.core.userdetails.User) auth.getPrincipal()).getUsername();

            log.info("USERNAME: {}", username);

            Collection<? extends GrantedAuthority> roles = auth.getAuthorities();

            Claims claims = getClaimsCustom(roles, username);
            if (Boolean.TRUE.equals(isDev)) {
                Mac sha256HMAC = Mac.getInstance(HMAC);
                SecretKeySpec secretKey = new SecretKeySpec(SECRET.getBytes(), HMAC);
                sha256HMAC.init(secretKey);

                resource.setToken(Jwts.builder()
                        .setClaims(claims)
                        .setSubject(username)
                        .setIssuedAt(new Date())
                        .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION))
                        .signWith(secretKey)
                        .compact());
            } else {
                resource.setToken(Jwts.builder()
                        .setClaims(claims)
                        .setSubject(username)
                        .setIssuedAt(new Date())
                        .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION))
                        .signWith(SECRET_KEY)
                        .compact());
            }

            User userEntity = this.userRepository.findByUsername(username).orElseThrow(() -> new CustomeException("El usuario no éxiste"));
            resource.setUserId(userEntity.getIdUsuario());
            resource.setUsername(userEntity.getUsername());
            resource.setEnabled(true);
            resource.setCode(200);
            resource.setMessage("Login exitoso");
            return resource;

        } catch (JsonProcessingException e) {
            log.error("{} {}", INTERNALERROR, e.getMessage());
            throw new CustomeException("Error when try to create token", e.getMessage());
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            log.error("{} {}", INTERNALERROR, e.getMessage());
            throw new CustomeException(e.getMessage());
        }
    }

    /**
     * Validates a JWT token by attempting to parse its claims.
     * Returns whether the token is valid or not.
     *
     * @param token the JWT token to be validated
     * @return {@code true} if the token is valid, otherwise {@code false}
     */
    @Override
    public Boolean validate(String token) {
        try {
            Claims claims = getClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException ex) {
            log.error("error: {}", ex.getMessage());
            return false;
        }
    }

    /**
     * Extracts and returns the claims from the provided JWT token.
     * The claims are parsed based on the signing key. In development mode,
     * it uses a specific HMAC signing algorithm while in other environments,
     * a different secret key is used for validation.
     *
     * @param token the JWT token from which claims need to be extracted
     * @return the claims extracted from the given token
     * @throws CustomeException if an error occurs during token parsing or signing key generation
     */
    @Override
    public Claims getClaims(String token) {
        if (Boolean.TRUE.equals(isDev)) {

            Mac sha256HMAC;
            try {
                sha256HMAC = Mac.getInstance(HMAC);
                SecretKeySpec secretKey = new SecretKeySpec(SECRET.getBytes(), HMAC);
                sha256HMAC.init(secretKey);
                return Jwts.parser()
                        .setSigningKey(secretKey)
                        .parseClaimsJws(resolve(token)).getBody();
            } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                log.error("Error interno : {}", e.getMessage());
                throw new CustomeException(e.getMessage());
            }

        } else {
            return Jwts.parser()
                    .setSigningKey(SECRET_KEY)
                    .parseClaimsJws(resolve(token)).getBody();
        }
    }

    /**
     * Extracts the username from the provided token by retrieving its subject field.
     *
     * @param token the token from which the username will be extracted
     * @return the username extracted from the token
     */
    @Override
    public String getUsername(String token) {
        return getClaims(token).getSubject();
    }

    /**
     * Retrieves roles from a provided token and converts them into a collection of GrantedAuthority objects.
     *
     * @param token the token containing the roles information
     * @return a collection of GrantedAuthority representing the roles associated with the token
     */
    @Override
    public Collection<GrantedAuthority> getRoles(String token) {
        try {
            Object roles = getClaims(token).get("authorities");
            log.info("Roles: " + roles.toString());
            return Arrays.asList(
                    new ObjectMapper()
                            .addMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthorityMixin.class)
                            .readValue(roles.toString().getBytes(), SimpleGrantedAuthority[].class));
        } catch (IOException e) {
            log.error("Error interno : {}", e.getMessage());
            throw new CustomeException("Error al obtener los roles", e.getMessage());
        }
    }

    /**
     * Resolves a given token by removing a predefined prefix if present.
     *
     * @param token the token to be processed; may include a specific prefix
     * @return the token without the predefined prefix if it exists, or null if the token is null or does not contain the prefix
     */
    @Override
    public String resolve(String token) {
        if (token != null && token.startsWith(TOKENPREFIX))
            return token.replace(TOKENPREFIX, "");
        else
            return null;
    }

    /**
     * Generates and populates a `Claims` object with authority, user, and additional information
     * retrieved from the database based on the provided user details.
     *
     * @param roles A collection of granted authorities associated with the user.
     * @param user The username of the user whose details are to be retrieved and included in the claims.
     * @return A `Claims` object containing user-specific information such as id, profile, and client ID.
     * @throws JsonProcessingException If an error occurs while serializing roles into JSON.
     */
    private Claims getClaimsCustom(Collection<? extends GrantedAuthority> roles, String user) throws JsonProcessingException {
        Claims claims = Jwts.claims();
        claims.put("authorities", new ObjectMapper().writeValueAsString(roles));

//        Add additional information
        User userEntity = this.userRepository.findByUsername(user).orElse(null);

        if (userEntity != null) {
            claims.put("id", userEntity.getIdUsuario());
            claims.put("perfil", userEntity.getPerfil().getNombre());
            claims.put("cliente", userEntity.getClientId());
            log.info("Profile: {}", userEntity.getPerfil().getNombre());
        }

        return claims;
    }

    /**
     * Increments the failed login attempts for a user identified by the provided username.
     * If the user's failed attempts reach 5, the account is marked as blocked.
     *
     * @param username the username of the user whose failed login attempts are to be incremented
     * @return a Boolean value indicating whether the user's account is blocked
     * @throws CustomeException if the user does not exist
     */
    public Boolean failedAttemps(String username) {
        User user = this.userRepository.findByUsername(username).orElseThrow(() -> new CustomeException("El usuario no éxiste"));

        if (user.getAttempts() == null) {
            user.setAttempts(1L);
            user = this.userRepository.save(user);
        } else {
            if (user.getAttempts() + 1 < 5) {
                user.setAttempts(user.getAttempts() + 1);
                user = this.userRepository.save(user);
            } else {
                if (user.getAttempts() + 1 == 5) {
                    user.setBlocked(true);
                    user.setAttempts(5L);
                    user = this.userRepository.save(user);
                }
            }
        }
        return user.getBlocked();
    }
}
