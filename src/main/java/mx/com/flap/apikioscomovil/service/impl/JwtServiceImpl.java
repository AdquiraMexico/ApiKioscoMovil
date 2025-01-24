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
import mx.com.flap.apikioscomovil.repositories.UserRepostory;
import mx.com.flap.apikioscomovil.resources.AuthenticationResource;
import mx.com.flap.apikioscomovil.service.JwtService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.jackson2.SimpleGrantedAuthorityMixin;
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

    @Value("${encrypt.isDev}")
    private Boolean isDev;

    private final UserRepostory userRepository;

    public static final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS512);

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
                SecretKeySpec secretKey = new SecretKeySpec(SECRET.getBytes(),HMAC);
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
            log.error("Error interno : {}" , e.getMessage());
            throw new CustomeException("Error when try to create token", e.getMessage());
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            log.error("Error interno : {}" , e.getMessage());
            throw new CustomeException(e.getMessage());
        }
    }

    @Override
    public Boolean validate(String token) {
        try {
            Claims claims = getClaims(token);

            return true;
        } catch (JwtException | IllegalArgumentException ex) {
            log.error("{}",ex);
            return false;
        }
    }

    @Override
    public Claims getClaims(String token) {
        if (Boolean.TRUE.equals(isDev)) {

            Mac sha256HMAC = null;
            try {
                sha256HMAC = Mac.getInstance(HMAC);
                SecretKeySpec secretKey = new SecretKeySpec(SECRET.getBytes(),HMAC);
                sha256HMAC.init(secretKey);
                return Jwts.parser()
                        .setSigningKey(secretKey)
                        .parseClaimsJws(resolve(token)).getBody();
            } catch (NoSuchAlgorithmException | InvalidKeyException e ) {
                log.error("Error interno : {}" , e.getMessage());
                throw new CustomeException(e.getMessage());
            }

        } else {
            return Jwts.parser()
                    .setSigningKey(SECRET_KEY)
                    .parseClaimsJws(resolve(token)).getBody();
        }
    }

    @Override
    public String getUsername(String token) {
        return getClaims(token).getSubject();
    }

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
            log.error("Error interno : {}" , e.getMessage());
            throw new CustomeException("Error al obtener los roles", e.getMessage());
        }
    }

    @Override
    public String resolve(String token) {
        if (token != null && token.startsWith(TOKENPREFIX))
            return token.replace(TOKENPREFIX, "");
        else
            return null;
    }

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

    public Boolean failedAttemps(String username){
        User user = this.userRepository.findByUsername(username).orElseThrow(() -> new CustomeException("El usuario no éxiste"));

        if (user != null){
            if (user.getAttempts() == null) {
                user.setAttempts(1L);
                user = this.userRepository.save(user);
            }else {
                if (user.getAttempts() + 1 < 5){
                    user.setAttempts(user.getAttempts() + 1);
                    user = this.userRepository.save(user);
                }else {
                    if (user.getAttempts()+1 == 5){
                        user.setBlocked(true);
                        user.setAttempts(5L);
                        user = this.userRepository.save(user);
                    }
                }
            }
        }
        return user.getBlocked();
    }
}
