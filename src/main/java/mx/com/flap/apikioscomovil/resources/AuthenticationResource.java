package mx.com.flap.apikioscomovil.resources;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class AuthenticationResource extends GenericResource{
    private Long userId;
    private String username;
    private Boolean enabled;
    private String token;
}
