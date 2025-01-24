package mx.com.flap.apikioscomovil.requests;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class UsuarioRequest {
    private String username;
    private String password;
    private String kiosco;
}
