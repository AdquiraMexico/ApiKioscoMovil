package mx.com.flap.apikioscomovil.entities;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Entity
@Table(name = "TKM_USUARIO")
@Getter
@Setter
@ToString
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "IDUSUARIO")
    private Long idUsuario;
    @Column(name = "USERNAME")
    private String username;
    @Column(name = "IDPASSWORD")
    private String password;
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "IDPROFILE")
    private Profile perfil;
    @Column(name = "TIPOUSUARIO")
    private String tipoUsuario;
    @Column(name = "CLIENTID")
    private Long clientId;
    @Column(name = "ATTEMPTS")
    private Long attempts;
    @Column(name = "BLOCKED")
    private Boolean blocked;
}
