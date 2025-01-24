package mx.com.flap.apikioscomovil.entities;

import jakarta.persistence.*;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.io.Serializable;

@Getter
@Setter
@ToString
@Entity
@Table(name = "TKM_CLIENTE")
@SequenceGenerator( name="sequence_client", sequenceName="TKM_CLIENTE_SEQ")
public class Client implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO, generator="sequence_client")
    @Column(name = "SERVICIOID", unique = true, nullable = false)
    private Long clientid;
    @Column(name = "NOMBRE", nullable = true)
    private String name;
    @Column(name = "KEYCODE", nullable = true)
    private String keycode;
    @Column(name = "EMAIL", nullable = true)
    private String email;
    @Column(name = "IDMULTIPAGOS", nullable = true)
    private Long idMultipagos;
    private Long idPriceList;

}
