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
@Table(name = "TKM_SERVICIO")
@SequenceGenerator( name="sequence_service", sequenceName="TKM_SERVICIO_SEQ", allocationSize = 1)
public class Servicio implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO, generator="sequence_service")
    @Column(name = "SERVICIOID", unique = true, nullable = false)
    private Long idService;
    @Column(name = "NOMBRE")
    private String name;
    @Column(name = "KEYCODE")
    private String keycode;
    @Column(name = "URLIMAGEN")
    private String urlimage;
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "CD_IDNODO", nullable = false)
    private Client client;

}
