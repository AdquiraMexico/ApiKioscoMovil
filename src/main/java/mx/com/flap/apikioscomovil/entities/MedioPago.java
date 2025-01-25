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
@Table(name = "TKM_MEDIOPAGO")
@SequenceGenerator( name="sequence_mediopago", sequenceName="TKM_MEDIOPAGO_SEQ", allocationSize = 1)
public class MedioPago implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO, generator="sequence_mediopago")
    @Column(name = "MEDIOPAGOID", unique = true, nullable = false)
    private Long idMeanPayment;
    @Column(name = "DESCRIPCION", nullable = true)
    private String description;
    @Column(name = "NOMBRE", nullable = true)
    private String name;
    @Column(name = "CLAVE", nullable = true)
    private String clave;
   
}
