package mx.com.flap.apikioscomovil.response;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import mx.com.flap.apikioscomovil.entities.Servicio;

@Getter
@Setter
@ToString
public class ServiceResponse {

    private Long idService;
    private String name;
    private String keycode;
    private String urlImage;

    public ServiceResponse(){
        //Constructor vacio
    }

    public ServiceResponse(Servicio servicio){
        this.idService = servicio.getIdService();
        this.name = servicio.getName();
        this.keycode = servicio.getKeycode();
        this.urlImage = servicio.getUrlimage();;
    }
}
