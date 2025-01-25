package mx.com.flap.apikioscomovil.controller;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import mx.com.flap.apikioscomovil.entities.Servicio;
import mx.com.flap.apikioscomovil.request.ServiceRequest;
import mx.com.flap.apikioscomovil.response.ServiceResponse;
import mx.com.flap.apikioscomovil.service.impl.ServicioServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/services")
@AllArgsConstructor
@Slf4j
public class ServiceController {

    @Autowired
    private ServicioServiceImpl servicioService;

   @PostMapping("/save")
    public ResponseEntity<?> saveService(@Validated @RequestBody ServiceRequest request){
       Servicio servicio = servicioService.saveService(request);

       if(servicio != null){
           return new ResponseEntity<>(HttpStatus.OK);
       }else{
           return new ResponseEntity<>(HttpStatus.NOT_FOUND);
       }
    }

    @PostMapping("/update")
    public ResponseEntity<Object> updateService(@Validated @RequestBody ServiceRequest request) {
       Servicio servicio = servicioService.update(request);

        if(servicio != null){
            return new ResponseEntity<>(HttpStatus.OK);
        }else{
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    @GetMapping("/list")
    public ResponseEntity<?> listServices(@RequestParam("idClient") Long idClient){
        List<ServiceResponse> responseList = servicioService.findAllByClient(idClient);

        return new ResponseEntity<>(responseList, HttpStatus.OK);
    }

    @GetMapping("/find-service")
    public ResponseEntity<ServiceResponse> findService(@RequestParam("idServicio") Long idService){
       Servicio servicio = servicioService.findById(idService);

       if (servicio != null) {
           return new ResponseEntity<>(new ServiceResponse(servicio), HttpStatus.OK);
       }else{
           return new ResponseEntity<>(HttpStatus.NOT_FOUND);
       }
    }
}
