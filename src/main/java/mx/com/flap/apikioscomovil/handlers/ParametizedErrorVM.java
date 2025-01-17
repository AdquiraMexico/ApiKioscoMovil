package mx.com.flap.apikioscomovil.handlers;

import lombok.Getter;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

@Getter
public class ParametizedErrorVM implements Serializable {
    private static final Long serialVersionUID = 1L;

    private final String message;
    private final List<String> paramMap;

    public ParametizedErrorVM(String message, List<String> paramMap) {
        this.message = message;
        this.paramMap = new ArrayList<>(paramMap);
    }


}
