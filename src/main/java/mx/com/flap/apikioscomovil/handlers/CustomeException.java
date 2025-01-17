package mx.com.flap.apikioscomovil.handlers;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class CustomeException extends RuntimeException{

    private final String message;
    private final List<String> paramMap = new ArrayList<>();

    public CustomeException(String message, String... params) {
        super(message);
        this.message = message;
        if (params != null && params.length > 0)
            Collections.addAll(paramMap, params);
    }

    public CustomeException(String message, List<String> paramMap) {
        this.message = message;
        this.paramMap.addAll(paramMap);
    }

    public ParametizedErrorVM getError() {return new ParametizedErrorVM(message, paramMap);}
}
