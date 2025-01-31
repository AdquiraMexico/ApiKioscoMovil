package mx.com.flap.apikioscomovil.handlers;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class CustomeException extends RuntimeException{

    private final String message;
    private final List<String> paramMap = new ArrayList<>();

    /**
     * Constructs a new {@code CustomeException} with the specified detail message
     * and optional parameters. The parameters are used to provide additional context
     * or information about the error.
     *
     * @param message the detail message associated with the exception
     * @param params optional parameters providing additional context or information
     */
    public CustomeException(String message, String... params) {
        super(message);
        this.message = message;
        if (params != null && params.length > 0)
            Collections.addAll(paramMap, params);
    }

    /**
     * Constructs a new {@code CustomeException} with the specified detail message
     * and a list of parameters. The parameters are used to provide additional context
     * or information about the error.
     *
     * @param message the detail message associated with the exception
     * @param paramMap a list of parameters providing additional context or information
     */
    public CustomeException(String message, List<String> paramMap) {
        this.message = message;
        this.paramMap.addAll(paramMap);
    }

    /**
     * Returns a {@code ParametizedErrorVM} instance containing the error message
     * and associated parameters. This provides detailed information about the
     * exception, including its context and any additional data provided during
     * its creation.
     *
     * @return a {@code ParametizedErrorVM} object encapsulating the error message
     *         and the list of associated parameters.
     */
    public ParametizedErrorVM getError() {return new ParametizedErrorVM(message, paramMap);}
}
