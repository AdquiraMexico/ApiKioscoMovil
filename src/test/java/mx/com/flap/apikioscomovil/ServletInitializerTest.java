package mx.com.flap.apikioscomovil;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.boot.builder.SpringApplicationBuilder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.*;

class ServletInitializerTest {

    /**
     * This class is designed to test the `configure` method in the `ServletInitializer` class.
     * The `configure` method customizes the `SpringApplicationBuilder` to set the source for the application startup.
     */

    @Test
    void testConfigureMethodSetsCorrectApplicationSource() {
        // Arrange
        ServletInitializer servletInitializer = new ServletInitializer();
        SpringApplicationBuilder mockBuilder = mock(SpringApplicationBuilder.class);
        ArgumentCaptor<Class<?>> classCaptor = ArgumentCaptor.forClass(Class.class);

        when(mockBuilder.sources(classCaptor.capture())).thenReturn(mockBuilder);

        // Act
        SpringApplicationBuilder resultBuilder = servletInitializer.configure(mockBuilder);

        // Assert
        verify(mockBuilder, times(1)).sources(ApiKioscoMovilApplication.class);
        assertEquals(mockBuilder, resultBuilder);
        assertEquals(ApiKioscoMovilApplication.class, classCaptor.getValue());
    }
}