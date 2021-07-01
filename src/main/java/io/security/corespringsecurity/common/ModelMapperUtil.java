package io.security.corespringsecurity.common;

import io.security.corespringsecurity.domain.Account;
import org.modelmapper.ModelMapper;

import java.lang.reflect.Type;

public class ModelMapperUtil {
    public static <T> T copyMember(Object object, Class<T> clazz) {
        ModelMapper modelMapper = new ModelMapper();
        return modelMapper.map(object, clazz);
    }
}
