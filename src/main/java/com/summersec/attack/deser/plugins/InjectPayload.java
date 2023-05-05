package com.summersec.attack.deser.plugins;

import com.sun.xml.internal.ws.util.StringUtils;
import javassist.ClassPool;
import javassist.CtClass;


public interface InjectPayload<T> {
    CtClass genPayload(ClassPool paramClassPool,String payloadskey) throws Exception;

    public static class Utils
    {
        public static Class<? extends InjectPayload> getPayloadClass(String className) throws ClassNotFoundException {
            Class<? extends InjectPayload> clazz = null;
            try {
                clazz = (Class)Class.forName("com.summersec.attack.deser.echo." + StringUtils.capitalize(className));
            } catch (ClassNotFoundException e1) {
                clazz = (Class)Class.forName("com.summersec.attack.deser.plugins." + StringUtils.capitalize(className));
            } catch (Exception e) {
                e.printStackTrace();
            }
            return clazz;
        }
    }
}



